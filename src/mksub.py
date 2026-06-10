#!/usr/bin/env python3
"""
mksub.py - subscription fetch/parse helper for proxy-unifi (MVP).

Scope: Base64 or plain newline-separated share-link subscriptions only
(Remnawave / 3x-ui style fallback format). Balancer/JSON-pool profiles are NOT
handled here. The shell CLI ('proxy sub ...') drives this; node validation and
activation reuse the existing single-link import path.

Security: HTTPS-only, SSRF guard that pins the connection to a validated public
IP (defeating DNS-rebinding), capped response size / node count / redirects /
overall deadline, the x-hwid header never forwarded to a different origin, and
all provider-controlled text sanitized before display. The subscription URL and
HWID are read from files (--url-file/--hwid-file) so they never appear in argv.

Subcommands:
  fetch  [--url-file F | --url U] [--hwid-file F] [--ua UA] [--body-file F]
                                       -> JSON catalog (stdout)
  render --file nodes.json             -> numbered human list (sanitized)
  get    --file nodes.json --index N   -> 'id\\tsupported\\treason\\tscheme\\tlink'
  find   --file nodes.json --id ID     -> 'link' (supported only) or exit 1

Stdlib only (Python 3.7+).
"""

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit, urljoin, unquote

# ---- limits ---------------------------------------------------------------
MAX_BYTES = 2000000        # 2 MB response cap
MAX_NODES = 1000           # accepted-node cap
MAX_LINES = 100000         # input-line scan cap (independent of accepted nodes)
MAX_REDIRECTS = 3
TIMEOUT = 15               # per-operation socket timeout (seconds)
DEADLINE = 30              # overall wall-clock budget for a fetch (seconds)
LABEL_MAX = 36             # display code points
FIELD_MAX = 80             # generic display field cap

SUPPORTED = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")
SINGBOX_PLUGINS = ("obfs-local", "simple-obfs", "v2ray-plugin")

# Characters stripped from any provider-controlled text shown in the terminal:
# C0/DEL/C1 controls, zero-width, bidi embeddings/overrides/isolates, BOM.
_BAD = set(range(0x00, 0x20)) | {0x7f} | set(range(0x80, 0xa0)) | {
    0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
    0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff,
}


def die(msg):
    sys.stderr.write("mksub: error: %s\n" % msg)
    sys.exit(2)


def _utf8_stdout():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _b64(text):
    """Decode possibly-unpadded url/standard base64; None on failure."""
    s = "".join(text.split())
    s += "=" * (-len(s) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(s).decode("utf-8", "replace")
        except Exception:
            pass
    return None


def clean(s, maxlen=FIELD_MAX):
    """Make any provider-controlled string safe to print in a terminal.
    Drops control/bidi/zero-width chars, collapses whitespace, caps length.
    Preserves ordinary Unicode (Cyrillic, CJK, emoji)."""
    if not s:
        return ""
    out = []
    for ch in str(s):
        o = ord(ch)
        if o in _BAD:
            continue
        if ch in ("\t", "\n", "\r"):
            out.append(" ")
        else:
            out.append(ch)
    r = "".join(out).strip()
    if len(r) > maxlen:
        r = r[:maxlen].rstrip() + "…"
    return r


# ---- per-protocol shallow extraction --------------------------------------
def _host_port(u):
    try:
        return u.hostname, u.port
    except ValueError:
        return None, None


def _server_of(link, scheme):
    if scheme == "vmess":
        body = link[len("vmess://"):].split("#", 1)[0]
        dec = _b64(body)
        if not dec:
            return ""
        try:
            v = json.loads(dec)
        except Exception:
            return ""
        if not isinstance(v, dict):
            return ""
        h, p = str(v.get("add", "")), v.get("port", "")
        return "%s:%s" % (h, p) if h else ""
    try:
        u = urlsplit(link)
        h, p = _host_port(u)
    except ValueError:
        return ""
    if not h:
        return ""
    return "%s:%s" % (h, p) if p else h


def _label_of(link, scheme):
    if scheme == "vmess":
        body = link[len("vmess://"):].split("#", 1)[0]
        dec = _b64(body)
        if dec:
            try:
                v = json.loads(dec)
                if isinstance(v, dict):
                    return str(v.get("ps", ""))
            except Exception:
                return ""
        return ""
    try:
        frag = urlsplit(link).fragment
    except ValueError:
        return ""
    return unquote(frag) if frag else ""


def _ss_engine(link):
    """(engine, reason) for an ss:// link mirroring the shell's engine routing."""
    try:
        q = urlsplit(link).query
    except ValueError:
        return "", "unparseable link"
    plugin = ""
    for kv in q.split("&"):
        if kv.startswith("plugin="):
            plugin = unquote(kv[len("plugin="):]).split(";", 1)[0]
            break
    if not plugin:
        return "xray", ""
    if plugin in SINGBOX_PLUGINS:
        return "singbox", ""
    return "", "unsupported SIP003 plugin"


def node_from_link(link):
    """Return a node dict for a recognized proxy URI, or None to skip the line.

    'recognized' means the scheme is one we handle and we could read a server;
    it is NOT a guarantee the installed core accepts every option (that is only
    proven at selection time, where cmd_import runs the real core's -test)."""
    link = link.strip()
    if "://" not in link:
        return None
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SUPPORTED:
        return None
    node = {"scheme": scheme, "link": link, "label": "", "server": "",
            "recognized": True, "engine": "", "reason": ""}
    try:
        node["label"] = _label_of(link, scheme)
        node["server"] = _server_of(link, scheme)
        if scheme in ("hysteria2", "hy2", "tuic"):
            node["engine"] = "singbox"
        elif scheme == "ss":
            eng, reason = _ss_engine(link)
            node["engine"] = eng
            if not eng:
                node["recognized"] = False
                node["reason"] = reason
        else:  # vless / vmess / trojan
            node["engine"] = "xray"
        if node["recognized"] and not node["server"]:
            node["recognized"] = False
            node["reason"] = "could not parse server host/port"
    except Exception:
        node["recognized"] = False
        node["reason"] = "unparseable node"
    # stable id: full sha256 of the canonical link (without display fragment)
    canonical = link.split("#", 1)[0]
    node["id"] = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
    return node


def process_body(raw, headers=None):
    text = raw.decode("utf-8", "replace").strip()
    head = text[:200].lstrip().lower()
    if head[:1] == "<" or "<html" in head or "<!doctype" in head:
        die("the URL returned an HTML page, not a subscription")
    if head[:1] in ("{", "["):
        die("the URL returned a JSON profile; only base64/plain link-list "
            "subscriptions are supported")
    if "://" not in text:
        dec = _b64(text)
        if not dec or "://" not in dec:
            die("could not decode subscription (not a base64 / plain link list)")
        text = dec
        if dec.lstrip()[:1] in ("{", "["):
            die("the URL returned a JSON profile; only base64/plain link-list "
                "subscriptions are supported")
    nodes = []
    seen_ids = set()
    for i, line in enumerate(text.splitlines()):
        if i >= MAX_LINES or len(nodes) >= MAX_NODES:
            break
        nd = node_from_link(line)
        if not nd:
            continue
        if nd["id"] in seen_ids:        # drop exact duplicates
            continue
        seen_ids.add(nd["id"])
        nodes.append(nd)
    for n, nd in enumerate(nodes, 1):
        nd["n"] = n
    supported = sum(1 for x in nodes if x["recognized"])
    if not nodes:
        die("subscription contained no proxy links")
    if supported == 0:
        die("subscription has no supported nodes (all unrecognized)")
    meta = {"count": len(nodes), "supported": supported}
    if headers:
        iv = headers.get("profile-update-interval")
        if iv and str(iv).strip().isdigit():
            meta["interval_hours"] = int(str(iv).strip())
        ui = headers.get("subscription-userinfo")
        if ui:
            meta["userinfo"] = clean(str(ui), 200)
    return {"meta": meta, "nodes": nodes}


# ---- network (SSRF-safe, DNS-rebinding-safe) ------------------------------
def _norm_origin(u):
    """(scheme, host, port) with default ports normalized so a redirect to an
    explicit :443 from an implicit one is still treated as same-origin."""
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    port = u.port if u.port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, port)


def _public_ips(host):
    # PROXY_UNIFI_SUB_ALLOW_PRIVATE=1 disables the SSRF guard (tests only).
    allow_private = os.environ.get("PROXY_UNIFI_SUB_ALLOW_PRIVATE") == "1"
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception as e:
        die("could not resolve host: %s" % e)
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not allow_private and (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            die("refusing to fetch: %s resolves to a non-public address" % host)
        ips.append(info[4][0])
    if not ips:
        die("host did not resolve to any address")
    return ips


def _https_get(url, send_hwid, hwid, ua, deadline):
    """One HTTPS GET, connecting to a pinned validated IP (no second DNS lookup).
    Returns (status, headers, body_bytes_or_None, redirect_location)."""
    if time.monotonic() > deadline:
        die("subscription request exceeded the time budget")
    u = urlsplit(url)
    if (u.scheme or "").lower() != "https":
        die("only https:// subscription URLs are allowed")
    host = u.hostname
    if not host:
        die("subscription URL has no host")
    port = u.port or 443
    ip = _public_ips(host)[0]          # pin the connection to a validated IP
    ctx = ssl.create_default_context()
    tls = None
    try:
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
    except OSError as e:
        die("could not connect: %s" % e)
    try:
        # verify the cert against the real hostname (SNI), not the pinned IP
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLError as e:
        raw.close()
        die("TLS error: %s" % e)
    except OSError as e:
        raw.close()
        die("TLS connection failed: %s" % e)
    try:
        # drive http.client directly over the established TLS socket
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
        conn.sock = tls
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        hdrs = {"Host": host, "User-Agent": ua, "Accept": "*/*", "Connection": "close"}
        if send_hwid and hwid:
            hdrs["x-hwid"] = hwid
        try:
            conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
        except (http.client.HTTPException, OSError) as e:
            die("HTTP request failed: %s" % e)
        status = resp.status
        rheaders = {k.lower(): v for k, v in resp.getheaders()}
        if status in (301, 302, 303, 307, 308):
            return status, rheaders, None, rheaders.get("location")
        if status != 200:
            die("HTTP error %s from subscription server" % status)
        try:
            body = b""
            while len(body) <= MAX_BYTES:
                if time.monotonic() > deadline:
                    die("subscription download exceeded the time budget")
                chunk = resp.read(65536)
                if not chunk:
                    break
                body += chunk
        except (http.client.HTTPException, OSError) as e:
            die("error reading subscription body: %s" % e)
        if len(body) > MAX_BYTES:
            die("subscription too large (> %d bytes)" % MAX_BYTES)
        return status, rheaders, body, None
    finally:
        try:
            tls.close()
        except Exception:
            pass


def fetch_url(url, hwid, ua):
    deadline = time.monotonic() + DEADLINE
    try:
        origin = _norm_origin(urlsplit(url))
    except ValueError:
        die("malformed subscription URL")
    cur = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            same_origin = _norm_origin(urlsplit(cur)) == origin
        except ValueError:
            die("malformed redirect URL")
        status, headers, body, loc = _https_get(
            cur, same_origin, hwid, ua, deadline)
        if body is not None:
            return body, headers
        if not loc:
            die("redirect without a Location header")
        cur = urljoin(cur, loc)
    die("too many redirects")


# ---- subcommands ----------------------------------------------------------
def _read_secret(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception as e:
        die("could not read %s: %s" % (path, e))


def cmd_fetch(args):
    if args.body_file:                         # test hook: skip the network
        with open(args.body_file, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            die("body too large")
        headers = None
    else:
        url = _read_secret(args.url_file) if args.url_file else args.url
        if not url:
            die("fetch needs --url-file/--url (or --body-file)")
        hwid = _read_secret(args.hwid_file) if args.hwid_file else args.hwid
        raw, headers = fetch_url(url, hwid, args.ua)
    json.dump(process_body(raw, headers), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cat = json.load(fh)
    except Exception as e:
        die("could not read catalog: %s" % e)
    if not isinstance(cat, dict) or not isinstance(cat.get("nodes"), list):
        die("catalog is malformed")
    return cat


def cmd_render(args):
    cat = _load(args.file)
    nodes = cat.get("nodes", [])
    if not nodes:
        print("(no nodes in subscription)")
        return
    for nd in nodes:
        mark = " " if nd.get("recognized") else "x"
        label = clean(nd.get("label", ""), LABEL_MAX) or "(no label)"
        server = clean(nd.get("server", "?"), 40)
        scheme = clean(nd.get("scheme", "?"), 12)
        idshort = clean(nd.get("id", ""), 8)[:8]
        line = "%3d. [%s] %-9s %-24s %s  %s" % (
            nd.get("n", 0), mark, scheme, server, idshort, label)
        if not nd.get("recognized") and nd.get("reason"):
            line += "  (%s)" % clean(nd["reason"], 40)
        print(line)


def cmd_get(args):
    cat = _load(args.file)
    match = [x for x in cat.get("nodes", []) if x.get("n") == args.index]
    if not match:
        die("no node #%d in subscription" % args.index)
    nd = match[0]
    sys.stdout.write("%s\t%s\t%s\t%s\t%s\n" % (
        nd.get("id", ""), "1" if nd.get("recognized") else "0",
        clean(nd.get("reason", ""), 60), nd.get("scheme", ""), nd.get("link", "")))


def cmd_find(args):
    for nd in _load(args.file).get("nodes", []):
        if nd.get("id") == args.id and nd.get("recognized"):
            sys.stdout.write(nd.get("link", "") + "\n")
            return
    sys.exit(1)


def main():
    _utf8_stdout()
    ap = argparse.ArgumentParser(description="proxy-unifi subscription helper")
    sub = ap.add_subparsers(dest="cmd")

    f = sub.add_parser("fetch")
    f.add_argument("--url", default="")
    f.add_argument("--url-file", default="")
    f.add_argument("--hwid", default="")
    f.add_argument("--hwid-file", default="")
    f.add_argument("--ua", default="proxy-unifi (UniFi OS)")
    f.add_argument("--body-file", default="")
    f.set_defaults(fn=cmd_fetch)

    r = sub.add_parser("render")
    r.add_argument("--file", required=True)
    r.set_defaults(fn=cmd_render)

    g = sub.add_parser("get")
    g.add_argument("--file", required=True)
    g.add_argument("--index", type=int, required=True)
    g.set_defaults(fn=cmd_get)

    n = sub.add_parser("find")
    n.add_argument("--file", required=True)
    n.add_argument("--id", required=True)
    n.set_defaults(fn=cmd_find)

    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        sys.exit(2)
    args.fn(args)


if __name__ == "__main__":
    main()
