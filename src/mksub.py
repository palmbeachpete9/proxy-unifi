#!/usr/bin/env python3
"""
mksub.py - subscription fetch/parse helper for proxy-unifi (MVP).

Scope: Base64 or plain newline-separated share-link subscriptions only
(Remnawave / 3x-ui style fallback format). Balancer/JSON-pool profiles are NOT
handled here. The shell CLI ('proxy sub ...') drives this; node validation and
activation reuse the existing single-link import path.

Security: HTTPS-only, SSRF guard (reject private/loopback/link-local/reserved
resolved addresses), capped response size / node count / redirects, and the HWID
header is never forwarded to a different origin on redirect.

Subcommands:
  fetch  --url URL --hwid HWID [--ua UA] [--body-file F]  -> JSON catalog (stdout)
  render --file nodes.json                                -> numbered human list
  get    --file nodes.json --index N                      -> 'id\\tsupported\\treason\\tscheme\\tlink'
  find   --file nodes.json --id ID                        -> 'link' (supported only) or exit 1

Stdlib only (Python 3.7+).
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from urllib.parse import urlsplit, urljoin, unquote
import urllib.request
import urllib.error

# ---- limits ---------------------------------------------------------------
MAX_BYTES = 2000000        # 2 MB response cap
MAX_NODES = 2000           # node-count cap
MAX_REDIRECTS = 3
TIMEOUT = 20               # seconds
LABEL_MAX = 36             # display code points

SUPPORTED = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")
SINGBOX_PLUGINS = ("obfs-local", "simple-obfs", "v2ray-plugin")

# control/format characters to strip from provider-supplied labels
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CTRL = re.compile(
    "[\x00-\x1f\x7f-\x9f"          # C0 / DEL / C1
    "​-‏"                # zero-width + LRM/RLM
    "‪-‮"                # bidi embeddings/overrides
    "⁦-⁩"                # bidi isolates
    "﻿]"                      # BOM / ZWNBSP
)


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


def sanitize_label(s):
    if not s:
        return ""
    s = _ANSI.sub("", s)
    s = _OSC.sub("", s)
    s = _CTRL.sub("", s)
    s = s.replace("\t", " ").strip()
    # truncate by code points (never mid-byte); add ellipsis if longer
    if len(s) > LABEL_MAX:
        s = s[:LABEL_MAX].rstrip() + "…"
    return s


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
        h, p = str(v.get("add", "")), v.get("port", "")
        return "%s:%s" % (h, p) if h else ""
    u = urlsplit(link)
    h, p = _host_port(u)
    if not h:
        return ""
    return "%s:%s" % (h, p) if p else h


def _label_of(link, scheme):
    if scheme == "vmess":
        body = link[len("vmess://"):].split("#", 1)[0]
        dec = _b64(body)
        if dec:
            try:
                return sanitize_label(str(json.loads(dec).get("ps", "")))
            except Exception:
                return ""
        return ""
    frag = urlsplit(link).fragment
    return sanitize_label(unquote(frag)) if frag else ""


def _ss_engine(link):
    """(engine, reason) for an ss:// link mirroring the shell's engine routing."""
    q = urlsplit(link).query
    plugin = ""
    for kv in q.split("&"):
        if kv.startswith("plugin="):
            plugin = unquote(kv[len("plugin="):]).split(";", 1)[0]
            break
    if not plugin:
        return "xray", ""
    if plugin in SINGBOX_PLUGINS:
        return "singbox", ""
    return "", "unsupported SIP003 plugin '%s'" % plugin


def node_from_link(link):
    """Return a node dict for a recognized proxy URI, or None to skip the line."""
    link = link.strip()
    low = link.lower()
    if "://" not in low:
        return None
    scheme = low.split("://", 1)[0]
    if scheme not in SUPPORTED:
        return None
    node = {"scheme": scheme, "link": link, "label": "", "server": "",
            "supported": True, "engine": "", "reason": ""}
    try:
        node["label"] = _label_of(link, scheme)
        node["server"] = _server_of(link, scheme)
        if scheme in ("hysteria2", "hy2", "tuic"):
            node["engine"] = "singbox"
        elif scheme == "ss":
            eng, reason = _ss_engine(link)
            node["engine"] = eng
            if not eng:
                node["supported"] = False
                node["reason"] = reason
        else:  # vless / vmess / trojan
            node["engine"] = "xray"
        if node["supported"] and not node["server"]:
            node["supported"] = False
            node["reason"] = "could not parse server host/port"
    except Exception:
        node["supported"] = False
        node["reason"] = "unparseable node"
    # stable id: hash of the link without its display fragment/label
    canonical = link.split("#", 1)[0]
    node["id"] = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()[:8]
    return node


def process_body(raw, headers=None):
    text = raw.decode("utf-8", "replace").strip()
    head = text[:200].lower()
    if text[:1] == "<" or "<html" in head or "<!doctype" in head:
        die("the URL returned an HTML page, not a subscription")
    if "://" not in text:
        dec = _b64(text)
        if not dec or "://" not in dec:
            die("could not decode subscription (not a base64 / plain link list)")
        text = dec
    nodes = []
    for i, line in enumerate(text.splitlines()):
        if i >= MAX_NODES:
            break
        nd = node_from_link(line)
        if nd:
            nodes.append(nd)
    for n, nd in enumerate(nodes, 1):
        nd["n"] = n
    meta = {"count": len(nodes),
            "supported": sum(1 for x in nodes if x["supported"])}
    if headers:
        iv = headers.get("profile-update-interval")
        if iv and str(iv).strip().isdigit():
            meta["interval_hours"] = int(str(iv).strip())
        ui = headers.get("subscription-userinfo")
        if ui:
            meta["userinfo"] = sanitize_label(str(ui))[:200]
    return {"meta": meta, "nodes": nodes}


# ---- network --------------------------------------------------------------
def _origin(url):
    u = urlsplit(url)
    return (u.scheme.lower(), (u.hostname or "").lower(), u.port)


def _check_public(host):
    if os.environ.get("PROXY_UNIFI_SUB_ALLOW_PRIVATE") == "1":
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        die("could not resolve host: %s" % e)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            die("refusing to fetch: %s resolves to a non-public address" % host)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch_url(url, hwid, ua):
    origin = _origin(url)
    cur = url
    opener = urllib.request.build_opener(_NoRedirect)
    ctx = ssl.create_default_context()
    for _ in range(MAX_REDIRECTS + 1):
        u = urlsplit(cur)
        if u.scheme.lower() != "https":
            die("only https:// subscription URLs are allowed")
        if not u.hostname:
            die("subscription URL has no host")
        _check_public(u.hostname)
        headers = {"User-Agent": ua, "Accept": "*/*"}
        if hwid and _origin(cur) == origin:   # never leak HWID cross-origin
            headers["x-hwid"] = hwid
        req = urllib.request.Request(cur, headers=headers)
        try:
            resp = opener.open(req, timeout=TIMEOUT, context=ctx)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get("Location")
                if not loc:
                    die("redirect without a Location header")
                cur = urljoin(cur, loc)
                continue
            die("HTTP error %s from subscription server" % e.code)
        except urllib.error.URLError as e:
            die("network error: %s" % getattr(e, "reason", e))
        except ssl.SSLError:
            die("TLS error talking to the subscription server")
        except socket.timeout:
            die("subscription request timed out")
        data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            die("subscription too large (> %d bytes)" % MAX_BYTES)
        return data, resp.headers
    die("too many redirects")


# ---- subcommands ----------------------------------------------------------
def cmd_fetch(args):
    if args.body_file:                         # test hook: skip the network
        with open(args.body_file, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            die("body too large")
        headers = None
    else:
        raw, headers = fetch_url(args.url, args.hwid, args.ua)
    json.dump(process_body(raw, headers), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        die("could not read catalog: %s" % e)


def cmd_render(args):
    cat = _load(args.file)
    nodes = cat.get("nodes", [])
    if not nodes:
        print("(no nodes in subscription)")
        return
    for nd in nodes:
        mark = " " if nd.get("supported") else "x"
        label = nd.get("label") or "(no label)"
        line = "%3d. [%s] %-7s %-22s %s  %s" % (
            nd.get("n", 0), mark, nd.get("scheme", "?"),
            nd.get("server", "?"), nd.get("id", ""), label)
        if not nd.get("supported") and nd.get("reason"):
            line += "  (%s)" % nd["reason"]
        print(line)


def cmd_get(args):
    cat = _load(args.file)
    nodes = cat.get("nodes", [])
    match = [x for x in nodes if x.get("n") == args.index]
    if not match:
        die("no node #%d in subscription" % args.index)
    nd = match[0]
    sys.stdout.write("%s\t%s\t%s\t%s\t%s\n" % (
        nd.get("id", ""), "1" if nd.get("supported") else "0",
        nd.get("reason", ""), nd.get("scheme", ""), nd.get("link", "")))


def cmd_find(args):
    cat = _load(args.file)
    for nd in cat.get("nodes", []):
        if nd.get("id") == args.id and nd.get("supported"):
            sys.stdout.write(nd.get("link", "") + "\n")
            return
    sys.exit(1)


def main():
    _utf8_stdout()
    ap = argparse.ArgumentParser(description="proxy-unifi subscription helper")
    sub = ap.add_subparsers(dest="cmd")

    f = sub.add_parser("fetch")
    f.add_argument("--url", default="")
    f.add_argument("--hwid", default="")
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
    if args.cmd == "fetch" and not args.body_file and not args.url:
        die("fetch needs --url (or --body-file)")
    args.fn(args)


if __name__ == "__main__":
    main()
