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
import json
import os
import sys
from urllib.parse import urlsplit, unquote
# Network-only modules (ssl, http.client, socket, ipaddress, time, urljoin) are
# imported lazily inside fetch_url()/_https_get()/_public_ips(); the hot local
# subcommands (render/get/find, used on every menu render) never touch the
# network and so avoid that import cost.

# ---- limits ---------------------------------------------------------------
SCHEMA_VERSION = 2         # catalog format version (bump on incompatible change)
MAX_BYTES = 2000000        # 2 MB response cap
MAX_NODES = 1000           # accepted-node cap
MAX_LINES = 100000         # input-line scan cap (independent of accepted nodes)
MAX_LINK = 8000            # per-link byte/char cap (avoids ARG_MAX at activation)
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


def _is_emoji(o):
    """True for emoji / pictographic symbol code points we discard from labels."""
    return (0x1F000 <= o <= 0x1FAFF or       # emoji & pictographs (incl. flags)
            0x2600 <= o <= 0x27BF or          # misc symbols + dingbats
            0x2190 <= o <= 0x21FF or          # arrows
            0x2B00 <= o <= 0x2BFF or          # misc symbols & arrows
            0xFE00 <= o <= 0xFE0F or          # variation selectors
            o in (0x20E3, 0x2122, 0x2139, 0x303D, 0x3030))


def clean(s, maxlen=FIELD_MAX):
    """Make any provider-controlled string safe to print in a terminal, reducing
    it to plain text. Discards: control/bidi/zero-width chars; the whole Latin-1
    supplement (0x80-0xFF) -- on minimal/locale-broken gateways a flag emoji
    routinely arrives UTF-8-as-Latin-1-mangled into this range ('ð©ðª') and is
    not always recoverable, so we drop it rather than show garbage; and emoji /
    pictographs. Keeps real text (ASCII, Cyrillic, Greek, CJK, Latin-Extended,
    ...), collapses whitespace, caps length."""
    if not s:
        return ""
    out = []
    for ch in str(s):
        o = ord(ch)
        if o in _BAD or 0x80 <= o <= 0xFF or _is_emoji(o):
            continue
        out.append(" " if ch in ("\t", "\n", "\r") else ch)
    # collapse runs of whitespace left where emoji/mojibake were removed, and trim
    r = " ".join("".join(out).split())
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
    if scheme == "vmess" and "@" not in link[len("vmess://"):].split("#", 1)[0]:
        # legacy base64(JSON) form
        dec = _b64(link[len("vmess://"):].split("#", 1)[0])
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
    # URI form (vless/vmess-AEAD/trojan/ss/hysteria2/tuic)
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
    # reject control bytes / NUL so the stored link can't differ from what the
    # shell later activates (shell command-substitution silently drops NUL).
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in link):
        return None
    if len(link) > MAX_LINK:
        return None
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SUPPORTED:
        return None
    # normalize the scheme casing so the stored/activated link matches what the
    # (case-sensitive) shell import accepts.
    link = scheme + link[len(scheme):]
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
        # providers return a 0.0.0.0 placeholder ("App not supported" /
        # "Limit of devices reached") to unauthorized clients -- flag it clearly
        # instead of offering a dead node.
        if node["recognized"] and node["server"].split(":", 1)[0] in ("0.0.0.0", "127.0.0.1"):
            node["recognized"] = False
            node["reason"] = "provider placeholder (%s)" % (clean(node["label"], 40) or "not authorized")
    except Exception:
        node["recognized"] = False
        node["reason"] = "unparseable node"
    # stable id: full sha256 of the canonical link (without display fragment)
    canonical = link.split("#", 1)[0]
    node["id"] = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
    return node


def _meta_from_headers(headers):
    meta = {}
    if headers:
        iv = str(headers.get("profile-update-interval", "")).strip()
        if iv and len(iv) <= 6 and iv.isdigit():
            hours = int(iv)
            if 1 <= hours <= 8760:
                meta["interval_hours"] = hours
        ui = headers.get("subscription-userinfo")
        if ui:
            meta["userinfo"] = clean(str(ui), 200)
    return meta


def _process_json(text, headers):
    """A JSON subscription: one Xray balancer/pool profile (object) or several
    (array), as Remnawave serves to recognized HWID clients. Each profile becomes
    a selectable 'pool' catalog node carrying its own raw JSON."""
    try:
        data = json.loads(text)
    except Exception:
        die("subscription JSON could not be parsed")
    profiles = data if isinstance(data, list) else [data]
    nodes = []
    seen = set()
    for prof in profiles:
        if len(nodes) >= MAX_NODES:
            break
        if not isinstance(prof, dict):
            continue
        raw_json = json.dumps(prof, ensure_ascii=False, separators=(",", ":"))
        if len(raw_json) > 200000:        # cap a single profile (sanity)
            continue
        nid = hashlib.sha256(raw_json.encode("utf-8", "replace")).hexdigest()
        if nid in seen:
            continue
        seen.add(nid)
        label = prof.get("remarks") if isinstance(prof.get("remarks"), str) else ""
        # classify + count balancer members; reject profiles we can't host
        recognized, reason, members, strat, servers = _classify_profile(prof)
        nodes.append({
            "kind": "pool", "scheme": "json", "label": label,
            "server": ("%d nodes, %s" % (members, strat)) if members else "profile",
            "recognized": recognized, "engine": "xraypool", "reason": reason,
            "members": members, "strategy": strat,
            "id": nid, "profile": raw_json,
        })
    for n, nd in enumerate(nodes, 1):
        nd["n"] = n
    if not nodes:
        die("subscription JSON contained no usable profiles")
    if sum(1 for x in nodes if x["recognized"]) == 0:
        die("subscription JSON has no supported profiles")
    meta = {"count": len(nodes), "supported": sum(1 for x in nodes if x["recognized"]),
            "format": "json"}
    meta.update(_meta_from_headers(headers))
    return {"schema": SCHEMA_VERSION, "meta": meta, "nodes": nodes}


def _classify_profile(prof):
    """(recognized, reason, members, strategy, servers) for an Xray JSON profile.
    A profile is unrecognized if it has no outbounds, or its only proxy server is
    the provider's 'App not supported' 0.0.0.0 placeholder, or it relies on
    source/SOCKS-auth routing a WireGuard inbound can't reproduce."""
    outs = prof.get("outbounds")
    if not isinstance(outs, list) or not outs:
        return False, "no outbounds", 0, "", []
    servers = []
    for o in outs:
        if not isinstance(o, dict):
            continue
        vn = o.get("settings", {}).get("vnext") if isinstance(o.get("settings"), dict) else None
        if isinstance(vn, list):
            for v in vn:
                if isinstance(v, dict) and v.get("address"):
                    servers.append(str(v["address"]))
        elif o.get("server"):
            servers.append(str(o["server"]))
    real = [s for s in servers if s not in ("0.0.0.0", "127.0.0.1", "", "1")]
    if not real:
        return False, "provider placeholder (app not authorized)", 0, "", servers
    # source/user routing can't be reproduced by a WireGuard inbound
    routing = prof.get("routing", {})
    rules = routing.get("rules", []) if isinstance(routing, dict) else []
    for r in rules:
        if isinstance(r, dict) and (r.get("user") or r.get("source") or r.get("sourcePort")):
            return False, "routing needs source/user identity", 0, "", servers
    bals = routing.get("balancers") if isinstance(routing, dict) else None
    members, strat = 0, ""
    if isinstance(bals, list) and bals and isinstance(bals[0], dict):
        sels = bals[0].get("selector") or []
        tags = [str(o.get("tag", "")) for o in outs if isinstance(o, dict)]
        members = sum(1 for t in tags if any(t.startswith(s) for s in sels))
        st = bals[0].get("strategy")
        if isinstance(st, dict):
            strat = str(st.get("type", "") or "")
    else:
        members = len(real)
    return True, "", members, strat or "single", real


def process_body(raw, headers=None):
    text = raw.decode("utf-8", "replace").strip()
    head = text[:200].lstrip().lower()
    if head[:1] == "<" or "<html" in head or "<!doctype" in head:
        die("the URL returned an HTML page, not a subscription")
    # JSON profile(s) -- a Remnawave/Happ-style Xray balancer feed (object or array).
    if head[:1] in ("{", "["):
        return _process_json(text, headers)
    if "://" not in text:
        dec = _b64(text)
        if not dec or "://" not in dec:
            # base64 may also wrap a JSON profile feed
            if dec and dec.lstrip()[:1] in ("{", "["):
                return _process_json(dec, headers)
            die("could not decode subscription (not a base64 / plain link list)")
        text = dec
        if dec.lstrip()[:1] in ("{", "["):
            return _process_json(dec, headers)
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
    meta = {"count": len(nodes), "supported": supported, "format": "links"}
    meta.update(_meta_from_headers(headers))
    return {"schema": SCHEMA_VERSION, "meta": meta, "nodes": nodes}


# ---- network (SSRF-safe, DNS-rebinding-safe) ------------------------------
def _norm_origin(u):
    """(scheme, host, port) with default ports normalized so a redirect to an
    explicit :443 from an implicit one is still treated as same-origin."""
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    port = u.port if u.port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, port)


def _idna_host(host):
    """ASCII host suitable for a Host header / SNI; encode IDN names, else die."""
    try:
        host.encode("ascii")
        return host
    except UnicodeEncodeError:
        try:
            return host.encode("idna").decode("ascii")
        except Exception:
            die("subscription host is not a valid domain name")


def _net():
    """Import and return the network-only stdlib modules on first use, so the
    purely-local subcommands never pay for them. Cached on the function object."""
    if not hasattr(_net, "_m"):
        import socket, ssl, http.client, ipaddress, time
        from urllib.parse import urljoin
        _net._m = (socket, ssl, http.client, ipaddress, time, urljoin)
    return _net._m


def _public_ips(host):
    """All validated public IPs for host (every resolved address), or die. A
    non-global/special-purpose address anywhere in the result set is rejected
    (CGNAT, private, loopback, link-local, reserved, multicast, etc.)."""
    socket, _ssl, _hc, ipaddress, _t, _uj = _net()
    # PROXY_UNIFI_SUB_ALLOW_PRIVATE=1 disables the SSRF guard (tests only).
    allow_private = os.environ.get("PROXY_UNIFI_SUB_ALLOW_PRIVATE") == "1"
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception as e:
        die("could not resolve host: %s" % e)
    out = []
    seen = set()
    for info in infos:
        fam, addr = info[0], info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        ip = ipaddress.ip_address(addr)
        if not allow_private and not ip.is_global:
            die("refusing to fetch: %s resolves to a non-public address" % host)
        out.append((fam, addr))
    if not out:
        die("host did not resolve to any address")
    return out


def _remaining(deadline):
    _s, _ssl, _hc, _ip, time, _uj = _net()
    r = deadline - time.monotonic()
    if r <= 0:
        die("subscription request exceeded the time budget")
    return min(r, TIMEOUT)


def _https_get(url, send_hwid, hwid, ua, deadline):
    """One HTTPS GET. Tries every validated address (mixed IPv4/IPv6 safe). Each
    blocking op uses the remaining overall budget. Returns
    (status, headers, body_or_None, redirect_location)."""
    socket, ssl, http_client, ipaddress, _t, _uj = _net()
    u = urlsplit(url)
    if (u.scheme or "").lower() != "https":
        die("only https:// subscription URLs are allowed")
    host = u.hostname
    if not host:
        die("subscription URL has no host")
    port = u.port or 443
    sni = _idna_host(host)
    ctx = ssl.create_default_context()

    # connect+TLS to the first address that works (within the shared deadline)
    tls = None
    last_err = "no address"
    for fam, addr in _public_ips(host):
        try:
            raw = socket.create_connection((addr, port), timeout=_remaining(deadline))
        except OSError as e:
            last_err = str(e); continue
        try:
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            break
        except (ssl.SSLError, OSError) as e:
            raw.close(); tls = None; last_err = str(e); continue
    if tls is None:
        die("could not connect to subscription host: %s" % last_err)

    try:
        tls.settimeout(_remaining(deadline))
        conn = http_client.HTTPConnection(sni, port, timeout=_remaining(deadline))
        conn.sock = tls
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        # RFC-correct Host header: include port if non-default, bracket IPv6
        hostport = sni
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                hostport = "[%s]" % host
        except ValueError:
            pass
        if port != 443:
            hostport = "%s:%d" % (hostport, port)
        hdrs = {"Host": hostport, "User-Agent": ua, "Accept": "*/*", "Connection": "close"}
        if send_hwid and hwid:
            hdrs["x-hwid"] = hwid
        try:
            conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
        except (http_client.HTTPException, OSError) as e:
            die("HTTP request failed: %s" % e)
        status = resp.status
        rheaders = {k.lower(): v for k, v in resp.getheaders()}
        if status in (301, 302, 303, 307, 308):
            return status, rheaders, None, rheaders.get("location")
        if status != 200:
            die("HTTP error %s from subscription server" % status)
        # Set the read timeout ONCE on the underlying socket. Re-setting it on
        # every iteration corrupts http.client's chunked/buffered reader and
        # yields "Bad file descriptor", so do it before the read, not inside it.
        try:
            tls.settimeout(_remaining(deadline))
        except OSError:
            pass
        try:
            # resp.read() transparently handles chunked transfer-encoding; cap by
            # reading one byte past the limit.
            body = resp.read(MAX_BYTES + 1)
        except (http_client.HTTPException, OSError) as e:
            die("error reading subscription body: %s" % e)
        if len(body) > MAX_BYTES:
            die("subscription too large (> %d bytes)" % MAX_BYTES)
        # transparently decompress gzip/deflate if the server used it
        enc = (rheaders.get("content-encoding") or "").lower()
        if "gzip" in enc:
            import gzip
            try:
                body = gzip.decompress(body)
            except Exception:
                die("could not decompress gzip subscription body")
        elif "deflate" in enc:
            import zlib
            try:
                body = zlib.decompress(body)
            except Exception:
                try:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
                except Exception:
                    die("could not decompress deflate subscription body")
        return status, rheaders, body, None
    finally:
        try:
            tls.close()
        except Exception:
            pass


def fetch_url(url, hwid, ua):
    _s, _ssl, _hc, _ip, time, urljoin = _net()
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
    # ensure_ascii=True: the on-disk catalog stays pure ASCII (\uXXXX escapes),
    # so stored text (Cyrillic / CJK labels, ...) survives being written and read
    # back regardless of the gateway's locale / stream encoding.
    json.dump(process_body(raw, headers), sys.stdout, ensure_ascii=True, indent=2)
    sys.stdout.write("\n")


_HEX64 = set("0123456789abcdef")


def _validate_node(nd):
    """Validate one catalog node's shape, or die. Returns the node."""
    if not isinstance(nd, dict):
        die("catalog has a malformed node (not an object)")
    nid = nd.get("id")
    if not (isinstance(nid, str) and len(nid) == 64 and all(c in _HEX64 for c in nid)):
        die("catalog node has an invalid id")
    if not isinstance(nd.get("n"), int) or nd["n"] < 1:
        die("catalog node has an invalid index")
    if not isinstance(nd.get("recognized"), bool):
        die("catalog node has an invalid 'recognized' flag")
    sch = nd.get("scheme")
    if nd.get("kind") == "pool" or sch == "json":
        # a JSON balancer/pool profile node: validate it carries raw profile JSON
        prof = nd.get("profile")
        if not isinstance(prof, str) or not prof.strip() or len(prof) > 200000:
            die("catalog pool node has an invalid profile")
    else:
        if not isinstance(sch, str) or sch not in SUPPORTED:
            die("catalog node has an invalid scheme")
        link = nd.get("link")
        if not isinstance(link, str) or "://" not in link or len(link) > MAX_LINK:
            die("catalog node has an invalid link")
        if any(ord(c) < 0x20 or ord(c) == 0x7f for c in link):
            die("catalog node link contains control characters")
    for f in ("label", "server", "reason", "engine"):
        if not isinstance(nd.get(f, ""), str):
            die("catalog node field '%s' is not a string" % f)
    return nd


def _migrate(cat):
    """Bring an older catalog up to the current schema, or return None if it
    cannot be migrated safely (caller then forces a refresh)."""
    nodes = cat.get("nodes")
    if not isinstance(nodes, list):
        return None
    # schema 1 (pre-versioning): had 'supported' instead of 'recognized', short
    # 8-char ids, and no 'schema' key. We can't reconstruct full-hash ids from the
    # old short ones, so a stored selection won't match -> force a refresh.
    if cat.get("schema") != SCHEMA_VERSION:
        return None
    return cat


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cat = json.load(fh)
    except Exception as e:
        die("could not read catalog: %s" % e)
    if not isinstance(cat, dict) or not isinstance(cat.get("nodes"), list):
        die("catalog is malformed")
    if _migrate(cat) is None:
        die("subscription catalog is from an older version; run a refresh "
            "(menu -> Import or replace -> subscription -> Refresh)")
    seen_n = set(); seen_id = set()
    for nd in cat["nodes"]:
        _validate_node(nd)
        if nd["n"] in seen_n:
            die("catalog has a duplicate node index")
        if nd["id"] in seen_id:
            die("catalog has a duplicate node id")
        seen_n.add(nd["n"]); seen_id.add(nd["id"])
    return cat


def cmd_render(args):
    cat = _load(args.file)
    nodes = cat.get("nodes", [])
    if not nodes:
        print("(no nodes in subscription)")
        return
    selected = getattr(args, "selected", "") or ""
    for nd in nodes:
        if not nd.get("recognized"):
            mark = "x"
        elif selected and nd.get("id") == selected:
            mark = "*"
        else:
            mark = " "
        label = clean(nd.get("label", ""), LABEL_MAX) or "(no label)"
        server = clean(nd.get("server", "?"), 40)
        scheme = clean(nd.get("scheme", "?"), 12)
        line = "%3d. [%s] %-9s %-24s %s" % (
            nd.get("n", 0), mark, scheme, server, label)
        if not nd.get("recognized") and nd.get("reason"):
            line += "  (%s)" % clean(nd["reason"], 40)
        print(line)


def cmd_get(args):
    cat = _load(args.file)
    match = [x for x in cat.get("nodes", []) if x.get("n") == args.index]
    if not match:
        die("no node #%d in subscription" % args.index)
    nd = match[0]
    kind = "pool" if (nd.get("kind") == "pool" or nd.get("scheme") == "json") else "link"
    # for a link node field 5 is the link; for a pool node it is the kind marker
    payload = "" if kind == "pool" else nd.get("link", "")
    sys.stdout.write("%s\t%s\t%s\t%s\t%s\n" % (
        nd.get("id", ""), "1" if nd.get("recognized") else "0",
        clean(nd.get("reason", ""), 60), kind, payload))


def cmd_find(args):
    for nd in _load(args.file).get("nodes", []):
        if nd.get("id") == args.id and nd.get("recognized"):
            if nd.get("kind") == "pool" or nd.get("scheme") == "json":
                sys.stdout.write("pool\n")    # caller must use 'profile' to get JSON
            else:
                sys.stdout.write(nd.get("link", "") + "\n")
            return
    sys.exit(1)


def cmd_profile(args):
    """Write the raw JSON profile of a pool node (by id) to stdout, for the shell
    to import via the balancer/-confdir path."""
    for nd in _load(args.file).get("nodes", []):
        if nd.get("id") == args.id and (nd.get("kind") == "pool" or nd.get("scheme") == "json"):
            prof = nd.get("profile")
            if isinstance(prof, str) and prof.strip():
                sys.stdout.write(prof)
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
    # Default UA mimics a recognized client: HWID-gated providers (Remnawave)
    # only serve the real config to allowlisted clients, returning an
    # "App not supported" placeholder to anything else.
    f.add_argument("--ua", default="Happ/1.0")
    f.add_argument("--body-file", default="")
    f.set_defaults(fn=cmd_fetch)

    r = sub.add_parser("render")
    r.add_argument("--file", required=True)
    r.add_argument("--selected", default="")   # id of the active node -> "[*]"
    r.set_defaults(fn=cmd_render)

    g = sub.add_parser("get")
    g.add_argument("--file", required=True)
    g.add_argument("--index", type=int, required=True)
    g.set_defaults(fn=cmd_get)

    n = sub.add_parser("find")
    n.add_argument("--file", required=True)
    n.add_argument("--id", required=True)
    n.set_defaults(fn=cmd_find)

    p = sub.add_parser("profile")
    p.add_argument("--file", required=True)
    p.add_argument("--id", required=True)
    p.set_defaults(fn=cmd_profile)

    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        sys.exit(2)
    args.fn(args)


if __name__ == "__main__":
    main()
