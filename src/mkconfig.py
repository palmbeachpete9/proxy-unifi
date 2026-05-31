#!/usr/bin/env python3
"""
mkconfig.py - Build a complete Xray-core config.json for the UniFi WireGuard bridge.

Topology:
    UniFi WireGuard VPN Client  --(UDP 127.0.0.1:PORT)-->  Xray WireGuard inbound
        --> proxy outbound (parsed from a vless:// / vmess:// / trojan:// / ss:// link)
        --> remote proxy server

It parses a proxy share link into an Xray outbound and emits a full config that
terminates a WireGuard peer (the UniFi gateway) locally and forwards everything
out through that proxy server.

Dependency-free (Python 3.7+ stdlib only) so it runs on the gateway as shipped.
"""

import argparse
import base64
import ipaddress
import json
import sys
from urllib.parse import urlsplit, parse_qs, unquote


def die(msg):
    sys.stderr.write("mkconfig: error: %s\n" % msg)
    sys.exit(2)


def _b64_pad(s):
    return s + "=" * (-len(s) % 4)


def _b64decode_any(s):
    """Decode url-safe or standard base64, with or without padding."""
    s = s.strip()
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(_b64_pad(s)).decode("utf-8")
        except Exception:
            pass
    return None


def flat_query(u):
    raw = parse_qs(u.query, keep_blank_values=True)
    return {k: v[0] for k, v in raw.items()}


def qg(q, *names, default=""):
    for n in names:
        if q.get(n, "") != "":
            return q[n]
    return default


def build_stream(q, security, net, host):
    """Build streamSettings shared by VLESS and Trojan."""
    if net == "h2":
        net = "http"
    stream = {"network": net, "security": security}

    # ---- security layer -------------------------------------------------
    sni = qg(q, "sni", "peer", "host") or host
    fp = qg(q, "fp", "fingerprint")
    alpn = qg(q, "alpn")
    allow_insecure = qg(q, "allowInsecure", "insecure") in ("1", "true", "True")

    if security == "tls":
        tls = {"serverName": sni}
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        if allow_insecure:
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": qg(q, "pbk", "publicKey"),
            "shortId": qg(q, "sid", "shortId"),
            "spiderX": qg(q, "spx", "spiderX", default="/"),
        }
    elif security in ("", "none"):
        stream["security"] = "none"
    else:
        die("unsupported security '%s'" % security)

    # ---- transport layer ------------------------------------------------
    header_type = qg(q, "headerType", default="none")
    host_hdr = qg(q, "host")
    path = qg(q, "path", default="/")

    if net == "tcp":
        if header_type == "http":
            req_host = [h for h in host_hdr.split(",") if h] or [host]
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {"path": [path] if path else ["/"], "headers": {"Host": req_host}},
                }
            }
    elif net == "ws":
        ws = {"path": path or "/"}
        if host_hdr:
            ws["headers"] = {"Host": host_hdr}
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        hu = {"path": path or "/"}
        if host_hdr:
            hu["host"] = host_hdr
        stream["httpupgradeSettings"] = hu
    elif net == "http":
        h = {"path": path or "/"}
        hosts = [x for x in host_hdr.split(",") if x]
        if hosts:
            h["host"] = hosts
        stream["httpSettings"] = h
    elif net == "grpc":
        grpc = {"serviceName": qg(q, "serviceName", "path", default="")}
        mode = qg(q, "mode")
        if mode in ("multi", "gun"):
            grpc["multiMode"] = mode == "multi"
        stream["grpcSettings"] = grpc
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        xh = {"path": path or "/"}
        if host_hdr:
            xh["host"] = host_hdr
        mode = qg(q, "mode")
        if mode:
            xh["mode"] = mode
        stream["xhttpSettings"] = xh
    elif net == "kcp":
        kcp = {"header": {"type": header_type or "none"}}
        seed = qg(q, "seed")
        if seed:
            kcp["seed"] = seed
        stream["kcpSettings"] = kcp
    elif net == "quic":
        stream["quicSettings"] = {
            "security": qg(q, "quicSecurity", default="none"),
            "key": qg(q, "key", default=""),
            "header": {"type": header_type or "none"},
        }
    else:
        die("unsupported transport type '%s'" % net)

    return stream


def parse_vless(link):
    u = urlsplit(link)
    uuid = unquote(u.username or "")
    host, port = u.hostname, u.port
    if not uuid:
        die("vless link is missing the UUID")
    if not host or not port:
        die("vless link is missing the server host/port")
    q = flat_query(u)

    user = {"id": uuid, "encryption": qg(q, "encryption", default="none") or "none"}
    flow = qg(q, "flow")
    if flow:
        user["flow"] = flow

    net = qg(q, "type", "net", default="tcp") or "tcp"
    security = qg(q, "security", default="none") or "none"
    stream = build_stream(q, security, net, host)

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": int(port), "users": [user]}]},
        "streamSettings": stream,
    }
    return outbound, host, int(port)


def parse_trojan(link):
    u = urlsplit(link)
    password = unquote(u.username or "")
    host, port = u.hostname, u.port
    if not password:
        die("trojan link is missing the password")
    if not host or not port:
        die("trojan link is missing the server host/port")
    q = flat_query(u)

    net = qg(q, "type", "net", default="tcp") or "tcp"
    security = qg(q, "security", default="tls") or "tls"   # trojan implies TLS
    stream = build_stream(q, security, net, host)

    # Note: xray removed the "flow" field for Trojan, so it is intentionally not
    # emitted here even if the link carries one.
    server = {"address": host, "port": int(port), "password": password}

    outbound = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {"servers": [server]},
        "streamSettings": stream,
    }
    return outbound, host, int(port)


def _ss_creds(link):
    """Decode (method, password, host, port) from an ss:// link (no plugin logic)."""
    u = urlsplit(link)
    host, port = u.hostname, u.port
    method = password = None

    # SIP002: ss://base64(method:password)@host:port  (or plain method:password)
    if u.username is not None and host and port:
        if u.password is not None:
            method, password = unquote(u.username), unquote(u.password)
        else:
            dec = _b64decode_any(u.username)
            if dec and ":" in dec:
                method, password = dec.split(":", 1)

    # Legacy: ss://base64(method:password@host:port)
    if method is None:
        dec = _b64decode_any(u.netloc)
        if dec and "@" in dec and ":" in dec:
            creds, hostport = dec.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, p = hostport.rsplit(":", 1)
            port = int(p)

    if not method or not password or not host or not port:
        die("could not parse shadowsocks link")
    return method, password, host, int(port)


def ss_plugin_name(link):
    """Return the SIP003 plugin name for an ss:// link, or None if it has no plugin."""
    raw = qg(flat_query(urlsplit(link)), "plugin")
    if not raw:
        return None
    raw = unquote(raw)
    return raw.split(";", 1)[0] if ";" in raw else raw


def parse_ss(link):
    method, password, host, port = _ss_creds(link)
    # SIP003-plugin Shadowsocks is handled by sing-box, never by xray.
    if ss_plugin_name(link):
        die("shadowsocks SIP003 plugin links are handled by sing-box, not xray")
    outbound = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{"address": host, "port": port, "method": method, "password": password}]
        },
    }
    return outbound, host, port


def parse_vmess(link):
    # Standard (v2rayN) form: vmess://base64(json). Decode and map the fields.
    body = link[len("vmess://"):]
    body = body.split("#", 1)[0]
    dec = _b64decode_any(body)
    if not dec:
        die("could not decode vmess link (expected base64-encoded JSON)")
    try:
        v = json.loads(dec)
    except Exception:
        die("vmess link is not valid base64-encoded JSON")

    host = str(v.get("add", "") or "")
    port = v.get("port")
    uid = str(v.get("id", "") or "")
    if not host or not port or not uid:
        die("vmess link is missing add/port/id")

    net = str(v.get("net", "tcp") or "tcp")
    tls = str(v.get("tls", "") or "")
    if tls == "reality":
        security = "reality"
    elif tls in ("tls", "xtls"):
        security = "tls"
    else:
        security = "none"

    # translate vmess fields into the same dict shape build_stream() consumes
    q = {}
    for src, dst in (("sni", "sni"), ("host", "host"), ("fp", "fp"),
                     ("alpn", "alpn"), ("type", "headerType"),
                     ("pbk", "pbk"), ("sid", "sid"), ("spx", "spx")):
        if v.get(src) not in (None, ""):
            q[dst] = str(v[src])
    if v.get("path") not in (None, ""):
        q["path"] = str(v["path"])
        q["serviceName"] = str(v["path"])   # grpc carries serviceName in "path"
    stream = build_stream(q, security, net, host)

    user = {
        "id": uid,
        "alterId": int(v.get("aid", 0) or 0),
        "security": str(v.get("scy", "auto") or "auto"),
    }
    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": int(port), "users": [user]}]},
        "streamSettings": stream,
    }
    return outbound, host, int(port)


def parse_link(link):
    link = link.strip()
    low = link.lower()
    if low.startswith("vless://"):
        return parse_vless(link)
    if low.startswith("vmess://"):
        return parse_vmess(link)
    if low.startswith("trojan://"):
        return parse_trojan(link)
    if low.startswith("ss://"):
        return parse_ss(link)
    die("unsupported link (expected vless://, vmess://, trojan://, or ss://)")


def build_test_config(args):
    """Throwaway config: SOCKS inbound on loopback -> the same proxy outbound.
    Used by `xray ping` to send a real request through the link in isolation."""
    outbound, _, _ = parse_link(args.link)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": args.socks_port,
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [outbound],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}],
        },
    }


def build_config(args):
    outbound, _, _ = parse_link(args.link)

    peer = {
        "publicKey": args.peer_pubkey,
        "allowedIPs": [x for x in args.peer_allowed.split(",") if x],
        "keepAlive": args.keepalive,
    }

    wg_inbound = {
        "tag": "wg-in",
        "listen": args.listen,
        "port": args.port,
        "protocol": "wireguard",
        "settings": {
            "secretKey": args.secret_key,
            "address": [x for x in args.address.split(",") if x],
            "mtu": args.mtu,
            "noKernelTun": True,
            "peers": [peer],
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
    }

    config = {
        "log": {"loglevel": args.loglevel},
        "inbounds": [wg_inbound],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["wg-in"], "outboundTag": "proxy"}],
        },
    }

    if args.dns:
        config["dns"] = {"servers": [s for s in args.dns.split(",") if s]}

    return config


def main():
    ap = argparse.ArgumentParser(description="Build Xray config for the UniFi WireGuard bridge")
    ap.add_argument("--link", required=True, help="proxy share link (vless:// / vmess:// / trojan:// / ss://)")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="UDP port for the WireGuard inbound")
    ap.add_argument("--secret-key", default="", help="Xray (server) WireGuard private key, base64")
    ap.add_argument("--peer-pubkey", default="", help="UniFi (client) WireGuard public key, base64")
    ap.add_argument("--address", default="10.7.0.1/32", help="Xray tunnel interface address(es)")
    ap.add_argument("--peer-allowed", default="0.0.0.0/0,::/0", help="allowedIPs accepted from the UniFi peer")
    ap.add_argument("--mtu", type=int, default=1340)
    ap.add_argument("--keepalive", type=int, default=25)
    ap.add_argument("--dns", default="", help="comma-separated inner DNS servers (optional)")
    ap.add_argument("--loglevel", default="warning")
    ap.add_argument("--socks-port", type=int, default=0, help="emit a SOCKS test config on this port instead")
    ap.add_argument("--print-server", action="store_true", help="print 'host<TAB>port' of the server and exit")
    ap.add_argument("--print-plugin", action="store_true",
                    help="print the SIP003 plugin name for an ss:// link, else nothing")
    args = ap.parse_args()

    if args.print_plugin:
        if args.link.strip().lower().startswith("ss://"):
            name = ss_plugin_name(args.link)
            if name:
                sys.stdout.write("%s\n" % name)
        return

    if args.print_server:
        _, host, port = parse_link(args.link)
        sys.stdout.write("%s\t%s\n" % (host, port))
        return

    if args.socks_port:
        json.dump(build_test_config(args), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    if not args.secret_key or not args.peer_pubkey or not args.port:
        die("--port, --secret-key and --peer-pubkey are required to build the bridge config")

    for a in args.address.split(","):
        a = a.strip()
        if not a:
            continue
        try:
            ipaddress.ip_interface(a)
        except ValueError:
            die("invalid --address '%s'" % a)

    json.dump(build_config(args), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
