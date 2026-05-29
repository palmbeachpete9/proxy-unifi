#!/usr/bin/env python3
"""
mkconfig.py - Build a complete Xray-core config.json for the UniFi WireGuard bridge.

Topology:
    UniFi WireGuard VPN Client  --(UDP 127.0.0.1:PORT)-->  Xray WireGuard inbound
        --> VLESS outbound (parsed from a vless:// link) --> remote VPN server

This script parses a vless:// share link into an Xray outbound and emits a full
config that terminates a WireGuard peer (the UniFi gateway) locally and forwards
everything out through that VLESS server.

It is intentionally dependency-free (Python 3.7+ stdlib only) so it runs on the
gateway as shipped.
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


def parse_vless(link):
    """Parse a vless:// link into (outbound dict)."""
    link = link.strip()
    if not link.lower().startswith("vless://"):
        die("not a vless:// link")

    u = urlsplit(link)
    uuid = unquote(u.username or "")
    if not uuid:
        die("vless link is missing the UUID (user info)")

    host = u.hostname
    port = u.port
    if not host:
        die("vless link is missing the server host")
    if not port:
        die("vless link is missing the server port")

    # parse_qs returns lists; flatten to single values
    raw = parse_qs(u.query, keep_blank_values=True)
    q = {k: v[0] for k, v in raw.items()}

    def g(*names, default=""):
        for n in names:
            if n in q and q[n] != "":
                return q[n]
        return default

    encryption = g("encryption", default="none") or "none"
    flow = g("flow")
    net = g("type", "net", default="tcp") or "tcp"
    security = g("security", default="none") or "none"

    # normalize aliases
    if net == "h2":
        net = "http"

    user = {"id": uuid, "encryption": encryption}
    if flow:
        user["flow"] = flow

    stream = {"network": net, "security": security}

    # ---- security layer -------------------------------------------------
    sni = g("sni", "peer", "host") or host
    fp = g("fp", "fingerprint")
    alpn = g("alpn")
    allow_insecure = g("allowInsecure", "insecure") in ("1", "true", "True")

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
        reality = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": g("pbk", "publicKey"),
            "shortId": g("sid", "shortId"),
            "spiderX": g("spx", "spiderX", default="/"),
        }
        stream["realitySettings"] = reality
    elif security in ("", "none"):
        stream["security"] = "none"
    else:
        die("unsupported security '%s'" % security)

    # ---- transport layer ------------------------------------------------
    header_type = g("headerType", default="none")
    host_hdr = g("host")
    path = g("path", default="/")

    if net == "tcp":
        if header_type == "http":
            req_host = [h for h in host_hdr.split(",") if h] or [host]
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [path] if path else ["/"],
                        "headers": {"Host": req_host},
                    },
                }
            }
        # plain tcp needs no tcpSettings
    elif net == "ws":
        ws = {"path": path or "/"}
        headers = {}
        if host_hdr:
            headers["Host"] = host_hdr
        if headers:
            ws["headers"] = headers
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
        grpc = {"serviceName": g("serviceName", "path", default="")}
        mode = g("mode")
        if mode in ("multi", "gun"):
            grpc["multiMode"] = mode == "multi"
        stream["grpcSettings"] = grpc
    elif net == "xhttp" or net == "splithttp":
        stream["network"] = "xhttp"
        xh = {"path": path or "/"}
        if host_hdr:
            xh["host"] = host_hdr
        mode = g("mode")
        if mode:
            xh["mode"] = mode
        stream["xhttpSettings"] = xh
    elif net == "kcp":
        kcp = {"header": {"type": header_type or "none"}}
        seed = g("seed")
        if seed:
            kcp["seed"] = seed
        stream["kcpSettings"] = kcp
    elif net == "quic":
        quic = {
            "security": g("quicSecurity", default="none"),
            "key": g("key", default=""),
            "header": {"type": header_type or "none"},
        }
        stream["quicSettings"] = quic
    else:
        die("unsupported transport type '%s'" % net)

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {"address": host, "port": int(port), "users": [user]}
            ]
        },
        "streamSettings": stream,
    }
    return outbound, host


def build_test_config(args):
    """A throwaway config: SOCKS inbound on loopback -> the same VLESS outbound.
    Used by `xray ping` to send a real request through the link in isolation."""
    outbound, _ = parse_vless(args.link)
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
    outbound, server_host = parse_vless(args.link)

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
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": True,
        },
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
            "rules": [
                # everything that enters via the WireGuard tunnel goes out the proxy
                {"type": "field", "inboundTag": ["wg-in"], "outboundTag": "proxy"}
            ],
        },
    }

    # optional DNS pinning for the inner resolver
    if args.dns:
        servers = [s for s in args.dns.split(",") if s]
        config["dns"] = {"servers": servers}

    return config


def main():
    ap = argparse.ArgumentParser(description="Build Xray config for the UniFi WireGuard bridge")
    ap.add_argument("--link", required=True, help="vless:// share link")
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
    ap.add_argument("--print-server", action="store_true", help="print 'host<TAB>port' of the VLESS server and exit")
    args = ap.parse_args()

    # mode: print the server endpoint (for tcp/icmp ping)
    if args.print_server:
        outbound, host = parse_vless(args.link)
        port = outbound["settings"]["vnext"][0]["port"]
        sys.stdout.write("%s\t%s\n" % (host, port))
        return

    # mode: throwaway SOCKS test config (for proxied GET/HEAD ping)
    if args.socks_port:
        json.dump(build_test_config(args), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    # default: full WireGuard->VLESS bridge config
    if not args.secret_key or not args.peer_pubkey or not args.port:
        die("--port, --secret-key and --peer-pubkey are required to build the bridge config")

    # light validation of the tunnel addresses
    for a in args.address.split(","):
        a = a.strip()
        if not a:
            continue
        try:
            ipaddress.ip_interface(a)
        except ValueError:
            die("invalid --address '%s'" % a)

    config = build_config(args)
    json.dump(config, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
