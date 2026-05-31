#!/usr/bin/env python3
"""
mksingbox.py - Build a sing-box config for the UniFi WireGuard bridge.

Used for the protocols xray-core can't do natively: Shadowsocks with a SIP003
plugin handled in-process (obfs-local / v2ray-plugin), Hysteria2 and TUIC.

Topology mirrors the xray path: a WireGuard *server* endpoint terminates the
UniFi gateway's WireGuard VPN Client (same keys/port), and everything it
receives is routed to the proxy outbound.

Stdlib only (Python 3.7+).
"""

import argparse
import base64
import json
import sys
from urllib.parse import urlsplit, parse_qs, unquote


def die(msg):
    sys.stderr.write("mksingbox: error: %s\n" % msg)
    sys.exit(2)


def _b64_pad(s):
    return s + "=" * (-len(s) % 4)


def _b64decode_any(s):
    s = s.strip()
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(_b64_pad(s)).decode("utf-8")
        except Exception:
            pass
    return None


def flat_query(u):
    return {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}


def qg(q, *names, default=""):
    for n in names:
        if q.get(n, "") != "":
            return q[n]
    return default


def host_port(u):
    """(hostname, port) from a urlsplit result, dying cleanly on a bad port
    (urlsplit raises ValueError instead of returning None for non-numeric ports)."""
    try:
        return u.hostname, u.port
    except ValueError:
        die("invalid port in link (must be 1-65535)")


def _truthy(v):
    return str(v).lower() in ("1", "true", "yes")


def _tls(sni, q, default_alpn=None):
    tls = {"enabled": True, "server_name": sni}
    alpn = qg(q, "alpn")
    if alpn:
        tls["alpn"] = [a for a in alpn.split(",") if a]
    elif default_alpn:
        tls["alpn"] = default_alpn
    if _truthy(qg(q, "insecure", "allowInsecure", "allow_insecure")):
        tls["insecure"] = True
    fp = qg(q, "fp", "fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def plugin_alias(name):
    if name in ("simple-obfs", "obfs-local"):
        return "obfs-local"
    return name


# --------------------------------------------------------------------------
# Per-protocol outbound builders -> (outbound dict, host, port)
# --------------------------------------------------------------------------
def parse_ss(link):
    u = urlsplit(link)
    host, port = host_port(u)
    method = password = None
    if u.username is not None and host and port:
        if u.password is not None:
            method, password = unquote(u.username), unquote(u.password)
        else:
            dec = _b64decode_any(u.username)
            if dec and ":" in dec:
                method, password = dec.split(":", 1)
    if method is None:
        dec = _b64decode_any(u.netloc)
        if dec and "@" in dec and ":" in dec:
            creds, hostport = dec.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, p = hostport.rsplit(":", 1)
            port = int(p)
    if not method or not password or not host or not port:
        die("could not parse shadowsocks link")

    out = {"type": "shadowsocks", "tag": "proxy", "server": host,
           "server_port": int(port), "method": method, "password": password}

    raw = qg(flat_query(u), "plugin")
    if raw:
        raw = unquote(raw)
        name, opts = (raw.split(";", 1) + [""])[:2]
        out["plugin"] = plugin_alias(name)
        out["plugin_opts"] = opts
    return out, host, int(port)


def parse_hysteria2(link):
    u = urlsplit(link)
    host, port = host_port(u)
    auth = unquote(u.username or "")
    if u.password:                       # hysteria2://user:pass@ -> password is after ':'
        auth = auth + ":" + unquote(u.password) if auth else unquote(u.password)
    if not host or not port:
        die("hysteria2 link is missing host/port")
    q = flat_query(u)
    sni = qg(q, "sni", "peer") or host
    out = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": int(port),
           "password": auth, "tls": _tls(sni, q, default_alpn=["h3"])}
    obfs_pw = qg(q, "obfs-password", "obfs_password")
    if qg(q, "obfs") and obfs_pw:
        out["obfs"] = {"type": "salamander", "password": obfs_pw}
    return out, host, int(port)


def parse_tuic(link):
    u = urlsplit(link)
    host, port = host_port(u)
    uuid = unquote(u.username or "")
    password = unquote(u.password or "")
    if not uuid or not host or not port:
        die("tuic link is missing uuid/host/port")
    q = flat_query(u)
    sni = qg(q, "sni", "peer") or host
    out = {"type": "tuic", "tag": "proxy", "server": host, "server_port": int(port),
           "uuid": uuid, "password": password, "tls": _tls(sni, q, default_alpn=["h3"])}
    cc = qg(q, "congestion_control", "congestion")
    if cc:
        out["congestion_control"] = cc
    urm = qg(q, "udp_relay_mode")
    if urm:
        out["udp_relay_mode"] = urm
    return out, host, int(port)


def parse_link(link):
    link = link.strip()
    low = link.lower()
    if low.startswith("hysteria2://") or low.startswith("hy2://"):
        return parse_hysteria2(link)
    if low.startswith("tuic://"):
        return parse_tuic(link)
    if low.startswith("ss://"):
        return parse_ss(link)
    die("unsupported link for sing-box (expected ss:// with plugin, hysteria2://, or tuic://)")


def build_test_config(args):
    """Throwaway config: SOCKS inbound on loopback -> the proxy outbound (for `ping`)."""
    outbound, _, _ = parse_link(args.link)
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": args.socks_port}],
        "outbounds": [outbound],
        "route": {"rules": [{"inbound": ["socks-in"], "outbound": "proxy"}], "final": "proxy"},
    }


def build_config(args):
    outbound, _, _ = parse_link(args.link)
    endpoint = {
        "type": "wireguard",
        "tag": "wg-in",
        "system": False,
        "mtu": args.mtu,
        "address": [a for a in args.address.split(",") if a],
        "private_key": args.secret_key,
        "listen_port": args.port,
        "peers": [{
            "public_key": args.peer_pubkey,
            "allowed_ips": [x for x in args.peer_allowed.split(",") if x],
        }],
    }
    return {
        "log": {"level": args.loglevel},
        "endpoints": [endpoint],
        "outbounds": [outbound],
        "route": {
            "rules": [{"inbound": ["wg-in"], "outbound": "proxy"}],
            "final": "proxy",
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Build sing-box config for the UniFi WireGuard bridge")
    ap.add_argument("--link", required=True, help="proxy share link (ss:// w/ plugin, hysteria2://, tuic://)")
    ap.add_argument("--port", type=int, default=0, help="UDP port for the WireGuard endpoint")
    ap.add_argument("--secret-key", default="", help="local WireGuard private key, base64")
    ap.add_argument("--peer-pubkey", default="", help="UniFi WireGuard public key, base64")
    ap.add_argument("--address", default="10.7.0.1/32")
    ap.add_argument("--peer-allowed", default="0.0.0.0/0,::/0")
    ap.add_argument("--mtu", type=int, default=1340)
    ap.add_argument("--loglevel", default="warn")
    ap.add_argument("--print-server", action="store_true", help="print 'host<TAB>port' and exit")
    ap.add_argument("--socks-port", type=int, default=0, help="emit a SOCKS test config on this port instead")
    args = ap.parse_args()

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

    json.dump(build_config(args), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
