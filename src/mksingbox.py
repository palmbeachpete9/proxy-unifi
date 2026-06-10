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


def safe_urlsplit(link):
    """urlsplit that dies cleanly on a malformed URL (e.g. bad bracketed host)."""
    try:
        return urlsplit(link)
    except ValueError:
        die("malformed link (could not parse URL)")


def host_port(u):
    """(hostname, port) from a urlsplit result, dying cleanly on a bad port
    (urlsplit raises ValueError instead of returning None for non-numeric ports)."""
    try:
        return u.hostname, u.port
    except ValueError:
        die("invalid port in link (must be 1-65535)")


def safe_port(value):
    try:
        p = int(value)
    except (TypeError, ValueError):
        die("invalid port in link (must be a number 1-65535)")
    if not (0 < p < 65536):
        die("port out of range in link (1-65535)")
    return p


_HOST_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]%")


def valid_host(host):
    """Return host if it is a safe IP/hostname, else die. Always rejects control/
    whitespace chars and a leading hyphen; non-ASCII only if IDNA-encodable."""
    if not host:
        die("link is missing a server host")
    if len(host) > 255:
        die("server host is too long")
    if host[0] == "-":
        die("invalid server host (starts with '-')")
    has_nonascii = False
    for ch in host:
        o = ord(ch)
        if o < 0x20 or o == 0x7f or ch in " \t\r\n":
            die("invalid server host (control/whitespace characters)")
        if o > 0x7f:
            has_nonascii = True
        elif ch not in _HOST_OK:
            die("invalid server host (unsafe characters)")
    if has_nonascii:
        try:
            host.encode("idna")
        except Exception:
            die("invalid server host (not a valid domain name)")
    return host


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
    u = safe_urlsplit(link)
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
            port = p
    if not method or not password or not host or not port:
        die("could not parse shadowsocks link")
    host = valid_host(host); port = safe_port(port)

    out = {"type": "shadowsocks", "tag": "proxy", "server": host,
           "server_port": port, "method": method, "password": password}

    raw = qg(flat_query(u), "plugin")
    if raw:
        raw = unquote(raw)
        name, opts = (raw.split(";", 1) + [""])[:2]
        out["plugin"] = plugin_alias(name)
        out["plugin_opts"] = opts
    return out, host, port


def parse_hysteria2(link):
    u = safe_urlsplit(link)
    host, port = host_port(u)
    if port is None:
        port = 443                       # hysteria2 default port
    host = valid_host(host); port = safe_port(port)
    auth = unquote(u.username or "")
    if u.password:                       # hysteria2://user:pass@ -> password is after ':'
        auth = auth + ":" + unquote(u.password) if auth else unquote(u.password)
    q = flat_query(u)
    # Reject a multi-port / port-hopping form we don't implement, rather than
    # silently connecting to a single port.
    if qg(q, "mport") or "-" in str(qg(q, "ports")) or "," in str(qg(q, "ports")):
        die("hysteria2 port-hopping (mport/ports) is not supported")
    sni = qg(q, "sni", "peer") or host
    tls = _tls(sni, q, default_alpn=["h3"])
    # pinSHA256 is a hex *certificate* fingerprint; sing-box only offers a base64
    # *public-key* pin (a different value), so we cannot honor it faithfully.
    # Reject rather than silently drop the requested pinning (security-relevant).
    if qg(q, "pinSHA256", "pinsha256"):
        die("hysteria2 'pinSHA256' certificate pinning is not supported")
    out = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": port,
           "password": auth, "tls": tls}
    obfs_pw = qg(q, "obfs-password", "obfs_password")
    obfs_type = qg(q, "obfs")
    if obfs_type and obfs_pw:
        # sing-box only implements 'salamander'; reject any other requested type
        # rather than silently substituting it.
        if obfs_type not in ("salamander",):
            die("hysteria2 obfs type '%s' is not supported (only salamander)" % obfs_type)
        out["obfs"] = {"type": "salamander", "password": obfs_pw}
    return out, host, port


def parse_tuic(link):
    u = safe_urlsplit(link)
    host, port = host_port(u)
    uuid = unquote(u.username or "")
    password = unquote(u.password or "")
    if not uuid or not host or not port:
        die("tuic link is missing uuid/host/port")
    host = valid_host(host); port = safe_port(port)
    q = flat_query(u)
    sni = qg(q, "sni", "peer") or host
    out = {"type": "tuic", "tag": "proxy", "server": host, "server_port": port,
           "uuid": uuid, "password": password, "tls": _tls(sni, q, default_alpn=["h3"])}
    cc = qg(q, "congestion_control", "congestion")
    if cc:
        out["congestion_control"] = cc
    urm = qg(q, "udp_relay_mode", "udp_over_stream")
    if qg(q, "udp_over_stream") in ("1", "true", "True"):
        out["udp_over_stream"] = True
    elif urm:
        out["udp_relay_mode"] = urm
    if qg(q, "zero_rtt_handshake", "reduce_rtt") in ("1", "true", "True"):
        out["zero_rtt_handshake"] = True
    hb = qg(q, "heartbeat")
    if hb:
        out["heartbeat"] = hb
    return out, host, port


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
    ap.add_argument("--link", default="", help="proxy share link (ss:// w/ plugin, hysteria2://, tuic://)")
    ap.add_argument("--port", type=int, default=0, help="UDP port for the WireGuard endpoint")
    ap.add_argument("--secret-key", default="", help="local WireGuard private key, base64")
    ap.add_argument("--peer-pubkey", default="", help="UniFi WireGuard public key, base64")
    ap.add_argument("--address", default="10.7.0.1/32")
    ap.add_argument("--peer-allowed", default="0.0.0.0/0,::/0")
    ap.add_argument("--mtu", type=int, default=1340)
    ap.add_argument("--loglevel", default="warn")
    ap.add_argument("--print-server", action="store_true", help="print 'host<TAB>port' and exit")
    ap.add_argument("--socks-port", type=int, default=0, help="emit a SOCKS test config on this port instead")
    ap.add_argument("--input-file", default="",
                    help="JSON file with secret inputs (link/secret_key/peer_pubkey), keeping "
                         "them out of argv; values here override the matching flags")
    args = ap.parse_args()

    # Secrets via a mode-600 file instead of argv (process-list safety + no ARG_MAX).
    if args.input_file:
        try:
            with open(args.input_file, "r", encoding="utf-8") as fh:
                _inp = json.load(fh)
        except Exception as e:
            die("could not read --input-file: %s" % e)
        if not isinstance(_inp, dict):
            die("--input-file must contain a JSON object")
        if "link" in _inp:
            args.link = str(_inp["link"])
        if "secret_key" in _inp:
            args.secret_key = str(_inp["secret_key"])
        if "peer_pubkey" in _inp:
            args.peer_pubkey = str(_inp["peer_pubkey"])
    if not args.link:
        die("no link provided (use --link or --input-file)")

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
