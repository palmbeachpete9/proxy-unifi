#!/usr/bin/env python3
"""
mksingbox.py - Build a sing-box config for the UniFi WireGuard bridge.

Used for SS2022, Shadowsocks with a supported SIP003 plugin handled in-process
(obfs-local / v2ray-plugin), Hysteria2 and TUIC.

Topology mirrors the xray path: a WireGuard *server* endpoint terminates the
UniFi gateway's WireGuard VPN Client (same keys/port), and everything it
receives is routed to the proxy outbound.

Stdlib only (Python 3.9+).
"""

import argparse
import json
import re
import sys
from urllib.parse import unquote

from proxylib import (die, flat_query, qg, safe_urlsplit, host_port, safe_port,
                      split_port_list, valid_host, reject_unknown_query, shadowsocks_credentials,
                      add_secret_file_arguments, load_generator_inputs,
                      handle_common_generator_modes, shadowsocks_engine)


_TLS_QUERY = {"sni", "peer", "alpn", "insecure", "allowInsecure",
              "allow_insecure", "fp", "fingerprint"}
# TCP Fast Open. Hysteria2 and TUIC run over QUIC (UDP), where it means nothing,
# so their links may carry it and it is not used.
_TFO_QUERY = {"tfo", "fastopen"}


def _bool_value(value, label):
    if value in (None, ""):
        return None
    lowered = str(value).lower()
    if lowered in ("1", "true", "yes"):
        return True
    if lowered in ("0", "false", "no"):
        return False
    die("%s must be true/false or 1/0" % label)


def _tls(sni, q, default_alpn=None):
    tls = {"enabled": True, "server_name": sni}
    alpn = qg(q, "alpn")
    if alpn:
        tls["alpn"] = [a for a in alpn.split(",") if a]
    elif default_alpn:
        tls["alpn"] = default_alpn
    if _bool_value(qg(q, "insecure", "allowInsecure", "allow_insecure"),
                   "TLS insecure option"):
        die("TLS insecure verification is not supported")
    # fp/fingerprint (uTLS) is not set: these protocols use QUIC, and sing-box
    # refuses uTLS there only when a connection opens ("unsupported usage for
    # uTLS"), leaving a tunnel that starts but carries nothing.
    return tls


def _port_ranges(spec):
    """'443,20000-30000' -> ['443:443', '20000:30000'] (sing-box server_ports)."""
    ranges = []
    for part in spec.split(","):
        low, _, high = part.strip().partition("-")
        low, high = safe_port(low), safe_port(high or low)
        if low > high:
            die("hysteria2 port range %d-%d is reversed" % (low, high))
        ranges.append("%d:%d" % (low, high))
    if len(ranges) > 16:
        die("hysteria2 lists too many port ranges")
    return ranges


def _whole_number(value, label, low, high, unit=""):
    """'100', '100mbps' or '30s' -> 100 / 30, within [low, high]."""
    match = re.fullmatch(r"(\d{1,7})\s*" + re.escape(unit), value.strip(), re.IGNORECASE) \
        or re.fullmatch(r"(\d{1,7})", value.strip())
    if not match or not low <= int(match.group(1)) <= high:
        die("%s must be a whole number %d-%d" % (label, low, high))
    return int(match.group(1))


def plugin_alias(name):
    if name in ("simple-obfs", "obfs-local"):
        return "obfs-local"
    return name


# --------------------------------------------------------------------------
# Per-protocol outbound builders -> (outbound dict, host, port)
# --------------------------------------------------------------------------
def parse_ss(link):
    u, method, password, host, port = shadowsocks_credentials(link)
    query = flat_query(u)
    reject_unknown_query(query, {"plugin", "uot"} | _TFO_QUERY)
    raw = qg(query, "plugin")
    name = ""
    opts = ""
    if raw:
        # flat_query already decoded the URI query once. Remaining percent
        # sequences belong to the plugin options (for example a WS path).
        name, opts = (raw.split(";", 1) + [""])[:2]
    engine, reason, _variant = shadowsocks_engine(method, password, name)
    if engine != "singbox":
        if reason:
            die(reason)
        die("plain legacy Shadowsocks links are handled by xray-core")

    out = {"type": "shadowsocks", "tag": "proxy", "server": host,
           "server_port": port, "method": method, "password": password}
    if name:
        out["plugin"] = plugin_alias(name)
        out["plugin_opts"] = opts
    if _bool_value(qg(query, "tfo", "fastopen"), "TCP Fast Open option"):
        out["tcp_fast_open"] = True
    if _bool_value(qg(query, "uot"), "Shadowsocks uot option"):
        out["udp_over_tcp"] = True
    return out, host, port


def parse_hysteria2(link):
    u, listed_ports = split_port_list(safe_urlsplit(link))
    host, port = host_port(u)
    q = flat_query(u)
    if listed_ports and qg(q, "mport", "ports"):
        die("hysteria2 lists its hopping ports twice")
    hop_ports = listed_ports or qg(q, "mport", "ports")
    hop_ranges = _port_ranges(hop_ports) if hop_ports else []
    if port is None:                     # hysteria2's default, or the first hopping port
        port = int(hop_ranges[0].split(":")[0]) if listed_ports else 443
    host = valid_host(host)
    port = safe_port(port)
    auth = unquote(u.username or "")
    if u.password:                       # hysteria2://user:pass@ -> password is after ':'
        auth = auth + ":" + unquote(u.password) if auth else unquote(u.password)
    reject_unknown_query(q, _TLS_QUERY | _TFO_QUERY | {
        "obfs", "obfs-password", "obfs_password", "pinSHA256", "pinsha256",
        "mport", "ports", "hop-interval", "hop_interval", "upmbps", "downmbps"})
    _bool_value(qg(q, "tfo", "fastopen"), "TCP Fast Open option")
    sni = qg(q, "sni", "peer") or host
    tls = _tls(sni, q, default_alpn=["h3"])
    # pinSHA256 is a hex *certificate* fingerprint; sing-box only offers a base64
    # *public-key* pin (a different value), so we cannot honor it faithfully.
    # Reject rather than silently drop the requested pinning (security-relevant).
    if qg(q, "pinSHA256", "pinsha256"):
        die("hysteria2 'pinSHA256' certificate pinning is not supported")
    out = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": port,
           "password": auth, "tls": tls}
    # Port hopping: the client moves between these server ports.
    if hop_ranges:
        out["server_ports"] = hop_ranges
    hop = qg(q, "hop-interval", "hop_interval")
    if hop:
        if not hop_ports:
            die("hysteria2 hop interval needs port hopping (mport)")
        out["hop_interval"] = "%ds" % _whole_number(hop, "hysteria2 hop interval", 5, 3600, "s")
    for name, field in (("upmbps", "up_mbps"), ("downmbps", "down_mbps")):
        if qg(q, name):
            out[field] = _whole_number(qg(q, name), "hysteria2 " + name, 1, 100000, "mbps")
    obfs_pw = qg(q, "obfs-password", "obfs_password")
    obfs_type = qg(q, "obfs")
    if obfs_type.lower() == "none" and not obfs_pw:
        obfs_type = ""
    if bool(obfs_type) != bool(obfs_pw):
        die("hysteria2 obfs requires both type and password")
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
    host = valid_host(host)
    port = safe_port(port)
    q = flat_query(u)
    reject_unknown_query(q, _TLS_QUERY | _TFO_QUERY | {
        "congestion_control", "congestion", "udp_relay_mode", "udp_over_stream",
        "zero_rtt_handshake", "reduce_rtt", "heartbeat", "network", "disable_sni",
    })
    _bool_value(qg(q, "tfo", "fastopen"), "TCP Fast Open option")
    sni = qg(q, "sni", "peer") or host
    out = {"type": "tuic", "tag": "proxy", "server": host, "server_port": port,
           "uuid": uuid, "password": password, "tls": _tls(sni, q, default_alpn=["h3"])}
    if _bool_value(qg(q, "disable_sni"), "tuic disable_sni"):
        out["tls"]["disable_sni"] = True
    cc = qg(q, "congestion_control", "congestion")
    if cc:
        out["congestion_control"] = cc
    udp_over_stream = _bool_value(qg(q, "udp_over_stream"), "tuic udp_over_stream")
    udp_relay_mode = qg(q, "udp_relay_mode")
    if udp_over_stream is True:
        if udp_relay_mode:
            die("tuic udp_over_stream conflicts with udp_relay_mode")
        out["udp_over_stream"] = True
    elif udp_relay_mode:
        out["udp_relay_mode"] = udp_relay_mode
    zero_rtt = _bool_value(qg(q, "zero_rtt_handshake", "reduce_rtt"),
                           "tuic zero_rtt_handshake")
    if zero_rtt is True:
        out["zero_rtt_handshake"] = True
    hb = qg(q, "heartbeat")
    if hb:
        out["heartbeat"] = hb
    network = qg(q, "network")
    if network:
        if network not in ("tcp", "udp"):
            die("tuic network must be 'tcp' or 'udp'")
        out["network"] = network
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
    die("unsupported link for sing-box (expected SS2022/SS plugin, hysteria2, or tuic)")


def build_test_config(args):
    """Throwaway config: SOCKS inbound on loopback -> the proxy outbound (for `ping`)."""
    outbound, _, _ = parse_link(args.link)
    return {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "socks", "tag": "socks-in", "listen": "127.0.0.1",
            "listen_port": args.socks_port,
        }],
        "outbounds": [outbound],
        "route": {
            "rules": [{"inbound": ["socks-in"], "outbound": "proxy"}],
            "final": "proxy",
        },
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
    ap = argparse.ArgumentParser(
        description="Build sing-box config for the UniFi WireGuard bridge")
    ap.add_argument("--link", default="",
                    help="proxy share link (SS2022/SS plugin, hysteria2://, tuic://)")
    ap.add_argument("--port", type=int, default=0, help="UDP port for the WireGuard endpoint")
    ap.add_argument("--secret-key", default="", help="local WireGuard private key, base64")
    ap.add_argument("--peer-pubkey", default="", help="UniFi WireGuard public key, base64")
    ap.add_argument("--address", default="10.7.0.1/32")
    ap.add_argument("--peer-allowed", default="0.0.0.0/0,::/0")
    ap.add_argument("--mtu", type=int, default=1340)
    ap.add_argument("--loglevel", default="warn")
    ap.add_argument("--print-server", action="store_true", help="print 'host<TAB>port' and exit")
    ap.add_argument("--socks-port", type=int, default=0,
                    help="emit a SOCKS test config on this port instead")
    add_secret_file_arguments(ap)
    args = ap.parse_args()

    # Secrets via a mode-600 file instead of argv (process-list safety + no ARG_MAX).
    load_generator_inputs(args)
    if handle_common_generator_modes(args, parse_link, build_test_config):
        return

    json.dump(build_config(args), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
