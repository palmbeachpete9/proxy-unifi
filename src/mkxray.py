#!/usr/bin/env python3
"""
mkxray.py - Build a complete Xray-core config.json for the UniFi WireGuard bridge.

Topology:
    UniFi WireGuard VPN Client  --(UDP 127.0.0.1:PORT)-->  Xray WireGuard inbound
        --> proxy outbound (parsed from a vless:// / vmess:// / trojan:// / ss:// link)
        --> remote proxy server

It parses a proxy share link into an Xray outbound and emits a full config that
terminates a WireGuard peer (the UniFi gateway) locally and forwards everything
out through that proxy server.

Generic link-parsing helpers (URL split, host/port validation, base64, query,
secret-file loading, Shadowsocks credentials, and die) live in proxylib.py, shared with
mksingbox.py. Stdlib only (Python 3.7+) so it runs on the gateway as shipped.
"""

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import unquote

from proxylib import (die, b64decode_any, flat_query, qg, safe_urlsplit,
                      host_port, safe_port, valid_host, reject_unknown_query,
                      shadowsocks_credentials, add_secret_file_arguments,
                      load_generator_inputs, handle_common_generator_modes,
                      validate_xhttp_download_settings)


_COMMON_QUERY = {
    "type", "net", "security", "sni", "peer", "host", "fp", "fingerprint",
    "alpn", "allowInsecure", "insecure", "ech", "pcs", "vcn", "pqv",
    "pbk", "publicKey", "sid", "shortId", "spx", "spiderX", "headerType",
    "path", "serviceName", "mode", "authority", "extra", "fm", "seed",
    "mtu", "tti", "user_agent", "idle_timeout", "health_check_timeout",
    "permit_without_stream", "initial_windows_size",
    "ed", "eh", "packetEncoding",
}
_LOCAL_FIELD = {"certificateFile", "keyFile", "masterKeyLog", "socketPath",
                "unixSocket", "unixSocketPath"}
_PATHLIKE_KEY = re.compile(
    r"(?:File|FilePath|SocketPath|KeyLog)$|(?:^|_)(?:file|file_path|socket_path|key_log)$")


def _q_int(q, name, minimum=0, maximum=2147483647):
    value = qg(q, name)
    if value == "":
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        die("share-link option '%s' must be an integer" % name)
    if parsed < minimum or parsed > maximum:
        die("share-link option '%s' is out of range" % name)
    return parsed


def _q_bool(q, name):
    value = qg(q, name)
    if value == "":
        return None
    low = value.lower()
    if low in ("1", "true", "yes"):
        return True
    if low in ("0", "false", "no"):
        return False
    die("share-link option '%s' must be true/false or 1/0" % name)


def _validate_json_option(value, path, depth=0):
    if depth > 32:
        die("share-link option '%s' is nested too deeply" % path)
    if isinstance(value, dict):
        if path.endswith(".downloadSettings"):
            validate_xhttp_download_settings(value)
        for key, child in value.items():
            if not isinstance(key, str):
                die("share-link JSON option contains a non-string key")
            if (key in _LOCAL_FIELD or _PATHLIKE_KEY.search(key)) \
                    and child not in (None, "", []):
                die("share-link JSON option contains an unsafe local path field")
            if key in ("unixSettings", "dsSettings") and child not in (None, "", {}):
                die("share-link JSON option requests a Unix-domain socket")
            _validate_json_option(child, "%s.%s" % (path, key), depth + 1)
    elif isinstance(value, list):
        if len(value) > 256:
            die("share-link JSON option contains an oversized array")
        for index, child in enumerate(value):
            _validate_json_option(child, "%s[%d]" % (path, index), depth + 1)


def _q_json(q, name):
    value = qg(q, name)
    if value == "":
        return None
    try:
        parsed = json.loads(value)
    except Exception:
        die("share-link option '%s' is not valid JSON" % name)
    if not isinstance(parsed, dict):
        die("share-link option '%s' must contain a JSON object" % name)
    _validate_json_option(parsed, name)
    return parsed


def _validate_option_relevance(q, security, net):
    """Reject understood fields when they do not apply to this security layer or
    transport. Accepting and then dropping them would make the generated config
    differ silently from the provider's link."""
    tls_only = {"alpn", "allowInsecure", "insecure", "ech", "pcs", "vcn"}
    reality_only = {"pbk", "publicKey", "sid", "shortId", "spx", "spiderX", "pqv"}
    shared_security = {"sni", "peer", "fp", "fingerprint"}
    if security == "tls":
        allowed_security = shared_security | tls_only
    elif security == "reality":
        allowed_security = shared_security | reality_only
    else:
        allowed_security = set()
    for name in shared_security | tls_only | reality_only:
        if q.get(name, "") != "" and name not in allowed_security:
            die("share-link option '%s' does not apply to security '%s'"
                % (name, security or "none"))

    transport_fields = {
        "headerType", "host", "path", "serviceName", "mode", "authority",
        "extra", "seed", "mtu", "tti", "user_agent", "idle_timeout",
        "health_check_timeout", "permit_without_stream", "initial_windows_size",
        "ed", "eh",
    }
    allowed_by_transport = {
        "tcp": {"headerType"},
        "ws": {"host", "path", "ed", "eh"},
        "httpupgrade": {"host", "path", "ed", "eh"},
        "grpc": {"path", "serviceName", "mode", "authority", "user_agent",
                 "idle_timeout", "health_check_timeout", "permit_without_stream",
                 "initial_windows_size"},
        "xhttp": {"host", "path", "mode", "extra"},
        "splithttp": {"host", "path", "mode", "extra"},
        "kcp": {"headerType", "seed", "mtu", "tti"},
    }
    allowed_transport = allowed_by_transport.get(net, set())
    if net == "tcp" and qg(q, "headerType", default="none") == "http":
        allowed_transport = allowed_transport | {"host", "path"}
    for name in transport_fields:
        value = q.get(name, "")
        # Serializers commonly emit headerType=none for transports that do not
        # use packet headers. It is an explicit no-op, not a discarded behavior.
        if name == "headerType" and value == "none":
            continue
        if value != "" and name not in allowed_transport:
            die("share-link option '%s' does not apply to transport '%s'" % (name, net))


def build_stream(q, security, net, host):
    """Build streamSettings shared by VLESS and Trojan.

    Transports removed by current Xray are rejected up front with a clear message
    (legacy HTTP/2, QUIC). mKCP is still supported, but its removed header/seed
    options are rejected. 'allowInsecure' was removed by Xray and has no safe
    equivalent, so a link that requests it is rejected rather than silently made
    secure (which would change the link's intended TLS behavior)."""
    if net in ("http", "h2"):
        die("legacy HTTP/2 (h2) transport was removed by Xray; not supported")
    if net == "quic":
        die("QUIC transport was removed by Xray; not supported")
    _validate_option_relevance(q, security, net)
    stream = {"network": net, "security": security}

    # ---- security layer -------------------------------------------------
    sni = qg(q, "sni", "peer") or host
    fp = qg(q, "fp", "fingerprint")
    alpn = qg(q, "alpn")
    insecure = qg(q, "allowInsecure", "insecure")
    if insecure:
        lowered = insecure.lower()
        if lowered in ("1", "true", "yes"):
            die("'allowInsecure' was removed by Xray and cannot be honored; "
                "this link is not supported (it asks to skip certificate verification)")
        if lowered not in ("0", "false", "no"):
            die("allowInsecure must be true/false or 1/0")
    if security == "tls":
        tls = {"serverName": sni}
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        if qg(q, "ech"):
            tls["echConfigList"] = qg(q, "ech")
        if qg(q, "pcs"):
            tls["pinnedPeerCertSha256"] = qg(q, "pcs")
        if qg(q, "vcn"):
            tls["verifyPeerCertByName"] = qg(q, "vcn")
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": qg(q, "pbk", "publicKey"),
            "shortId": qg(q, "sid", "shortId"),
            "spiderX": qg(q, "spx", "spiderX", default="/"),
        }
        if qg(q, "pqv"):
            reality["mldsa65Verify"] = qg(q, "pqv")
        stream["realitySettings"] = reality
    elif security in ("", "none"):
        stream["security"] = "none"
    else:
        die("unsupported security '%s'" % security)

    # ---- transport layer ------------------------------------------------
    header_type = qg(q, "headerType", default="none")
    host_hdr = qg(q, "host")
    path = qg(q, "path", default="/")

    if net == "tcp":
        if header_type not in ("none", "http"):
            die("unsupported TCP headerType '%s'" % header_type)
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
        early = _q_int(q, "ed", 0, 1048576)
        if early is not None:
            ws["maxEarlyData"] = early
        if qg(q, "eh"):
            ws["earlyDataHeaderName"] = qg(q, "eh")
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        hu = {"path": path or "/"}
        if host_hdr:
            hu["host"] = host_hdr
        early = _q_int(q, "ed", 0, 1048576)
        if early is not None:
            hu["maxEarlyData"] = early
        if qg(q, "eh"):
            hu["earlyDataHeaderName"] = qg(q, "eh")
        stream["httpupgradeSettings"] = hu
    elif net == "grpc":
        grpc = {"serviceName": qg(q, "serviceName", "path", default="")}
        mode = qg(q, "mode")
        if mode not in ("", "gun", "multi"):
            die("gRPC mode '%s' is not supported by the installed Xray config format" % mode)
        if mode:
            grpc["multiMode"] = mode == "multi"
        if "authority" in q:
            grpc["authority"] = q["authority"]
        for qname, cname, maximum in (
                ("user_agent", "user_agent", None),
                ("idle_timeout", "idle_timeout", 86400),
                ("health_check_timeout", "health_check_timeout", 86400),
                ("initial_windows_size", "initial_windows_size", 16777216)):
            if qname in q and q[qname] != "":
                if qname == "user_agent":
                    if len(q[qname]) > 512 or any(ord(ch) < 0x20 or ord(ch) == 0x7f
                                                  for ch in q[qname]):
                        die("gRPC user_agent is too long or contains control characters")
                    grpc[cname] = q[qname]
                else:
                    grpc[cname] = _q_int(q, qname, 0, maximum)
        permit = _q_bool(q, "permit_without_stream")
        if permit is not None:
            grpc["permit_without_stream"] = permit
        stream["grpcSettings"] = grpc
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        xh = {"path": path or "/"}
        if host_hdr:
            xh["host"] = host_hdr
        mode = qg(q, "mode")
        if mode:
            xh["mode"] = mode
        extra = _q_json(q, "extra")
        if extra is not None:
            xh["extra"] = extra
        stream["xhttpSettings"] = xh
    elif net == "kcp":
        # mKCP is still supported, but its header/seed options were removed by Xray.
        if qg(q, "seed"):
            die("mKCP 'seed' was removed by Xray; this link is not supported")
        if header_type not in ("", "none"):
            die("mKCP header obfuscation was removed by Xray; this link is not supported")
        kcp = {}
        mtu = _q_int(q, "mtu", 576, 65535)
        tti = _q_int(q, "tti", 1, 1000)
        if mtu is not None:
            kcp["mtu"] = mtu
        if tti is not None:
            kcp["tti"] = tti
        stream["kcpSettings"] = kcp
    else:
        die("unsupported transport type '%s'" % net)

    finalmask = _q_json(q, "fm")
    if finalmask is not None:
        stream["finalmask"] = finalmask
    return stream


def parse_vless(link):
    u = safe_urlsplit(link)
    uuid = unquote(u.username or "")
    host, port = host_port(u)
    if not uuid:
        die("vless link is missing the UUID")
    if not host or not port:
        die("vless link is missing the server host/port")
    host = valid_host(host)
    port = safe_port(port)
    q = flat_query(u)
    reject_unknown_query(q, _COMMON_QUERY | {"encryption", "flow"})

    user = {"id": uuid, "encryption": qg(q, "encryption", default="none") or "none"}
    flow = qg(q, "flow")
    if flow:
        user["flow"] = flow

    net = qg(q, "type", "net", default="tcp") or "tcp"
    security = qg(q, "security", default="none") or "none"
    stream = build_stream(q, security, net, host)

    settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    packet_encoding = qg(q, "packetEncoding")
    if packet_encoding:
        if packet_encoding not in ("none", "packet", "xudp"):
            die("unsupported packetEncoding '%s'" % packet_encoding)
        settings["packetEncoding"] = packet_encoding
    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": settings,
        "streamSettings": stream,
    }
    return outbound, host, port


def parse_trojan(link):
    u = safe_urlsplit(link)
    password = unquote(u.username or "")
    host, port = host_port(u)
    if not password:
        die("trojan link is missing the password")
    if not host or not port:
        die("trojan link is missing the server host/port")
    host = valid_host(host)
    port = safe_port(port)
    q = flat_query(u)
    reject_unknown_query(q, _COMMON_QUERY | {"flow"})
    if qg(q, "flow"):
        die("Trojan 'flow' was removed by Xray and cannot be honored")

    net = qg(q, "type", "net", default="tcp") or "tcp"
    security = qg(q, "security", default="tls") or "tls"   # trojan implies TLS
    stream = build_stream(q, security, net, host)

    server = {"address": host, "port": port, "password": password}

    outbound = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {"servers": [server]},
        "streamSettings": stream,
    }
    return outbound, host, port


def _ss_plugin_name(parsed):
    query = flat_query(parsed)
    reject_unknown_query(query, {"plugin"})
    raw = qg(query, "plugin")
    if not raw:
        return None
    raw = unquote(raw)
    return raw.split(";", 1)[0] if ";" in raw else raw


def ss_plugin_name(link):
    """Return the SIP003 plugin name for an ss:// link, or None if it has no plugin."""
    return _ss_plugin_name(safe_urlsplit(link))


def parse_ss(link):
    parsed, method, password, host, port = shadowsocks_credentials(link)
    # SIP003-plugin Shadowsocks is handled by sing-box, never by xray.
    if _ss_plugin_name(parsed):
        die("shadowsocks SIP003 plugin links are handled by sing-box, not xray")
    outbound = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{"address": host, "port": port, "method": method, "password": password}]
        },
    }
    return outbound, host, port


def _vmess_outbound(host, port, uid, aid, scy, security, net, q):
    host = valid_host(host)
    port = safe_port(port)
    if not uid:
        die("vmess link is missing the UUID")
    stream = build_stream(q, security, net, host)
    user = {"id": uid, "alterId": aid, "security": scy or "auto"}
    settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    packet_encoding = qg(q, "packetEncoding")
    if packet_encoding:
        if packet_encoding not in ("none", "packet", "xudp"):
            die("unsupported packetEncoding '%s'" % packet_encoding)
        settings["packetEncoding"] = packet_encoding
    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": settings,
        "streamSettings": stream,
    }
    return outbound, host, port


def parse_vmess(link):
    # Two forms: legacy base64(JSON), and the current URI form vmess://uuid@host:port?...
    body = link[len("vmess://"):].split("#", 1)[0]
    if "@" in body:
        # URI form (VMess AEAD), same field set as VLESS.
        u = safe_urlsplit(link)
        uid = unquote(u.username or "")
        host, port = host_port(u)
        if not host or not port:
            die("vmess link is missing the server host/port")
        q = flat_query(u)
        reject_unknown_query(q, _COMMON_QUERY | {"aid", "scy", "encryption"})
        net = qg(q, "type", "net", default="tcp") or "tcp"
        security = qg(q, "security", default="none") or "none"
        try:
            aid = int(qg(q, "aid", default="0") or "0")
        except ValueError:
            die("vmess link has an invalid alterId (aid)")
        scy = qg(q, "scy", "encryption", default="auto") or "auto"
        return _vmess_outbound(host, port, uid, aid, scy, security, net, q)

    # legacy base64(JSON)
    dec = b64decode_any(body)
    if not dec:
        die("could not decode vmess link (expected base64-encoded JSON or URI form)")
    try:
        v = json.loads(dec)
    except Exception:
        die("vmess link is not valid base64-encoded JSON")
    if not isinstance(v, dict):
        die("vmess link JSON must be an object")

    host = str(v.get("add", "") or "")
    uid = str(v.get("id", "") or "")
    if not host:
        die("vmess link is missing the server address")
    tls = str(v.get("tls", "") or "")
    if tls == "reality":
        security = "reality"
    elif tls in ("tls", "xtls"):
        security = "tls"
    else:
        security = "none"
    net = str(v.get("net", "tcp") or "tcp")

    q = {}
    for src, dst in (("sni", "sni"), ("host", "host"), ("fp", "fp"),
                     ("alpn", "alpn"), ("type", "headerType"),
                     ("pbk", "pbk"), ("sid", "sid"), ("spx", "spx")):
        if v.get(src) not in (None, ""):
            q[dst] = str(v[src])
    if v.get("path") not in (None, ""):
        q["path"] = str(v["path"])
        if net == "grpc":
            q["serviceName"] = str(v["path"])   # grpc carries serviceName in "path"
    try:
        aid = int(v.get("aid", 0) or 0)
    except (TypeError, ValueError):
        die("vmess link has an invalid alterId (aid)")
    return _vmess_outbound(host, v.get("port"), uid, aid,
                           str(v.get("scy", "auto") or "auto"), security, net, q)


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
    ap = argparse.ArgumentParser(
        description="Build Xray config for the UniFi WireGuard bridge")
    ap.add_argument("--link", default="",
                    help="proxy share link (vless:// / vmess:// / trojan:// / ss://)")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="UDP port for the WireGuard inbound")
    ap.add_argument("--secret-key", default="", help="Xray (server) WireGuard private key, base64")
    ap.add_argument("--peer-pubkey", default="", help="UniFi (client) WireGuard public key, base64")
    ap.add_argument("--address", default="10.7.0.1/32", help="Xray tunnel interface address(es)")
    ap.add_argument("--peer-allowed", default="0.0.0.0/0,::/0",
                    help="allowedIPs accepted from the UniFi peer")
    ap.add_argument("--mtu", type=int, default=1340)
    ap.add_argument("--keepalive", type=int, default=25)
    ap.add_argument("--dns", default="", help="comma-separated inner DNS servers (optional)")
    ap.add_argument("--loglevel", default="warning")
    ap.add_argument("--socks-port", type=int, default=0,
                    help="emit a SOCKS test config on this port instead")
    ap.add_argument("--print-server", action="store_true",
                    help="print 'host<TAB>port' of the server and exit")
    ap.add_argument("--print-plugin", action="store_true",
                    help="print the SIP003 plugin name for an ss:// link, else nothing")
    add_secret_file_arguments(ap)
    args = ap.parse_args()

    # Secret inputs (proxy link + WireGuard private key) are read from a mode-600
    # file instead of argv to keep them out of the process list, and to avoid the
    # ARG_MAX limit on very long links.
    load_generator_inputs(args)

    if args.print_plugin:
        if args.link.strip().lower().startswith("ss://"):
            name = ss_plugin_name(args.link)
            if name:
                sys.stdout.write("%s\n" % name)
        return

    if handle_common_generator_modes(args, parse_link, build_test_config):
        return

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
