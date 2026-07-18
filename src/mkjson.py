#!/usr/bin/env python3
"""
mkjson.py - support importing a full Xray JSON *profile* (balancer / auto-select
pool) as a proxy-unifi connection, using Xray's multi-file (-confdir) merge.

A provider profile contains several outbounds plus routing.balancers /
observatory / burstObservatory. proxy-unifi cannot represent that as a single
share link, so instead of rewriting its routing semantics we:

  1. validate and sanitize the provider JSON as 01-provider.json, and
  2. generate a small 99-overlay.json that swaps the provider's local entry
     inbound for the proxy-unifi WireGuard inbound (re-using the same inbound
     tag + sniffing, so the provider's routing/balancer rules still apply).

Xray then runs `xray run -confdir <dir>`: the later file replaces the inbound
with the matching tag, and every provider outbound / balancer / observatory /
fallbackTag stays intact.

This module is the *overlay + sanitizer*: it reads the provider JSON, validates
it is a usable pool we can host, removes platform-specific fields that would
break on UniFi (absolute log paths, etc.), and emits the overlay.

Stdlib only (Python 3.7+).

Subcommands:
  overlay   --profile P.json --out-overlay O.json --out-provider Q.json
            --port N --secret-key-file F --peer-pubkey-file F
            [--address A] [--mtu N] [--loglevel L]
                 -> write sanitized provider + WG overlay; print a one-line summary
  info      --profile P.json
                 -> print 'members<TAB>strategy<TAB>tag<TAB>label' for catalog use
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from urllib.parse import urlsplit

from proxylib import (valid_host, safe_port, xray_outbound_servers,
                      is_non_public_host as _is_non_public,
                      validate_xhttp_download_settings, nested_too_deep,
                      dispatch_subcommand)


MAX_PROFILE_BYTES = 2000000
MAX_DEPTH = 64
MAX_OUTBOUNDS = 256
MAX_BALANCERS = 64
MIN_PROBE_SECONDS = 5.0
_FORBIDDEN_KEYS = {"certificateFile", "keyFile", "masterKeyLog",
                   "socketPath", "unixSocket", "unixSocketPath"}
_PATHLIKE_KEY = re.compile(
    r"(?:File|FilePath|SocketPath|KeyLog)$|(?:^|_)(?:file|file_path|socket_path|key_log)$")


def die(msg):
    sys.stderr.write("mkjson: error: %s\n" % msg)
    sys.exit(2)


def _load(path):
    try:
        if os.path.getsize(path) > MAX_PROFILE_BYTES:
            die("profile is too large")
        with open(path, "r", encoding="utf-8") as fh:
            value = json.load(fh)
    except Exception as e:
        die("could not read profile: %s" % e)
    if nested_too_deep(value, MAX_DEPTH):
        die("profile nesting is too deep")
    return value


def _safe_text(value, label, maximum=256):
    if not isinstance(value, str) or len(value) > maximum:
        die("%s must be a short string" % label)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
        die("%s contains control characters" % label)
    return value


def _duration_seconds(value):
    if not isinstance(value, str):
        return None
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$", value)
    if not match:
        return None
    number = float(match.group(1))
    return number * {"ms": .001, "s": 1, "m": 60, "h": 3600}[match.group(2)]


def _validate_remote_url(value, label, schemes=("http", "https")):
    if not isinstance(value, str) or len(value) > 2048:
        die("%s must be a URL string" % label)
    try:
        parsed = urlsplit(value)
    except ValueError:
        die("%s is malformed" % label)
    if parsed.scheme not in schemes or not parsed.hostname:
        die("%s uses an unsupported or hostless URL scheme" % label)
    if _is_non_public(parsed.hostname):
        die("%s targets a non-public address" % label)


def _validate_untrusted_tree(value, path="profile"):
    if isinstance(value, dict):
        if path.endswith(".downloadSettings"):
            validate_xhttp_download_settings(value)
        for key, child in value.items():
            if not isinstance(key, str):
                die("%s has a non-string key" % path)
            if key in _FORBIDDEN_KEYS and child not in (None, "", []):
                die("unsafe local file/device field is not allowed: %s.%s" % (path, key))
            if _PATHLIKE_KEY.search(key) and key not in _FORBIDDEN_KEYS \
                    and child not in (None, "", []):
                die("unknown path-bearing field is not allowed: %s.%s" % (path, key))
            if key in ("unixSettings", "dsSettings") and child not in (None, {}, ""):
                die("Unix-domain socket transports are not allowed in provider profiles")
            _validate_untrusted_tree(child, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_untrusted_tree(child, "%s[%d]" % (path, index))
    elif isinstance(value, str):
        if value.lower().startswith("ext:") and ("routing" in path or "domain" in path.lower()):
            die("external file-backed geodata references are not allowed")


def _validate_tls_pin_destination(outbound, targets):
    """Reject the certificate-pin shape affected by GHSA-5wf9-h793-w73c.

    The core downloader enforces a patched Xray version too. This check keeps a
    dangerous provider profile from becoming active if an administrator restores
    an older local binary manually.
    """
    stream = outbound.get("streamSettings")
    if not isinstance(stream, dict) or stream.get("network") not in ("grpc", "hysteria"):
        return
    tls = stream.get("tlsSettings")
    if not isinstance(tls, dict) or not tls.get("pinnedPeerCertSha256"):
        return
    server_name = tls.get("serverName")
    if isinstance(server_name, str) and server_name:
        return
    for host, _port in targets:
        try:
            ipaddress.ip_address(str(host).strip("[]"))
        except ValueError:
            continue
        die("provider uses certificate pinning with an IP-based %s target but no "
            "TLS serverName; this is unsafe on older Xray cores" % stream["network"])


def _primary_inbound(cfg):
    """The provider's local entry inbound that user traffic enters through.
    Prefer a socks inbound, else the first inbound. Returns (index, inbound)."""
    ibs = cfg.get("inbounds")
    if not isinstance(ibs, list) or not ibs:
        die("profile has no inbounds (not a runnable client profile)")
    for index, inbound in enumerate(ibs):
        if isinstance(inbound, dict) and inbound.get("protocol") == "socks":
            return index, inbound
    if not isinstance(ibs[0], dict):
        die("profile's primary inbound is malformed")
    return 0, ibs[0]


def _balancer_info(cfg):
    """(member_count, strategy_type, balancer_tag) for a balancer profile, or
    (0, '', '') if there is no balancer (a plain multi-outbound profile)."""
    routing = cfg.get("routing")
    if not isinstance(routing, dict):
        return 0, "", ""
    bals = routing.get("balancers")
    if not isinstance(bals, list) or not bals:
        return 0, "", ""
    outs = [str(o.get("tag", "")) for o in cfg.get("outbounds", [])
            if isinstance(o, dict)]
    members = 0
    strategies = []
    tags = []
    for bal in bals:
        if not isinstance(bal, dict):
            continue
        tag = str(bal.get("tag", "") or "")
        if tag:
            tags.append(tag)
        st = bal.get("strategy")
        if isinstance(st, dict) and st.get("type"):
            strategies.append(str(st["type"]))
        sels = bal.get("selector") or []
        if not isinstance(sels, list) or not all(isinstance(s, str) for s in sels):
            continue
        members += sum(1 for out in outs if any(out.startswith(s) for s in sels))
    return members, ",".join(dict.fromkeys(strategies)), ",".join(tags)


def validate_profile(cfg):
    """Ensure the profile is something we can host. Die with a precise reason if
    not. Returns the primary-inbound (index, inbound)."""
    if not isinstance(cfg, dict):
        die("profile is not a JSON object")
    outs = cfg.get("outbounds")
    if not isinstance(outs, list) or not outs:
        die("profile has no outbounds")
    if len(outs) > MAX_OUTBOUNDS:
        die("profile has too many outbounds (maximum %d)" % MAX_OUTBOUNDS)
    if not all(isinstance(outbound, dict) for outbound in outs):
        die("profile has a malformed outbound")
    _validate_untrusted_tree(cfg)
    idx, ib = _primary_inbound(cfg)
    # routing that depends on the source entry-point identity can't be reproduced
    # by a WireGuard inbound; reject those rather than silently changing behavior.
    if isinstance(ib, dict):
        st = ib.get("settings", {})
        if isinstance(st, dict) and st.get("accounts"):
            die("profile inbound requires SOCKS authentication, which a WireGuard "
                "inbound cannot reproduce; not supported")
    for inbound in cfg.get("inbounds", []):
        if not isinstance(inbound, dict):
            die("profile has a malformed inbound")
        tag = inbound.get("tag")
        if tag not in (None, ""):
            _safe_text(tag, "inbound tag")
    primary_tag = str(ib.get("tag", "") or "socks")
    routing = cfg.get("routing", {})
    if routing is not None and not isinstance(routing, dict):
        die("profile routing must be an object")
    routing = routing or {}
    rules = routing.get("rules", [])
    if not isinstance(rules, list):
        die("profile routing.rules must be an array")
    for r in rules:
        if not isinstance(r, dict):
            die("profile has a malformed routing rule")
        if r.get("user") or r.get("source") or r.get("sourcePort"):
            die("profile routing depends on source/user identity, which a "
                "WireGuard entry cannot reproduce; not supported")
        refs = r.get("inboundTag")
        if refs is not None:
            refs = [refs] if isinstance(refs, str) else refs
            if not isinstance(refs, list) or not all(isinstance(tag, str) for tag in refs):
                die("routing inboundTag must be a string or array of strings")
            if any(tag != primary_tag for tag in refs):
                die("profile routing references an inbound removed by the WireGuard overlay")

    balancers = routing.get("balancers", [])
    if balancers is not None and not isinstance(balancers, list):
        die("profile routing.balancers must be an array")
    if len(balancers or []) > MAX_BALANCERS:
        die("profile has too many balancers")
    outbound_tag_list = [str(outbound.get("tag", "")) for outbound in outs
                         if outbound.get("tag") not in (None, "")]
    if len(outbound_tag_list) != len(set(outbound_tag_list)):
        die("profile has duplicate outbound tags")
    outbound_tags = set(outbound_tag_list)
    balancer_tags = set()
    for balancer in balancers or []:
        if not isinstance(balancer, dict):
            die("profile has a malformed balancer")
        selectors = balancer.get("selector", [])
        if not isinstance(selectors, list) or not all(isinstance(x, str) for x in selectors):
            die("balancer selector must be an array of strings")
        for selector in selectors:
            _safe_text(selector, "balancer selector")
        if balancer.get("tag"):
            tag = _safe_text(balancer["tag"], "balancer tag")
            if tag in balancer_tags:
                die("profile has duplicate balancer tags")
            balancer_tags.add(tag)
        strategy = balancer.get("strategy")
        if strategy is not None and not isinstance(strategy, dict):
            die("balancer strategy must be an object")
        if isinstance(strategy, dict) and strategy.get("type"):
            _safe_text(strategy["type"], "balancer strategy")
        fallback = balancer.get("fallbackTag")
        if fallback and fallback not in outbound_tags:
            die("balancer fallbackTag references a missing outbound")

    for rule in rules:
        outbound_ref = rule.get("outboundTag")
        balancer_ref = rule.get("balancerTag")
        if outbound_ref is not None:
            if not isinstance(outbound_ref, str) or outbound_ref not in outbound_tags:
                die("routing rule references a missing outbound")
        if balancer_ref is not None:
            if not isinstance(balancer_ref, str) or balancer_ref not in balancer_tags:
                die("routing rule references a missing balancer")
        if outbound_ref is not None and balancer_ref is not None:
            die("routing rule cannot select both an outbound and a balancer")

    for outbound in outs:
        protocol = outbound.get("protocol")
        if not isinstance(protocol, str) or not protocol:
            die("profile outbound is missing a protocol")
        _safe_text(protocol, "outbound protocol", 64)
        tag = outbound.get("tag")
        if tag not in (None, ""):
            _safe_text(tag, "outbound tag")
        targets = xray_outbound_servers(outbound)
        local_protocols = {"blackhole", "freedom", "dns", "loopback"}
        if protocol not in local_protocols and not targets:
            die("outbound protocol '%s' uses an unsupported destination schema" % protocol)
        for host, port in targets:
            host = valid_host(host)
            if _is_non_public(host):
                die("provider outbound targets a non-public address: %s" % host)
            if port not in (None, ""):
                safe_port(port)
        _validate_tls_pin_destination(outbound, targets)
        if outbound.get("protocol") == "freedom":
            settings = outbound.get("settings")
            redirect = settings.get("redirect") if isinstance(settings, dict) else None
            if redirect:
                if not isinstance(redirect, str) or len(redirect) > 512:
                    die("freedom redirect is malformed")
                try:
                    redirect_host = urlsplit("//" + redirect).hostname
                except ValueError:
                    die("freedom redirect is malformed")
                if redirect_host and _is_non_public(redirect_host):
                    die("freedom redirect targets a non-public address")

    dns = cfg.get("dns")
    if dns is not None:
        if not isinstance(dns, dict):
            die("profile dns must be an object")
        servers = dns.get("servers", [])
        if not isinstance(servers, list) or len(servers) > 64:
            die("profile dns.servers must be a bounded array")
        for server in servers:
            address = server.get("address") if isinstance(server, dict) else server
            if not isinstance(address, str) or len(address) > 2048:
                die("profile contains a malformed DNS server")
            candidate = address
            if "://" in candidate:
                _validate_remote_url(candidate, "DNS server",
                                     ("tcp", "tcp+local", "https", "https+local",
                                      "quic+local", "h2c"))
            else:
                if candidate == "fakedns":
                    continue
                try:
                    host = urlsplit("//" + candidate).hostname
                except ValueError:
                    die("profile contains a malformed DNS server")
                if not host or _is_non_public(host):
                    die("profile DNS targets a non-public address")
        hosts = dns.get("hosts", {})
        if not isinstance(hosts, dict) or len(hosts) > 1024:
            die("profile dns.hosts must be a bounded object")
        for mapped in hosts.values():
            mapped_values = mapped if isinstance(mapped, list) else [mapped]
            if not all(isinstance(item, str) for item in mapped_values):
                die("profile contains a malformed DNS hosts mapping")
            for item in mapped_values:
                candidate = item[len("domain:"):] if item.startswith("domain:") else item
                if _is_non_public(candidate):
                    die("profile DNS hosts mapping targets a non-public address")

    for key in ("observatory", "burstObservatory"):
        observatory = cfg.get(key)
        if observatory is None:
            continue
        if not isinstance(observatory, dict):
            die("%s must be an object" % key)
        selectors = observatory.get("subjectSelector", [])
        if not isinstance(selectors, list) or len(selectors) > MAX_OUTBOUNDS \
                or not all(isinstance(x, str) for x in selectors):
            die("%s subjectSelector is malformed or too large" % key)
        for selector in selectors:
            _safe_text(selector, "%s subjectSelector" % key)
        ping = observatory.get("probeURL", observatory.get("probeUrl"))
        config = observatory.get("pingConfig")
        if isinstance(config, dict):
            ping = config.get("destination", ping)
            interval = config.get("interval")
            if interval is not None:
                seconds = _duration_seconds(interval)
                if seconds is None or seconds < MIN_PROBE_SECONDS:
                    die("%s probe interval must be at least 5s" % key)
            timeout = config.get("timeout")
            if timeout is not None:
                timeout_seconds = _duration_seconds(timeout)
                if timeout_seconds is None or not 0.1 <= timeout_seconds <= 60:
                    die("%s probe timeout must be between 100ms and 60s" % key)
            sampling = config.get("sampling")
            if sampling is not None and (not isinstance(sampling, int) or not 1 <= sampling <= 100):
                die("%s probe sampling must be 1-100" % key)
        elif config is not None:
            die("%s pingConfig must be an object" % key)
        if ping:
            _validate_remote_url(ping, "%s probe destination" % key)
        probe_interval = observatory.get("probeInterval")
        if probe_interval is not None:
            seconds = _duration_seconds(probe_interval)
            if seconds is None or seconds < MIN_PROBE_SECONDS:
                die("%s probe interval must be at least 5s" % key)
    return idx, ib


def sanitize_provider(cfg):
    """Remove platform-specific fields that break on UniFi. Returns the cleaned
    config with provider inbounds removed; the overlay supplies the sole inbound."""
    # Only top-level keys and the log object are changed, so a shallow copy
    # avoids duplicating every outbound/balancer in a potentially large profile.
    out = dict(cfg)
    # SECURITY: the provider's local entry inbound is replaced by our loopback
    # WireGuard inbound (the overlay supplies it, carrying the primary tag). Drop
    # ALL provider inbounds so a hostile/compromised profile cannot smuggle extra
    # listeners -- an open socks/http relay or a dokodemo-door to the LAN /
    # cloud-metadata -- that the by-tag overlay merge would otherwise leave running
    # as root. Routing rules key off balancerTag/outboundTag, not the dropped
    # inbounds, so balancer/observatory resolution is unaffected.
    out.pop("inbounds", None)
    # Strip service blocks that can open control surfaces or outbound bridges even
    # without an inbound (api/stats/metrics/policy control planes; reverse tunnels).
    for k in ("api", "stats", "metrics", "policy", "reverse", "geodata"):
        out.pop(k, None)
    log = out.get("log")
    if isinstance(log, dict):
        log = dict(log)
        out["log"] = log
        # absolute access/error log paths from a desktop export won't exist on
        # UniFi and make Xray fail; drop them, keep loglevel.
        for k in ("access", "error"):
            if k in log:
                del log[k]
        if "dnsLog" in log:
            del log["dnsLog"]
    return out


def build_overlay(args, primary_tag, sniffing):
    try:
        with open(args.secret_key_file, "r", encoding="utf-8") as fh:
            secret = fh.read().strip()
        with open(args.peer_pubkey_file, "r", encoding="utf-8") as fh:
            pubkey = fh.read().strip()
    except Exception as e:
        die("could not read key file: %s" % e)
    inbound = {
        "tag": primary_tag,
        "listen": args.listen,
        "port": args.port,
        "protocol": "wireguard",
        "settings": {
            "secretKey": secret,
            "address": [x for x in args.address.split(",") if x],
            "mtu": args.mtu,
            "noKernelTun": True,
            "peers": [{
                "publicKey": pubkey,
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "keepAlive": args.keepalive,
            }],
        },
    }
    # reuse the provider inbound's sniffing so destination-based routing keeps
    # working; fall back to a sensible default.
    if isinstance(sniffing, dict):
        inbound["sniffing"] = sniffing
    else:
        inbound["sniffing"] = {"enabled": True,
                               "destOverride": ["http", "tls", "quic"],
                               "routeOnly": True}
    return {"log": {"loglevel": args.loglevel}, "inbounds": [inbound]}


def cmd_overlay(args):
    cfg = _load(args.profile)
    _, ib = validate_profile(cfg)
    valid_host(args.listen)
    safe_port(args.port)
    if not 576 <= args.mtu <= 9000:
        die("WireGuard MTU is out of range")
    if not 0 <= args.keepalive <= 65535:
        die("WireGuard keepalive is out of range")
    if args.loglevel not in ("debug", "info", "warning", "error", "none"):
        die("invalid loglevel")
    primary_tag = str(ib.get("tag", "") or "socks") if isinstance(ib, dict) else "socks"
    sniffing = ib.get("sniffing") if isinstance(ib, dict) else None
    provider = sanitize_provider(cfg)
    overlay = build_overlay(args, primary_tag, sniffing)
    try:
        with open(args.out_provider, "w", encoding="utf-8") as fh:
            json.dump(provider, fh, ensure_ascii=False)
        with open(args.out_overlay, "w", encoding="utf-8") as fh:
            json.dump(overlay, fh, ensure_ascii=False)
    except Exception as e:
        die("could not write output: %s" % e)
    members, strat, _ = _balancer_info(cfg)
    sys.stdout.write("ok\ttag=%s\tmembers=%s\tstrategy=%s\n"
                     % (primary_tag, members, strat or "-"))


def _outbound_server(ob):
    """Best-effort (host, port) of a proxy outbound (vnext/servers shapes)."""
    if not isinstance(ob, dict):
        return (None, None)
    if ob.get("protocol") in ("blackhole", "freedom", "dns", "loopback"):
        return (None, None)
    for host, port in xray_outbound_servers(ob):
        host = valid_host(host)
        if port not in (None, ""):
            port = safe_port(port)
            return (host, str(port))
    return (None, None)


def cmd_firstserver(args):
    """Print 'host\\tport' of the first reachable proxy server in the profile,
    so the shell's TCP/ICMP ping has a concrete host to probe in pool mode."""
    cfg = _load(args.profile)
    for ob in cfg.get("outbounds", []):
        host, port = _outbound_server(ob)
        if host:
            sys.stdout.write("%s\t%s\n" % (host, port))
            return
    sys.exit(1)


def cmd_socksconfig(args):
    """Emit a complete runnable Xray config that exposes the profile's
    balancer/outbounds through a local SOCKS inbound -- used by the ping test
    so 'via proxy' latency can be measured for a pool the same way as a link."""
    cfg = _load(args.profile)
    _, ib = validate_profile(cfg)
    primary_tag = str(ib.get("tag", "") or "socks") if isinstance(ib, dict) else "socks"
    sniffing = ib.get("sniffing") if isinstance(ib, dict) else None
    out = sanitize_provider(cfg)
    inbound = {"tag": primary_tag, "listen": "127.0.0.1", "port": args.socks_port,
               "protocol": "socks", "settings": {"udp": True}}
    if isinstance(sniffing, dict):
        inbound["sniffing"] = sniffing
    out["inbounds"] = [inbound]
    sys.stdout.write(json.dumps(out, ensure_ascii=False))


def cmd_info(args):
    cfg = _load(args.profile)
    validate_profile(cfg)
    members, strat, btag = _balancer_info(cfg)
    label = ""
    if isinstance(cfg.get("remarks"), str):
        label = cfg["remarks"]
    sys.stdout.write("%s\t%s\t%s\t%s\n"
                     % (members, strat or "-", btag or "-", label))


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Xray JSON profile (balancer/pool) overlay builder")
    sub = ap.add_subparsers(dest="cmd")

    o = sub.add_parser("overlay")
    o.add_argument("--profile", required=True)
    o.add_argument("--out-overlay", required=True)
    o.add_argument("--out-provider", required=True)
    o.add_argument("--port", type=int, required=True)
    o.add_argument("--listen", default="127.0.0.1")
    o.add_argument("--secret-key-file", required=True)
    o.add_argument("--peer-pubkey-file", required=True)
    o.add_argument("--address", default="10.7.0.1/32")
    o.add_argument("--mtu", type=int, default=1340)
    o.add_argument("--keepalive", type=int, default=25)
    o.add_argument("--loglevel", default="warning")
    o.set_defaults(fn=cmd_overlay)

    f = sub.add_parser("info")
    f.add_argument("--profile", required=True)
    f.set_defaults(fn=cmd_info)

    s = sub.add_parser("socksconfig")
    s.add_argument("--profile", required=True)
    s.add_argument("--socks-port", type=int, required=True)
    s.set_defaults(fn=cmd_socksconfig)

    fs = sub.add_parser("firstserver")
    fs.add_argument("--profile", required=True)
    fs.set_defaults(fn=cmd_firstserver)

    dispatch_subcommand(ap)


if __name__ == "__main__":
    main()
