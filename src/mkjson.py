#!/usr/bin/env python3
"""
mkjson.py - support importing a full Xray JSON *profile* (balancer / auto-select
pool) as a proxy-unifi connection, using Xray's multi-file (-confdir) merge.

A provider profile contains several outbounds plus routing.balancers /
observatory / burstObservatory. proxy-unifi cannot represent that as a single
share link, so instead of rewriting it we:

  1. keep the provider JSON verbatim as 01-provider.json, and
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
import json
import sys


def die(msg):
    sys.stderr.write("mkjson: error: %s\n" % msg)
    sys.exit(2)


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        die("could not read profile: %s" % e)


def _primary_inbound(cfg):
    """The provider's local entry inbound that user traffic enters through.
    Prefer a socks inbound, else the first inbound. Returns (index, inbound)."""
    ibs = cfg.get("inbounds")
    if not isinstance(ibs, list) or not ibs:
        die("profile has no inbounds (not a runnable client profile)")
    socks = [(i, b) for i, b in enumerate(ibs)
             if isinstance(b, dict) and b.get("protocol") == "socks"]
    if socks:
        return socks[0]
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
    bal = bals[0]
    if not isinstance(bal, dict):
        return 0, "", ""
    tag = str(bal.get("tag", "") or "")
    strat = ""
    st = bal.get("strategy")
    if isinstance(st, dict):
        strat = str(st.get("type", "") or "")
    # count outbounds the selector matches (prefix match, like Xray)
    sels = bal.get("selector") or []
    outs = [str(o.get("tag", "")) for o in cfg.get("outbounds", [])
            if isinstance(o, dict)]
    members = sum(1 for o in outs if any(o.startswith(s) for s in sels))
    return members, strat, tag


def validate_profile(cfg):
    """Ensure the profile is something we can host. Die with a precise reason if
    not. Returns the primary-inbound (index, inbound)."""
    if not isinstance(cfg, dict):
        die("profile is not a JSON object")
    outs = cfg.get("outbounds")
    if not isinstance(outs, list) or not outs:
        die("profile has no outbounds")
    idx, ib = _primary_inbound(cfg)
    # routing that depends on the source entry-point identity can't be reproduced
    # by a WireGuard inbound; reject those rather than silently changing behavior.
    if isinstance(ib, dict):
        st = ib.get("settings", {})
        if isinstance(st, dict) and st.get("accounts"):
            die("profile inbound requires SOCKS authentication, which a WireGuard "
                "inbound cannot reproduce; not supported")
    routing = cfg.get("routing", {})
    rules = routing.get("rules", []) if isinstance(routing, dict) else []
    for r in rules:
        if not isinstance(r, dict):
            continue
        if r.get("user") or r.get("source") or r.get("sourcePort"):
            die("profile routing depends on source/user identity, which a "
                "WireGuard entry cannot reproduce; not supported")
    return idx, ib


def sanitize_provider(cfg):
    """Remove platform-specific fields that break on UniFi. Returns the cleaned
    config (a copy of the provider's, inbounds left as-is for the overlay to
    replace by tag)."""
    out = json.loads(json.dumps(cfg))   # deep copy
    log = out.get("log")
    if isinstance(log, dict):
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
        "listen": "127.0.0.1",
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
                "keepAlive": 25,
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
    return {"inbounds": [inbound]}


def cmd_overlay(args):
    cfg = _load(args.profile)
    _, ib = validate_profile(cfg)
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
    members, strat, btag = _balancer_info(cfg)
    sys.stdout.write("ok\ttag=%s\tmembers=%s\tstrategy=%s\n"
                     % (primary_tag, members, strat or "-"))


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
    o.add_argument("--secret-key-file", required=True)
    o.add_argument("--peer-pubkey-file", required=True)
    o.add_argument("--address", default="10.7.0.1/32")
    o.add_argument("--mtu", type=int, default=1340)
    o.add_argument("--loglevel", default="warning")
    o.set_defaults(fn=cmd_overlay)

    f = sub.add_parser("info")
    f.add_argument("--profile", required=True)
    f.set_defaults(fn=cmd_info)

    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        sys.exit(2)
    args.fn(args)


if __name__ == "__main__":
    main()
