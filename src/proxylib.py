#!/usr/bin/env python3
"""
proxylib.py - shared share-link parsing utilities for proxy-unifi's two config
generators, mkxray.py (Xray) and mksingbox.py (sing-box).

Both generators parse the same family of proxy URIs into an engine-specific
outbound; only the generic plumbing (URL splitting, host/port validation,
base64, query helpers, the secret --input-file loader, the error helper) is the
same, so it lives here instead of being copy-pasted into each.

It is imported, never run directly: each generator is invoked as
`python3 .../mkxray.py`, and Python puts that script's directory on sys.path[0],
so a sibling proxylib.py in the same bin dir is importable with no packaging.

Stdlib only (Python 3.7+).
"""

import base64
import json
import os
import sys
from urllib.parse import urlsplit, parse_qsl


def die(msg):
    """Print 'PROG: error: MSG' to stderr and exit 2. PROG is derived from the
    invoked script name so each generator keeps its own identity in errors."""
    prog = os.path.basename(sys.argv[0]) or "proxy-unifi"
    if prog.endswith(".py"):
        prog = prog[:-3]
    sys.stderr.write("%s: error: %s\n" % (prog, msg))
    sys.exit(2)


def b64_pad(s):
    return s + "=" * (-len(s) % 4)


def b64decode_any(s):
    """Decode url-safe or standard base64, with or without padding; None on failure."""
    s = s.strip()
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(b64_pad(s)).decode("utf-8")
        except Exception:
            pass
    return None


def flat_query(u):
    """Parse a URI query without silently resolving duplicate parameters.

    Xray's share-link proposal explicitly forbids duplicate fields. Choosing the
    first or last value would let different clients interpret a security or
    transport option differently, so reject duplicates here for both engines.
    """
    out = {}
    try:
        pairs = parse_qsl(u.query, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        die("malformed query string in link")
    for key, value in pairs:
        if key in out:
            die("duplicate query parameter '%s'" % key)
        out[key] = value
    return out


def reject_unknown_query(q, allowed):
    """Reject semantic fields the generator does not understand.

    Silently dropping a new share-link field can produce a valid-looking config
    with different security/transport behavior. Callers provide a protocol-
    specific allowlist after parsing all documented aliases.
    """
    unknown = sorted(k for k in q if k not in allowed)
    if unknown:
        die("unsupported query parameter(s): %s" % ", ".join(unknown))


def qg(q, *names, default=""):
    """Value of one alias, rejecting conflicting non-empty aliases."""
    values = [(n, q[n]) for n in names if q.get(n, "") != ""]
    if len({value for _name, value in values}) > 1:
        die("conflicting query aliases: %s" % ", ".join(name for name, _ in values))
    if values:
        return values[0][1]
    return default


def safe_urlsplit(link):
    """urlsplit that dies cleanly instead of raising on a malformed URL
    (e.g. an unterminated bracketed IPv6 host)."""
    try:
        return urlsplit(link)
    except ValueError:
        die("malformed link (could not parse URL)")


def host_port(u):
    """(hostname, port) from a urlsplit result. urlsplit raises ValueError for a
    non-numeric/out-of-range port instead of returning None, so catch it and die
    cleanly rather than letting a traceback escape."""
    try:
        return u.hostname, u.port
    except ValueError:
        die("invalid port in link (must be 1-65535)")


def safe_port(value):
    """Parse a port string/int into 1..65535, dying cleanly on anything else."""
    try:
        p = int(value)
    except (TypeError, ValueError):
        die("invalid port in link (must be a number 1-65535)")
    if not (0 < p < 65536):
        die("port out of range in link (1-65535)")
    return p


# Host chars allowed without further IDNA processing: letters/digits/.-_:[] and %
# (for zone ids). Control bytes, ESC/OSC, whitespace, and a leading '-' are rejected
# so a hostile server address can't inject terminal sequences or look like a CLI flag.
_HOST_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:%")


def valid_host(host):
    """Return host if it is a safe IP literal or hostname, else die. Always rejects
    control/whitespace/non-printable characters and a leading hyphen; non-ASCII is
    allowed only if it is a real IDNA-encodable domain name."""
    if not host:
        die("link is missing a server host")
    # Legacy base64 Shadowsocks links may retain brackets around an IPv6
    # literal; urlsplit().hostname removes them for normal URI forms.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
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
    # Accept IP literals (including an IPv6 zone id) before domain validation.
    ip_candidate = host.split("%", 1)[0]
    try:
        import ipaddress
        ipaddress.ip_address(ip_candidate)
        return host
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii") if has_nonascii else host
    except Exception:
        die("invalid server host (not a valid domain name)")
    core = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
    labels = core.split(".")
    if not core or any(not x or len(x) > 63 or x[0] == "-" or x[-1] == "-"
                       or any(not (ch.isalnum() or ch == "-") for ch in x)
                       for x in labels):
        die("invalid server host (malformed domain name)")
    return ascii_host


def xray_outbound_servers(ob):
    """Return validated-looking (host, port) pairs from common Xray outbounds.

    This is structural extraction only; the real core remains authoritative for
    protocol validation. It covers vnext (VLESS/VMess) and servers
    (Trojan/Shadowsocks/SOCKS/HTTP) without assuming the first member is valid.
    """
    if not isinstance(ob, dict):
        return []
    settings = ob.get("settings")
    if not isinstance(settings, dict):
        return []
    result = []
    for key in ("vnext", "servers"):
        values = settings.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            host = value.get("address", value.get("server"))
            port = value.get("port", value.get("server_port"))
            if host not in (None, ""):
                result.append((str(host), port))
    # Current HTTP/SOCKS and several newer outbound schemas use a direct
    # settings.address/settings.server pair rather than an array.
    for key in ("address", "server"):
        host = settings.get(key)
        if isinstance(host, str) and host:
            result.append((host, settings.get("port", settings.get("server_port"))))
    # WireGuard-style peers carry their dial target as endpoint=host:port.
    peers = settings.get("peers")
    if isinstance(peers, list):
        for peer in peers:
            endpoint = peer.get("endpoint") if isinstance(peer, dict) else None
            if not isinstance(endpoint, str) or not endpoint:
                continue
            try:
                parsed = urlsplit("//" + endpoint)
                host, port = parsed.hostname, parsed.port
            except ValueError:
                host, port = endpoint, None
            if host:
                result.append((host, port))
    # A few outbound implementations use top-level server/server_port fields.
    if ob.get("server") not in (None, ""):
        result.append((str(ob["server"]), ob.get("server_port", ob.get("port"))))
    return result


def apply_input_file(args):
    """If --input-file was given, load the secret fields (link/secret_key/
    peer_pubkey) from that mode-600 JSON and override the matching argv flags, so
    secrets stay out of the process list and dodge ARG_MAX on very long links."""
    path = getattr(args, "input_file", "")
    if not path:
        _apply_separate_input_files(args)
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            inp = json.load(fh)
    except Exception as e:
        die("could not read --input-file: %s" % e)
    if not isinstance(inp, dict):
        die("--input-file must contain a JSON object")
    for k in ("link", "secret_key", "peer_pubkey"):
        if k in inp:
            setattr(args, k, str(inp[k]))

    _apply_separate_input_files(args)


def _read_text_file(path, label):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception as e:
        die("could not read %s: %s" % (label, e))


def _apply_separate_input_files(args):
    """Load individual secret fields from files when those flags are present."""
    for attr, file_attr, label in (
            ("link", "link_file", "--link-file"),
            ("secret_key", "secret_key_file", "--secret-key-file"),
            ("peer_pubkey", "peer_pubkey_file", "--peer-pubkey-file")):
        path = getattr(args, file_attr, "")
        if path:
            setattr(args, attr, _read_text_file(path, label))
