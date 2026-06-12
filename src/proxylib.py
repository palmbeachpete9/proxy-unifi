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
from urllib.parse import urlsplit, parse_qs


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
    """Flatten a urlsplit result's query into {key: first_value}."""
    return {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}


def qg(q, *names, default=""):
    """First non-empty value among the given query keys, else default."""
    for n in names:
        if q.get(n, "") != "":
            return q[n]
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
_HOST_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]%")


def valid_host(host):
    """Return host if it is a safe IP literal or hostname, else die. Always rejects
    control/whitespace/non-printable characters and a leading hyphen; non-ASCII is
    allowed only if it is a real IDNA-encodable domain name."""
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
        # non-ASCII present: accept only a real IDNA-encodable domain name
        try:
            host.encode("idna")
        except Exception:
            die("invalid server host (not a valid domain name)")
    return host


def apply_input_file(args):
    """If --input-file was given, load the secret fields (link/secret_key/
    peer_pubkey) from that mode-600 JSON and override the matching argv flags, so
    secrets stay out of the process list and dodge ARG_MAX on very long links."""
    path = getattr(args, "input_file", "")
    if not path:
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
