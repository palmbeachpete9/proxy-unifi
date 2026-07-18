#!/usr/bin/env python3
"""
proxylib.py - shared parsing utilities for proxy-unifi's config generators.

The two share-link generators parse the same family of proxy URIs into an engine-specific
outbound; only the generic plumbing (URL splitting, host/port validation,
base64, query helpers, secret-file loading, Shadowsocks credentials, and error
handling) is shared here instead of being copy-pasted into each.
mkawg.py also reuses the strict host validator for AmneziaWG peer endpoints.

It is imported, never run directly. Each helper runs from the installed `bin/`
directory, which Python places on sys.path[0], so the sibling proxylib.py is
importable with no packaging.

Stdlib only (Python 3.9+).
"""

import base64
import ipaddress
import json
import os
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

_B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")

SS2022_KEY_BYTES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}
SS2022_MAX_KEYS = 16
SINGBOX_SS_PLUGINS = ("obfs-local", "simple-obfs", "v2ray-plugin")


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
    s = "".join(s.split())
    if any(ch not in _B64_ALPHABET for ch in s):
        return None
    try:
        # altchars accepts URL-safe (-_) and standard (+/) alphabets in one
        # strict decoder pass.
        return base64.b64decode(b64_pad(s), altchars=b"-_", validate=True).decode("utf-8")
    except Exception:
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


def is_non_public_host(host):
    low = host.rstrip(".").lower()
    if low == "localhost" or low in ("metadata.google.internal", "metadata.aws.internal") \
            or low.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return True
    candidate = host.split("%", 1)[0]
    if ":" not in candidate and any(ch not in "0123456789." for ch in candidate):
        return False
    try:
        return not ipaddress.ip_address(candidate).is_global
    except ValueError:
        return False


def validate_xhttp_download_settings(value):
    address = value.get("address")
    if address not in (None, ""):
        host = valid_host(str(address))
        if is_non_public_host(host):
            die("XHTTP downloadSettings targets a non-public address")
    if value.get("port") not in (None, "", 0, "0"):
        safe_port(value["port"])


def nested_too_deep(value, maximum, depth=0):
    """Return early when a JSON-like dict/list exceeds the nesting limit."""
    if depth > maximum:
        return True
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return False
    for child in children:
        if nested_too_deep(child, maximum, depth + 1):
            return True
    return False


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


def shadowsocks_method_password(parsed):
    """Extract SS method/password without validating the destination.

    This non-exiting form is shared with subscription classification, where one
    malformed provider row must be marked unsupported instead of terminating
    the entire catalog parse.
    """
    method = password = None
    if parsed.username is not None:
        if parsed.password is not None:
            method, password = unquote(parsed.username), unquote(parsed.password)
        else:
            decoded = b64decode_any(parsed.username)
            if decoded and ":" in decoded:
                method, password = decoded.split(":", 1)
    if method is None:
        decoded = b64decode_any(parsed.netloc)
        if decoded and "@" in decoded and ":" in decoded:
            credentials = decoded.rsplit("@", 1)[0]
            method, password = credentials.split(":", 1)
    return method, password


def shadowsocks_2022_key_info(method, password, allow_xray_compat=True):
    """Return (is_ss2022, error, needs_xray_compat) without exposing keys.

    SS2022 uses one fixed-length base64 PSK, or a colon-separated identity chain
    for an AES single-port multi-user server and optional relays. Xray historically
    also accepts 32-byte keys with the AES-128 method; preserve that existing
    behavior only when the caller explicitly allows the compatibility path.
    """
    lowered = method.lower() if isinstance(method, str) else ""
    if lowered not in SS2022_KEY_BYTES:
        if lowered.startswith("2022-"):
            return True, "unsupported SS2022 method", False
        return False, "", False
    if method != lowered:
        return True, "SS2022 method must use its exact lowercase name", False
    if not isinstance(password, str) or not password or len(password) > 1024:
        return True, "SS2022 key is empty or too long", False
    parts = password.split(":")
    if len(parts) > SS2022_MAX_KEYS or any(not part for part in parts):
        return True, "SS2022 key must contain 1-%d colon-delimited PSKs" \
            % SS2022_MAX_KEYS, False
    if len(parts) > 1 and method == "2022-blake3-chacha20-poly1305":
        return True, "SS2022 multi-user keys require an AES-GCM method", False
    expected = SS2022_KEY_BYTES[method]
    compatibility = False
    for number, encoded in enumerate(parts, 1):
        try:
            # SS2022 PSKs use standard base64. Accept omitted trailing padding,
            # but not whitespace or the URL-safe alphabet inside the decoded
            # SIP002 credential.
            if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                   for ch in encoded):
                raise ValueError()
            raw = base64.b64decode(b64_pad(encoded), validate=True)
        except Exception:
            return True, "SS2022 key #%d is not valid base64" % number, False
        if len(raw) == expected:
            continue
        if method == "2022-blake3-aes-128-gcm" and len(raw) == 32 \
                and allow_xray_compat:
            compatibility = True
            continue
        return True, "SS2022 key #%d must decode to %d bytes" % (number, expected), False
    return True, "", compatibility


def shadowsocks_engine(method, password, plugin=""):
    """Return (engine, reason, variant) for one parsed Shadowsocks link."""
    is_2022, error, compatibility = shadowsocks_2022_key_info(
        method, password, allow_xray_compat=True)
    variant = "2022" if is_2022 else ""
    if error:
        return "", error, variant
    if plugin and plugin not in SINGBOX_SS_PLUGINS:
        return "", "unsupported SIP003 plugin", variant
    if is_2022:
        if compatibility:
            if plugin:
                return "", "32-byte AES-128 compatibility keys cannot use a SIP003 plugin", variant
            return "xray", "Xray 32-byte AES-128 compatibility key", variant
        return "singbox", "", variant
    return ("singbox", "", variant) if plugin else ("xray", "", variant)


def shadowsocks_credentials(link):
    """Return (split URL, method, password, host, port) for SIP002 or legacy SS."""
    parsed = safe_urlsplit(link)
    host, port = host_port(parsed)
    method, password = shadowsocks_method_password(parsed)
    if parsed.username is None and (not host or not port):
        decoded = b64decode_any(parsed.netloc)
        if decoded and "@" in decoded and ":" in decoded:
            credentials, hostport = decoded.rsplit("@", 1)
            if method is None:
                method, password = credentials.split(":", 1)
            try:
                if hostport.startswith("[") and "]:" in hostport:
                    host, port = hostport[1:].rsplit("]:", 1)
                else:
                    host, port = hostport.rsplit(":", 1)
            except ValueError:
                die("could not parse shadowsocks server host/port")
    if not method or not password or not host or not port:
        die("could not parse shadowsocks link")
    is_2022, error, _compatibility = shadowsocks_2022_key_info(
        method, password, allow_xray_compat=True)
    if is_2022 and error:
        die(error)
    if is_2022:
        # Providers occasionally omit trailing key padding inside the SIP002
        # credential. The bytes are unambiguous, but current cores expect the
        # canonical padded spelling in their JSON configuration.
        password = ":".join(
            base64.b64encode(base64.b64decode(b64_pad(part), validate=True)).decode("ascii")
            for part in password.split(":"))
    return parsed, method, password, valid_host(host), safe_port(port)


def _read_text_file(path, label):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception as e:
        die("could not read %s: %s" % (label, e))


def apply_secret_files(args):
    """Load individual secret fields from files when those flags are present."""
    for attr, file_attr, label in (
            ("link", "link_file", "--link-file"),
            ("secret_key", "secret_key_file", "--secret-key-file"),
            ("peer_pubkey", "peer_pubkey_file", "--peer-pubkey-file")):
        path = getattr(args, file_attr, "")
        if path:
            setattr(args, attr, _read_text_file(path, label))


def add_secret_file_arguments(parser):
    parser.add_argument("--link-file", default="", help="read the proxy link from a file")
    parser.add_argument("--secret-key-file", default="",
                        help="read the WireGuard private key from a file")
    parser.add_argument("--peer-pubkey-file", default="",
                        help="read the peer public key from a file")


def load_generator_inputs(args):
    apply_secret_files(args)
    if not args.link:
        die("no link provided (use --link or --link-file)")


def handle_common_generator_modes(args, parse_link, build_test_config):
    """Handle shared print-server/test-config modes and bridge prerequisites."""
    if args.print_server:
        _, host, port = parse_link(args.link)
        sys.stdout.write("%s\t%s\n" % (host, port))
        return True
    if args.socks_port:
        json.dump(build_test_config(args), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return True
    if not args.secret_key or not args.peer_pubkey or not args.port:
        die("--port, --secret-key and --peer-pubkey are required to build the bridge config")
    return False


def dispatch_subcommand(parser):
    args = parser.parse_args()
    if not getattr(args, "fn", None):
        parser.print_help()
        sys.exit(2)
    args.fn(args)
