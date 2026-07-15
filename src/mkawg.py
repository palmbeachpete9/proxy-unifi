#!/usr/bin/env python3
"""Parse AmneziaWG profiles and build the proxy-unifi bridge config.

The generated config runs two userspace endpoints in one amnezia-box process:
the existing WireGuard server used by UniFi, and an AmneziaWG client endpoint.
No provider key is passed on argv and no kernel interface or route is created.

Stdlib only (Python 3.7+).
"""

import argparse
import base64
import binascii
import contextlib
import io
import ipaddress
import json
import os
import re
import shutil
import stat
import sys
import unicodedata

from proxylib import valid_host


MAX_CONFIG_BYTES = 256 * 1024
MAX_NAME_CHARS = 80
MAX_PEERS = 32
MAX_INTERFACE_ADDRESSES = 16
MAX_DNS_SERVERS = 16
MAX_ALLOWED_IPS = 128
MAX_CPS_PACKET = 65507
PROFILE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
HEADER_RE = re.compile(r"^(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?$")
TAG_RE = re.compile(r"<([^<>]*)>")

INTERFACE_KEYS = {
    "privatekey": "private_key",
    "address": "address",
    "dns": "dns",
    "mtu": "mtu",
    "listenport": "listen_port",
    "jc": "jc",
    "jmin": "jmin",
    "jmax": "jmax",
    "s1": "s1",
    "s2": "s2",
    "s3": "s3",
    "s4": "s4",
    "h1": "h1",
    "h2": "h2",
    "h3": "h3",
    "h4": "h4",
    "i1": "i1",
    "i2": "i2",
    "i3": "i3",
    "i4": "i4",
    "i5": "i5",
}
PEER_KEYS = {
    "publickey": "public_key",
    "presharedkey": "preshared_key",
    "allowedips": "allowed_ips",
    "endpoint": "endpoint",
    "persistentkeepalive": "persistent_keepalive",
    "persistentkeepaliveinterval": "persistent_keepalive",
}
WG_QUICK_KEYS = {
    "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark"
}


class ProfileError(ValueError):
    pass


def fail(message):
    raise ProfileError(message)


def _unsafe_text_char(ch):
    category = unicodedata.category(ch)
    # Keep U+200D so valid joined emoji remain usable, but reject terminal
    # controls and invisible formatting/bidirectional override characters.
    return category in ("Cc", "Cs") or (category == "Cf" and ch != "\u200d")


def _read_regular(path, maximum=MAX_CONFIG_BYTES):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        fail("profile is not a regular file")
    if st.st_size <= 0:
        fail("profile is empty")
    if st.st_size > maximum:
        fail("profile is too large (maximum %d bytes)" % maximum)
    with open(path, "rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        fail("profile is too large (maximum %d bytes)" % maximum)
    if b"\x00" in raw:
        fail("profile contains a NUL byte")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        fail("profile must be UTF-8 text")


def _clean_text(value, maximum):
    value = unicodedata.normalize("NFC", value)
    if any(_unsafe_text_char(ch) for ch in value):
        fail("text contains control characters")
    value = " ".join(value.split())
    if not value:
        fail("text cannot be empty")
    if len(value) > maximum:
        fail("text is too long (maximum %d characters)" % maximum)
    return value


def validate_name(value):
    return _clean_text(value, MAX_NAME_CHARS)


def _parse_ini(path):
    text = _read_regular(path)
    interface = None
    peers = []
    current = None
    section_name = ""

    for number, original in enumerate(text.splitlines(), 1):
        line = original.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section_name = line[1:-1].strip().lower()
            if section_name == "interface":
                if interface is not None:
                    fail("line %d: duplicate [Interface] section" % number)
                interface = {}
                current = interface
            elif section_name == "peer":
                if interface is None:
                    fail("line %d: [Peer] appears before [Interface]" % number)
                if len(peers) >= MAX_PEERS:
                    fail("too many [Peer] sections (maximum %d)" % MAX_PEERS)
                current = {}
                peers.append(current)
            else:
                fail("line %d: unsupported section [%s]" % (number, line[1:-1].strip()))
            continue
        if current is None:
            fail("line %d: setting appears outside a section" % number)
        if "=" not in line:
            fail("line %d: expected Key = Value" % number)
        key, value = (part.strip() for part in line.split("=", 1))
        if not key:
            fail("line %d: setting name is empty" % number)
        folded = key.lower()
        mapping = INTERFACE_KEYS if section_name == "interface" else PEER_KEYS
        if folded in WG_QUICK_KEYS:
            fail("line %d: %s hooks/routing are not supported in managed profiles" %
                 (number, key))
        canonical = mapping.get(folded)
        if canonical is None:
            fail("line %d: unsupported %s setting %s" %
                 (number, section_name, key))
        if canonical in current:
            fail("line %d: duplicate setting %s" % (number, key))
        current[canonical] = value

    if interface is None:
        fail("missing [Interface] section")
    if not peers:
        fail("missing [Peer] section")
    return interface, peers


def _strict_key(value, label, allow_empty=False, reject_zero=False):
    if not value and allow_empty:
        return ""
    if len(value) != 44:
        fail("%s must encode exactly 32 bytes" % label)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        fail("%s must be strict base64" % label)
    if len(raw) != 32:
        fail("%s must encode exactly 32 bytes" % label)
    if base64.b64encode(raw).decode("ascii") != value:
        fail("%s must use canonical base64" % label)
    if reject_zero and raw == bytes(32):
        fail("%s cannot be the all-zero key" % label)
    return value


def _integer(value, label, minimum, maximum):
    if value is None or value == "":
        return 0
    if not re.match(r"^(0|[1-9][0-9]*)$", value):
        fail("%s must be an integer" % label)
    if len(value) > len(str(maximum)):
        fail("%s must be %d-%d" % (label, minimum, maximum))
    number = int(value)
    if number < minimum or number > maximum:
        fail("%s must be %d-%d" % (label, minimum, maximum))
    return number


def _header(value, label):
    if value is None or value == "":
        return None
    match = HEADER_RE.match(value)
    if not match:
        fail("%s must be an unsigned integer or range (start-end)" % label)
    if len(match.group(1)) > 10 or len(match.group(2) or "") > 10:
        fail("%s exceeds the 32-bit header range" % label)
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if start > 0xFFFFFFFF or end > 0xFFFFFFFF:
        fail("%s exceeds the 32-bit header range" % label)
    if end < start:
        fail("%s range ends before it starts" % label)
    # amneziawg-go calculates (end - start + 1) as uint32 before handing it to
    # crypto/rand. The complete 0..2^32-1 range wraps to zero and can panic.
    if start == 0 and end == 0xFFFFFFFF:
        fail("%s range is too wide" % label)
    return value, start, end


def _cps(value, label):
    if value is None or value == "":
        return "", 0
    matches = list(TAG_RE.finditer(value))
    if not matches:
        fail("%s must contain CPS tags such as <b 0x12ab> or <r 20>" % label)
    cursor = 0
    output_size = 0
    dynamic = False
    for match in matches:
        if value[cursor:match.start()].strip():
            fail("%s contains text outside CPS tags" % label)
        cursor = match.end()
        parts = match.group(1).split()
        if not parts:
            fail("%s contains an empty CPS tag" % label)
        kind = parts[0]
        args = parts[1:]
        if kind == "b":
            if len(args) != 1:
                fail("%s: <b> requires one hexadecimal argument" % label)
            encoded = args[0]
            if encoded.startswith("0x"):
                encoded = encoded[2:]
            if not encoded or len(encoded) % 2 or not re.match(r"^[0-9a-fA-F]+$", encoded):
                fail("%s: <b> requires an even-length hexadecimal value" % label)
            output_size += len(encoded) // 2
        elif kind in ("r", "rc", "rd"):
            if len(args) != 1 or not re.match(r"^(0|[1-9][0-9]*)$", args[0]):
                fail("%s: <%s> requires a non-negative byte count" % (label, kind))
            if len(args[0]) > len(str(MAX_CPS_PACKET)):
                fail("%s static data exceeds the UDP payload limit" % label)
            output_size += int(args[0])
        elif kind == "t":
            if args:
                fail("%s: <t> does not take an argument" % label)
            output_size += 4
        elif kind in ("d", "ds"):
            if args:
                fail("%s: <%s> does not take an argument" % (label, kind))
            dynamic = True
        elif kind == "dz":
            if len(args) != 1 or not re.match(r"^[1-8]$", args[0]):
                fail("%s: <dz> requires a size from 1 to 8" % label)
            output_size += int(args[0])
        else:
            fail("%s contains unsupported CPS tag <%s>" % (label, kind))
        if output_size > MAX_CPS_PACKET:
            fail("%s static data exceeds the UDP payload limit" % label)
    if value[cursor:].strip():
        fail("%s contains text outside CPS tags" % label)
    if dynamic and output_size > MAX_CPS_PACKET - 148:
        fail("%s leaves no room for dynamic packet data" % label)
    return value, output_size


def _endpoint(value):
    if not value:
        fail("Peer Endpoint is required")
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
            fail("Peer Endpoint has malformed bracketed IPv6 syntax")
        host = value[1:closing]
        port_text = value[closing + 2:]
    else:
        if value.count(":") != 1:
            fail("Peer Endpoint must be host:port (IPv6 must use [address]:port)")
        host, port_text = value.rsplit(":", 1)
    # proxylib's public helper exits after printing its own CLI error. Suppress
    # that implementation detail so mkawg returns one clear validation error.
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            host = valid_host(host)
        except SystemExit:
            fail("Peer Endpoint host is invalid")
    port = _integer(port_text, "Peer Endpoint port", 1, 65535)
    core_host = "[%s]" % host if ":" in host else host
    return host, core_host, port


def _prefixes(value, label, required=True, maximum=MAX_INTERFACE_ADDRESSES):
    result = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            interface = ipaddress.ip_interface(item)
        except ValueError:
            fail("%s contains invalid address/prefix %s" % (label, item))
        result.append(str(interface))
        if len(result) > maximum:
            fail("%s has too many entries (maximum %d)" % (label, maximum))
    if required and not result:
        fail("%s is required" % label)
    return result


def _allowed_prefixes(value):
    result = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            result.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            fail("Peer AllowedIPs contains invalid prefix %s" % item)
        if len(result) > MAX_ALLOWED_IPS:
            fail("Peer AllowedIPs has too many entries (maximum %d)" %
                 MAX_ALLOWED_IPS)
    if not result:
        fail("Peer AllowedIPs is required")
    return result


def _dns(value):
    result = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        if any(_unsafe_text_char(ch) for ch in item):
            fail("DNS contains control characters")
        if len(item) > 253:
            fail("DNS item is too long")
        result.append(item)
        if len(result) > MAX_DNS_SERVERS:
            fail("DNS has too many entries (maximum %d)" % MAX_DNS_SERVERS)
    return result


def load_profile(path):
    raw_interface, raw_peers = _parse_ini(path)
    interface = {
        "private_key": _strict_key(raw_interface.get("private_key", ""),
                                   "Interface PrivateKey", reject_zero=True),
        "address": _prefixes(raw_interface.get("address"), "Interface Address"),
        "dns": _dns(raw_interface.get("dns")),
        "mtu": _integer(raw_interface.get("mtu"), "Interface MTU", 576, 9000) or 1408,
        "listen_port": _integer(raw_interface.get("listen_port"), "Interface ListenPort", 0, 65535),
        "jc": _integer(raw_interface.get("jc"), "Jc", 0, 128),
        "jmin": _integer(raw_interface.get("jmin"), "Jmin", 0, MAX_CPS_PACKET),
        "jmax": _integer(raw_interface.get("jmax"), "Jmax", 0, MAX_CPS_PACKET),
    }
    for number in range(1, 5):
        if number == 1:
            maximum = MAX_CPS_PACKET - 148
        elif number == 2:
            maximum = MAX_CPS_PACKET - 92
        elif number == 3:
            maximum = MAX_CPS_PACKET - 64
        else:
            maximum = MAX_CPS_PACKET - interface["mtu"] - 32
        interface["s%d" % number] = _integer(
            raw_interface.get("s%d" % number), "S%d" % number, 0, maximum)

    if interface["jc"]:
        if not interface["jmin"] or not interface["jmax"]:
            fail("Jmin and Jmax are required when Jc is non-zero")
        if interface["jmin"] > interface["jmax"]:
            fail("Jmin cannot exceed Jmax")

    headers = []
    for number in range(1, 5):
        parsed = _header(raw_interface.get("h%d" % number), "H%d" % number)
        interface["h%d" % number] = parsed[0] if parsed else ""
        headers.append(parsed)
    if any(headers) and not all(headers):
        fail("H1-H4 must either all be present or all be omitted")
    for index, first in enumerate(headers):
        if first is None:
            continue
        for second in headers[index + 1:]:
            if not (first[2] < second[1] or second[2] < first[1]):
                fail("H1-H4 ranges must not overlap")

    cps_sizes = []
    for number in range(1, 6):
        value, size = _cps(raw_interface.get("i%d" % number), "I%d" % number)
        interface["i%d" % number] = value
        cps_sizes.append(size)
    interface["cps_sizes"] = cps_sizes

    peers = []
    public_keys = set()
    for index, raw in enumerate(raw_peers, 1):
        host, core_host, port = _endpoint(raw.get("endpoint", ""))
        keepalive = _integer(raw.get("persistent_keepalive"),
                             "Peer %d PersistentKeepalive" % index, 0, 65535)
        peer = {
            "public_key": _strict_key(raw.get("public_key", ""),
                                      "Peer %d PublicKey" % index,
                                      reject_zero=True),
            "preshared_key": _strict_key(raw.get("preshared_key", ""),
                                         "Peer %d PresharedKey" % index,
                                         allow_empty=True),
            "allowed_ips": _allowed_prefixes(raw.get("allowed_ips")),
            "host": host,
            "core_host": core_host,
            "port": port,
            "persistent_keepalive": keepalive,
        }
        if peer["public_key"] in public_keys:
            fail("Peer %d duplicates an earlier PublicKey" % index)
        public_keys.add(peer["public_key"])
        peers.append(peer)

    version = "1.0"
    has_cps = any(interface["i%d" % n] for n in range(1, 6))
    has_v2 = any(key in raw_interface for key in ("s3", "s4", "i2", "i3", "i4", "i5")) \
        or any(header and header[1] != header[2] for header in headers)
    if has_v2:
        version = "2.0"
    elif has_cps:
        version = "1.5"
    return {"interface": interface, "peers": peers, "version": version}


def _endpoint_json(profile):
    interface = profile["interface"]
    endpoint = {
        "type": "awg",
        "tag": "awg-out",
        "useIntegratedTun": False,
        "private_key": interface["private_key"],
        "address": interface["address"],
        "mtu": interface["mtu"],
        "peers": [],
    }
    # A client-side ListenPort is not needed for the outbound and would create a
    # second externally reachable UDP listener outside proxy-unifi's WG guard.
    # Keep it in the saved source profile, but deliberately omit it at runtime.
    numeric = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
    text = ("h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5")
    for key in numeric:
        if interface[key]:
            endpoint[key] = interface[key]
    for key in text:
        if interface[key]:
            endpoint[key] = interface[key]
    for peer in profile["peers"]:
        item = {
            "address": peer["core_host"],
            "port": peer["port"],
            "public_key": peer["public_key"],
            "allowed_ips": peer["allowed_ips"],
        }
        if peer["preshared_key"]:
            item["preshared_key"] = peer["preshared_key"]
        if peer["persistent_keepalive"]:
            item["persistent_keepalive_interval"] = peer["persistent_keepalive"]
        endpoint["peers"].append(item)
    return endpoint


def build_config(profile, args):
    awg_endpoint = _endpoint_json(profile)
    if args.socks_port:
        return {
            "log": {"level": args.loglevel},
            "inbounds": [{
                "type": "socks", "tag": "socks-in", "listen": "127.0.0.1",
                "listen_port": args.socks_port,
            }],
            "endpoints": [awg_endpoint],
            "route": {
                "rules": [{"inbound": ["socks-in"], "outbound": "awg-out"}],
                "final": "awg-out",
            },
        }
    inner_private = _strict_key(_read_secret(args.secret_key_file),
                                "inner WireGuard private key", reject_zero=True)
    inner_peer = _strict_key(_read_secret(args.peer_pubkey_file),
                             "inner WireGuard peer public key", reject_zero=True)
    inner = {
        "type": "wireguard",
        "tag": "wg-in",
        "system": False,
        "mtu": args.mtu,
        "address": _prefixes(args.address, "inner WireGuard address"),
        "private_key": inner_private,
        "listen_port": args.port,
        "peers": [{
            "public_key": inner_peer,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
        }],
    }
    return {
        "log": {"level": args.loglevel},
        "endpoints": [inner, awg_endpoint],
        "route": {
            "rules": [{"inbound": ["wg-in"], "outbound": "awg-out"}],
            "final": "awg-out",
        },
    }


def _read_secret(path):
    if not path:
        fail("secret file path is required")
    return _read_regular(path, 4096).strip()


def _terminal_fallback(value):
    if os.environ.get("PROXY_UNIFI_TERMINAL_SAFE_EMOJI") != "1":
        return value
    result = []
    index = 0
    while index < len(value):
        ch = value[index]
        code = ord(ch)
        if 0x1F1E6 <= code <= 0x1F1FF and index + 1 < len(value):
            next_code = ord(value[index + 1])
            if 0x1F1E6 <= next_code <= 0x1F1FF:
                country = chr(ord("A") + code - 0x1F1E6) + \
                    chr(ord("A") + next_code - 0x1F1E6)
                result.append("[%s] " % country)
                index += 2
                continue
        elif ch in ("\U0001F6DC", "\U0001F4F6"):
            result.append("Wi-Fi ")
        elif code > 0xFFFF:
            result.append("")
        else:
            result.append(ch)
        index += 1
    return "".join(result)


def _display_width(ch):
    if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    code = ord(ch)
    if 0x1F000 <= code <= 0x1FAFF or 0x2600 <= code <= 0x27BF:
        return 2
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _display(value, maximum=80):
    value = unicodedata.normalize("NFC", value)
    value = "".join("" if _unsafe_text_char(ch) else ch
                    for ch in value)
    value = " ".join(value.split())
    value = _terminal_fallback(value)
    value = " ".join(value.split())
    output = []
    width = 0
    for ch in value:
        char_width = _display_width(ch)
        if width + char_width > maximum:
            while output and width + 3 > maximum:
                removed = output.pop()
                width -= _display_width(removed)
            return "".join(output).rstrip() + "..."
        output.append(ch)
        width += char_width
    return "".join(output)


def _terminal_columns():
    try:
        columns = shutil.get_terminal_size(fallback=(100, 24)).columns
    except (OSError, ValueError):
        columns = 100
    return max(40, min(columns, 240))


def _profile_entries(directory):
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return []
    result = []
    for entry in entries:
        if not entry.name.endswith(".conf") or not entry.is_file(follow_symlinks=False):
            continue
        profile_id = entry.name[:-5]
        if not PROFILE_ID_RE.match(profile_id):
            continue
        name_path = os.path.join(directory, profile_id + ".name")
        try:
            name = validate_name(_read_regular(name_path, 4096).strip())
        except (OSError, ProfileError):
            name = profile_id
        try:
            profile = load_profile(entry.path)
            error = ""
        except (OSError, ProfileError) as exc:
            profile = None
            error = str(exc)
        result.append((profile_id, entry.path, name, profile, error))
    result.sort(key=lambda item: (item[2].casefold(), item[0]))
    return result


def _write_map(path, entries):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            fail("profile selection map is not a regular file")
        payload = "".join(item[0] + "\n" for item in entries).encode("ascii")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def render_profiles(directory, selected, map_file=""):
    entries = _profile_entries(directory)
    if map_file:
        _write_map(map_file, entries)
    if not entries:
        print("  (no AmneziaWG profiles saved)")
        return
    columns = _terminal_columns()
    for index, (profile_id, _path, name, profile, error) in enumerate(entries, 1):
        marker = "*" if profile_id == selected else " "
        if profile is None:
            prefix = "%3d. [%s] invalid " % (index, marker)
            print(prefix + _display(name, max(8, columns - len(prefix))))
            prefix = "     error: "
            print(prefix + _display(error, max(8, columns - len(prefix))))
            continue
        peer = profile["peers"][0]
        endpoint = "%s:%d" % (peer["core_host"], peer["port"])
        prefix = "%3d. [%s] AWG %-4s " % (index, marker, profile["version"])
        if columns < 64:
            print(prefix + _display(name, max(8, columns - len(prefix))))
            prefix = "     endpoint: "
            print(prefix + _display(endpoint, max(8, columns - len(prefix))))
            continue
        endpoint_width = min(24, max(16, columns // 4))
        endpoint = _display(endpoint, endpoint_width)
        prefix += "%-*s " % (endpoint_width, endpoint)
        print(prefix + _display(name, max(8, columns - len(prefix))))


def pick_profile(directory, index=None, profile_id="", allow_invalid=False):
    entries = _profile_entries(directory)
    if profile_id:
        matches = [item for item in entries if item[0] == profile_id]
        if not matches:
            fail("profile no longer exists")
        selected = matches[0]
        label = profile_id
    else:
        if index is None or index < 1 or index > len(entries):
            fail("no profile #%s" % (index if index is not None else "?"))
        selected = entries[index - 1]
        label = "#%d" % index
    selected_id, path, name, profile, error = selected
    if profile is None and not allow_invalid:
        fail("profile %s is invalid: %s" % (label, error))
    print("%s\t%s\t%s" % (selected_id, path, _display(name, 60)))


def print_info(profile):
    peer = profile["peers"][0]
    dns = _display(",".join(profile["interface"]["dns"]) or "-", 48)
    print("%s\t%s\t%d\t%d\t%s\t%d" %
          (profile["version"], peer["host"], peer["port"], len(profile["peers"]),
           dns, profile["interface"]["mtu"]))


def make_parser():
    parser = argparse.ArgumentParser(description="Validate and render AmneziaWG profiles")
    sub = parser.add_subparsers(dest="command")

    for command in ("validate", "info", "server"):
        item = sub.add_parser(command)
        item.add_argument("--file", required=True)

    build = sub.add_parser("build")
    build.add_argument("--file", required=True)
    build.add_argument("--secret-key-file", default="")
    build.add_argument("--peer-pubkey-file", default="")
    build.add_argument("--port", type=int, default=0)
    build.add_argument("--address", default="10.7.0.1/32")
    build.add_argument("--mtu", type=int, default=1340)
    build.add_argument("--loglevel", default="warn")
    build.add_argument("--socks-port", type=int, default=0)

    render = sub.add_parser("render")
    render.add_argument("--dir", required=True)
    render.add_argument("--selected", default="")
    render.add_argument("--map-file", default="")

    pick = sub.add_parser("pick")
    pick.add_argument("--dir", required=True)
    target = pick.add_mutually_exclusive_group(required=True)
    target.add_argument("--index", type=int)
    target.add_argument("--id", default="")
    pick.add_argument("--allow-invalid", action="store_true")

    name = sub.add_parser("name")
    name.add_argument("--value", required=True)
    return parser


def main():
    args = make_parser().parse_args()
    if not args.command:
        fail("a command is required")
    if args.command == "name":
        print(validate_name(args.value))
        return
    if args.command == "render":
        render_profiles(args.dir, args.selected, args.map_file)
        return
    if args.command == "pick":
        pick_profile(args.dir, args.index, args.id, args.allow_invalid)
        return

    profile = load_profile(args.file)
    if args.command == "validate":
        print_info(profile)
    elif args.command == "info":
        print_info(profile)
    elif args.command == "server":
        peer = profile["peers"][0]
        print("%s\t%d" % (peer["host"], peer["port"]))
    elif args.command == "build":
        if args.socks_port:
            if not (1 <= args.socks_port <= 65535):
                fail("SOCKS port must be 1-65535")
        else:
            if not (1 <= args.port <= 65535):
                fail("WireGuard port must be 1-65535")
            if not (576 <= args.mtu <= 9000):
                fail("inner WireGuard MTU must be 576-9000")
        config = build_config(profile, args)
        json.dump(config, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ProfileError) as exc:
        print("mkawg: error: %s" % _display(str(exc), 240), file=sys.stderr)
        raise SystemExit(1)
