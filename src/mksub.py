#!/usr/bin/env python3
"""
mksub.py - subscription fetch/parse helper for proxy-unifi.

Scope: Base64/plain newline-separated share links plus raw Xray JSON profile
objects/arrays (including balancer pools). The shell CLI drives fetching,
selection, scheduled refresh, and activation through the hardened link/profile
import paths.

Security: HTTPS-only, SSRF guard that pins the connection to a validated public
IP (defeating DNS-rebinding), capped response size / node count / redirects /
overall deadline, the x-hwid header never forwarded to a different origin, and
all provider-controlled text sanitized before display. The subscription URL and
HWID are read from files (--url-file/--hwid-file) so they never appear in argv.

Subcommands:
  fetch  [--url-file F | --url U] [--hwid-file F] [--ua UA] [--body-file F]
                                       -> JSON catalog (stdout)
  render --file nodes.json             -> numbered human list (sanitized)
  extract --file nodes.json --index N --meta-file F [--payload-file F]
                                       -> validated selection metadata/payload

Stdlib only (Python 3.7+).
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import unicodedata
from urllib.parse import urlsplit, unquote, parse_qsl, urlencode, urlunsplit
from proxylib import (dispatch_subcommand, is_non_public_host,
                      nested_too_deep, xray_outbound_servers,
                      shadowsocks_method_password, shadowsocks_engine)
# Network-only modules (ssl, http.client, socket, time, urljoin) are
# imported lazily inside fetch_url()/_https_get()/_public_ips(); the hot local
# subcommands (render/extract/match) never touch the
# network and so avoid that import cost.

# ---- limits ---------------------------------------------------------------
SCHEMA_VERSION = 2         # catalog format version (bump on incompatible change)
MAX_BYTES = 2000000        # 2 MB response cap
MAX_NODES = 1000           # accepted-node cap
MAX_LINES = 100000         # input-line scan cap (independent of accepted nodes)
MAX_LINK = 8000            # per-link byte cap
MAX_REDIRECTS = 3
TIMEOUT = 15               # per-operation socket timeout (seconds)
DEADLINE = 30              # overall wall-clock budget for a fetch (seconds)
LABEL_MAX = 36             # display code points
FIELD_MAX = 80             # generic display field cap
MAX_PROFILE = 200000       # serialized bytes/chars per JSON profile
MAX_JSON_DEPTH = 64
MAX_EXPANSION_RATIO = 500

SUPPORTED = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")

# Characters stripped from any provider-controlled text shown in the terminal:
# C0/DEL/C1 controls, zero-width, bidi embeddings/overrides/isolates, BOM.
_BAD = set(range(0x00, 0x20)) | {0x7f} | set(range(0x80, 0xa0)) | {
    0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
    0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff,
}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")


def die(msg):
    sys.stderr.write("mksub: error: %s\n" % msg)
    sys.exit(2)


def _utf8_stdout():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _b64(text):
    """Decode possibly-unpadded url/standard base64; None on failure."""
    s = "".join(text.split())
    if any(ch not in _B64_ALPHABET for ch in s):
        return None
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, altchars=b"-_", validate=True).decode("utf-8", "replace")
    except Exception:
        return None


_CP1252_MOJIBAKE_CHARS = set(
    "\u20ac\u201a\u0192\u201e\u2026\u2020\u2021\u02c6\u2030\u0160"
    "\u2039\u0152\u017D\u2018\u2019\u201C\u201D\u2022\u2013\u2014"
    "\u02dc\u2122\u0161\u203A\u0153\u017E\u0178")


def _repair_mojibake(value):
    """Repair only high-confidence UTF-8 mojibake.

    Providers and terminals commonly corrupt UTF-8 either as ISO-8859-1
    (``ð\x9f...``) or Windows-1252 (``ðŸ...``). Legitimate Latin text must
    survive, so reversal is attempted only when common mojibake markers are
    present and the decoded result has a strong Unicode signal while removing
    those markers.
    """
    markers = ("Ã", "Â", "ð", "â", "Ð", "Ñ", "Ÿ", "‡", "€", "œ")
    if not any(x in value for x in markers):
        return value

    def repair_part(part):
        if not any(x in part for x in markers):
            return part
        old_markers = sum(part.count(x) for x in markers)
        for enc in ("latin-1", "cp1252"):
            try:
                candidate = part.encode(enc).decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            new_markers = sum(candidate.count(x) for x in markers)
            strong = any(ord(ch) > 0x2FF for ch in candidate)
            if strong and new_markers < old_markers:
                return candidate
        return part

    def flush(buf, out):
        if buf:
            out.append(repair_part("".join(buf)))
            del buf[:]

    repaired = repair_part(value)
    if repaired != value:
        return repaired
    out, buf = [], []
    for ch in value:
        if ord(ch) <= 0xff or ch in _CP1252_MOJIBAKE_CHARS:
            buf.append(ch)
        else:
            flush(buf, out)
            out.append(ch)
    flush(buf, out)
    return "".join(out)


def _display_width(ch):
    if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    o = ord(ch)
    if 0x1F000 <= o <= 0x1FAFF or 0x2600 <= o <= 0x27BF:
        return 2
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _terminal_emoji_fallback(value):
    """Avoid mojibake in terminals that cannot render 4-byte UTF-8 emoji.

    UniFi/web SSH terminals commonly render BMP Unicode correctly (Cyrillic,
    arrows, hourglass, star) but corrupt supplementary-plane symbols such as
    regional-indicator flags and newer Wi-Fi emoji. Keep stored labels intact;
    this is display-only and opt-in via PROXY_UNIFI_TERMINAL_SAFE_EMOJI=1.
    """
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        code = ord(ch)
        if 0x1F1E6 <= code <= 0x1F1FF and i + 1 < len(value):
            nxt = value[i + 1]
            ncode = ord(nxt)
            if 0x1F1E6 <= ncode <= 0x1F1FF:
                country = chr(ord("A") + code - 0x1F1E6) \
                    + chr(ord("A") + ncode - 0x1F1E6)
                out.append("[%s] " % country)
                i += 2
                continue
        if ch in ("\U0001f6dc", "\U0001f4f6"):
            out.append("Wi-Fi ")
        elif code > 0xFFFF:
            out.append("")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def clean(s, maxlen=FIELD_MAX):
    """Return terminal-safe Unicode while preserving letters and emoji."""
    if not s:
        return ""
    value = unicodedata.normalize("NFC", _repair_mojibake(str(s)))
    if os.environ.get("PROXY_UNIFI_TERMINAL_SAFE_EMOJI") == "1":
        value = _terminal_emoji_fallback(value)
    value = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", value)
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    out = []
    for ch in value:
        o = ord(ch)
        if o in _BAD or unicodedata.category(ch) in ("Cc", "Cs"):
            continue
        out.append(" " if ch in ("\t", "\n", "\r") else ch)
    r = " ".join("".join(out).split())
    rendered = []
    width = 0
    for ch in r:
        w = _display_width(ch)
        if width + w > maxlen:
            while rendered and width + 1 > maxlen:
                removed = rendered.pop()
                width -= _display_width(removed)
            return "".join(rendered).rstrip() + "…"
        rendered.append(ch)
        width += w
    return "".join(rendered)


# ---- per-protocol shallow extraction --------------------------------------
def _host_port(u):
    try:
        return u.hostname, u.port
    except ValueError:
        return None, None


def _legacy_vmess(link, scheme):
    """Return (is_legacy, decoded_dict_or_none) without decoding twice."""
    if scheme != "vmess":
        return False, None
    body = link[len("vmess://"):].split("#", 1)[0]
    if "@" in body:
        return False, None
    decoded = _b64(body)
    if not decoded:
        return True, None
    try:
        value = json.loads(decoded)
    except (TypeError, ValueError):
        return True, None
    return True, value if isinstance(value, dict) else None


def _link_details(parsed, scheme, legacy_vmess):
    """Return (label, host, display-server), decoding legacy forms only once."""
    is_legacy, value = legacy_vmess
    if is_legacy:
        if value is None:
            return "", "", ""
        h, p = str(value.get("add", "")), value.get("port", "")
        label = str(value.get("ps", ""))
        return label, h, ("%s:%s" % (h, p) if h else "")
    if scheme == "ss":
        if parsed is None:
            return "", "", ""
        h, p = _host_port(parsed)
        label = unquote(parsed.fragment) if parsed.fragment else ""
        if h and p and parsed.username is not None:
            return label, h, "%s:%s" % (h, p)
        dec = _b64(parsed.netloc)
        if dec and "@" in dec:
            hostport = dec.rsplit("@", 1)[1]
            if hostport.startswith("[") and "]:" in hostport:
                h, p = hostport[1:].rsplit("]:", 1)
            elif ":" in hostport:
                h, p = hostport.rsplit(":", 1)
            else:
                return "", "", ""
            return label, h, "%s:%s" % (h, p)
        return "", "", ""
    # URI form (vless/vmess-AEAD/trojan/ss/hysteria2/tuic)
    if parsed is None:
        return "", "", ""
    h, p = _host_port(parsed)
    if not h:
        return "", "", ""
    label = unquote(parsed.fragment) if parsed.fragment else ""
    return label, h, ("%s:%s" % (h, p) if p else h)


def _canonical_link(link, parsed, legacy_vmess):
    """Canonical subscription row identity.

    The URI fragment / VMess ``ps`` name is intentionally included. Providers
    sometimes publish several selectable rows with the same dial target but
    different labels; clients show those as separate nodes, so proxy-unifi must
    not collapse them as duplicates.
    """
    try:
        is_legacy, value = legacy_vmess
        if is_legacy:
            if isinstance(value, dict):
                value = dict(value)
                return "vmess://" + json.dumps(
                    value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            return link
        if parsed is None:
            return link
        u = parsed
        pairs = parse_qsl(u.query, keep_blank_values=True)
        # Duplicate parameters are ambiguous and the generator rejects them.
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            return link
        query = urlencode(sorted(pairs), doseq=True)
        fragment = unquote(u.fragment) if u.fragment else ""
        # A legacy SS authority is case-sensitive base64, not a hostname.
        if u.scheme.lower() == "ss" and u.username is None:
            netloc = u.netloc
            return urlunsplit((u.scheme.lower(), netloc, u.path, query, fragment))
        host = (u.hostname or "").lower()
        if ":" in host and not host.startswith("["):
            host = "[" + host + "]"
        userinfo = ""
        if u.username is not None:
            userinfo = u.username
            if u.password is not None:
                userinfo += ":" + u.password
            userinfo += "@"
        netloc = userinfo + host
        if u.port is not None:
            netloc += ":%d" % u.port
        return urlunsplit((u.scheme.lower(), netloc, u.path, query, fragment))
    except (TypeError, ValueError):
        return link


def _ss_engine(parsed):
    """(engine, reason, variant) mirroring direct-import engine routing."""
    if parsed is None:
        return "", "unparseable link", ""
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
    except ValueError:
        return "", "malformed query string", ""
    keys = [key for key, _value in pairs]
    if len(keys) != len(set(keys)):
        return "", "duplicate query parameter", ""
    if any(key != "plugin" for key in keys):
        return "", "unsupported Shadowsocks query parameter", ""
    plugin = ""
    for key, value in pairs:
        if key == "plugin" and value:
            plugin = unquote(value).split(";", 1)[0]
    method, password = shadowsocks_method_password(parsed)
    if not method or not password:
        return "", "unparseable Shadowsocks credentials", ""
    return shadowsocks_engine(method, password, plugin)


def _profile_catalog_node(prof, label_hint="", identity_salt="",
                          prefer_label_hint=False):
    """Build one selectable catalog node from an Xray JSON profile dict."""
    if not isinstance(prof, dict):
        return None
    if nested_too_deep(prof, MAX_JSON_DEPTH):
        return None
    raw_json = json.dumps(prof, ensure_ascii=False, separators=(",", ":"))
    if len(raw_json) > MAX_PROFILE:
        return None
    identity = dict(prof)
    canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"))
    if identity_salt:
        canonical += "\0" + identity_salt
    remarks = prof.get("remarks")
    profile_label = remarks if isinstance(remarks, str) else ""
    if prefer_label_hint and label_hint:
        label = label_hint
    else:
        label = profile_label or label_hint
    recognized, reason, members, strat, _ = _classify_profile(prof)
    return {
        "kind": "pool", "scheme": "json", "label": label,
        "server": ("%d nodes, %s" % (members, strat)) if members else "profile",
        "recognized": recognized, "engine": "xraypool", "reason": reason,
        "members": members, "strategy": strat,
        "id": hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest(),
        "profile": raw_json,
    }


def _json_profile_from_text(text):
    text = text.strip()
    if text[:1] not in ("{", "["):
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
        return data[0]
    return None


def _profile_text_candidates(value):
    if value in (None, ""):
        return []
    raw = unquote(str(value)).strip()
    if not raw:
        return []
    out = [raw]
    first = _b64(raw)
    if first:
        out.append(first.strip())
        second = _b64(first)
        if second:
            out.append(second.strip())
    return out


def _json_profile_from_ss_wrapper(link, parsed, label_hint):
    """Detect subscription rows that disguise an Xray profile as ss://.

    Some providers emit ``ss://payload@host:port#name`` wrappers where the
    payload is an encoded Xray JSON profile. Treating those rows as ordinary
    Shadowsocks makes selection import the wrong thing, so probe only fields
    that can legally carry opaque credentials and require valid profile JSON.
    """
    if parsed is None:
        return None
    fields = [parsed.username, parsed.password, parsed.path.lstrip("/")]
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key in ("profile", "config", "json", "payload", "data", "link"):
            fields.append(value)
    decoded_legacy = _b64(parsed.netloc)
    if decoded_legacy:
        fields.append(decoded_legacy)
        credentials = decoded_legacy.rsplit("@", 1)[0]
        fields.append(credentials)
        if ":" in credentials:
            fields.append(credentials.split(":", 1)[1])
    seen = set()
    for field in fields:
        for text in _profile_text_candidates(field):
            if text in seen:
                continue
            seen.add(text)
            prof = _json_profile_from_text(text)
            if prof is None:
                continue
            return _profile_catalog_node(prof, label_hint, link, True)
    return None


def node_from_link(link):
    """Return a node dict for a recognized proxy URI, or None to skip the line.

    'recognized' means the scheme is one we handle and we could read a server;
    it is NOT a guarantee the installed core accepts every option (that is only
    proven at selection time, where cmd_import runs the real core's -test)."""
    link = link.strip()
    if "://" not in link:
        return None
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SUPPORTED:
        return None
    if len(link.encode("utf-8", "replace")) > MAX_LINK:
        return None
    # Reject control bytes / NUL so the stored link can't differ from what the
    # shell later activates (shell command-substitution silently drops NUL).
    if _CONTROL_RE.search(link):
        return None
    # normalize the scheme casing so the stored/activated link matches what the
    # (case-sensitive) shell import accepts.
    link = scheme + link[len(scheme):]
    legacy_vmess = _legacy_vmess(link, scheme)
    if legacy_vmess[0]:
        parsed = None
    else:
        try:
            parsed = urlsplit(link)
        except ValueError:
            parsed = None
    if scheme == "ss":
        label = ""
        if parsed is not None and parsed.fragment:
            label = unquote(parsed.fragment)
        profile_node = _json_profile_from_ss_wrapper(link, parsed, label)
        if profile_node is not None:
            return profile_node
    node = {"scheme": scheme, "variant": "", "link": link, "label": "",
            "server": "", "recognized": True, "engine": "", "reason": ""}
    try:
        node["label"], destination, node["server"] = _link_details(
            parsed, scheme, legacy_vmess)
        if scheme in ("hysteria2", "hy2", "tuic"):
            node["engine"] = "singbox"
        elif scheme == "ss":
            eng, reason, variant = _ss_engine(parsed)
            node["engine"] = eng
            node["variant"] = variant
            if not eng:
                node["recognized"] = False
                node["reason"] = reason
            elif reason:
                node["reason"] = reason
        else:  # vless / vmess / trojan
            node["engine"] = "xray"
        if node["recognized"] and not node["server"]:
            node["recognized"] = False
            node["reason"] = "could not parse server host/port"
        # providers return a 0.0.0.0 placeholder ("App not supported" /
        # "Limit of devices reached") to unauthorized clients -- flag it clearly
        # instead of offering a dead node.
        if node["recognized"] and is_non_public_host(destination):
            node["recognized"] = False
            node["reason"] = "non-public provider destination (%s)" % (
                clean(node["label"], 40) or destination or "not authorized")
    except Exception:
        node["recognized"] = False
        node["reason"] = "unparseable node"
    # stable id: full sha256 of the canonical link, including display identity
    canonical = _canonical_link(link, parsed, legacy_vmess)
    node["id"] = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
    return node


def _meta_from_headers(headers):
    meta = {}
    if headers:
        iv = str(headers.get("profile-update-interval", "")).strip()
        if iv and len(iv) <= 6 and iv.isdigit():
            hours = int(iv)
            if 1 <= hours <= 8760:
                meta["interval_hours"] = hours
        ui = headers.get("subscription-userinfo")
        if ui:
            meta["userinfo"] = clean(str(ui), 200)
    return meta


def _process_json(text, headers):
    """A JSON subscription: one Xray balancer/pool profile (object) or several
    (array), as Remnawave serves to recognized HWID clients. Each profile becomes
    a selectable 'pool' catalog node carrying its own raw JSON."""
    try:
        data = json.loads(text)
    except Exception:
        die("subscription JSON could not be parsed")
    profiles = data if isinstance(data, list) else [data]
    nodes = []
    seen = set()
    for prof in profiles:
        if len(nodes) >= MAX_NODES:
            break
        if not isinstance(prof, dict):
            continue
        if nested_too_deep(prof, MAX_JSON_DEPTH):
            continue
        raw_json = json.dumps(prof, ensure_ascii=False, separators=(",", ":"))
        if len(raw_json) > MAX_PROFILE:
            continue
        identity = dict(prof)
        canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"))
        nid = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
        if nid in seen:
            continue
        seen.add(nid)
        label = prof.get("remarks") if isinstance(prof.get("remarks"), str) else ""
        # classify + count balancer members; reject profiles we can't host
        recognized, reason, members, strat, _ = _classify_profile(prof)
        nodes.append({
            "kind": "pool", "scheme": "json", "label": label,
            "server": ("%d nodes, %s" % (members, strat)) if members else "profile",
            "recognized": recognized, "engine": "xraypool", "reason": reason,
            "members": members, "strategy": strat,
            "id": nid, "profile": raw_json,
        })
    for n, nd in enumerate(nodes, 1):
        nd["n"] = n
    if not nodes:
        die("subscription JSON contained no usable profiles")
    supported = sum(1 for node in nodes if node["recognized"])
    if supported == 0:
        die("subscription JSON has no supported profiles")
    meta = {"count": len(nodes), "supported": supported, "format": "json"}
    meta.update(_meta_from_headers(headers))
    return {"schema": SCHEMA_VERSION, "meta": meta, "nodes": nodes}


def _classify_profile(prof):
    """(recognized, reason, members, strategy, servers) for an Xray JSON profile.
    A profile is unrecognized if it has no outbounds, or its only proxy server is
    the provider's 'App not supported' 0.0.0.0 placeholder, or it relies on
    source/SOCKS-auth routing a WireGuard inbound can't reproduce."""
    outs = prof.get("outbounds")
    if not isinstance(outs, list) or not outs:
        return False, "no outbounds", 0, "", []
    if len(outs) > 256:
        return False, "too many outbounds", 0, "", []
    servers = []
    for o in outs:
        if not isinstance(o, dict):
            continue
        servers.extend(host for host, _port in xray_outbound_servers(o))
    for server in servers:
        if _CONTROL_RE.search(server):
            return False, "server contains control characters", 0, "", servers
        if is_non_public_host(server):
            return False, "non-public/placeholder provider destinations", 0, "", servers
    if not servers:
        return False, "no supported proxy servers", 0, "", servers
    # source/user routing can't be reproduced by a WireGuard inbound
    routing = prof.get("routing", {})
    rules = routing.get("rules", []) if isinstance(routing, dict) else []
    if not isinstance(rules, list):
        return False, "routing.rules must be an array", 0, "", servers
    for r in rules:
        if isinstance(r, dict) and (r.get("user") or r.get("source") or r.get("sourcePort")):
            return False, "routing needs source/user identity", 0, "", servers
    bals = routing.get("balancers") if isinstance(routing, dict) else None
    members, strategies = 0, []
    if bals is not None and not isinstance(bals, list):
        return False, "routing.balancers must be an array", 0, "", servers
    if isinstance(bals, list) and len(bals) > 64:
        return False, "too many balancers", 0, "", servers
    tags = [str(o.get("tag", "")) for o in outs if isinstance(o, dict)]
    for bal in bals or []:
        if not isinstance(bal, dict):
            return False, "malformed balancer", 0, "", servers
        sels = bal.get("selector", [])
        if not isinstance(sels, list) or not all(isinstance(s, str) for s in sels):
            return False, "balancer selector must be an array of strings", 0, "", servers
        members += sum(1 for tag in tags if any(tag.startswith(s) for s in sels))
        strategy = bal.get("strategy")
        if isinstance(strategy, dict) and strategy.get("type"):
            strategies.append(str(strategy["type"]))
    if not bals:
        members = len(servers)
    direct_bypass = False
    for bal in bals or []:
        if isinstance(bal, dict) and bal.get("fallbackTag") == "direct":
            direct_bypass = True
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outboundTag") == "direct":
            direct_bypass = True
    warning = "provider routing permits direct bypass" if direct_bypass else ""
    return True, warning, members, ",".join(dict.fromkeys(strategies)) or "single", servers


def process_body(raw, headers=None):
    text = raw.decode("utf-8", "replace").strip()
    head = text[:200].lstrip().lower()
    if head[:1] == "<" or "<html" in head or "<!doctype" in head:
        die("the URL returned an HTML page, not a subscription")
    # JSON profile(s) -- a Remnawave/Happ-style Xray balancer feed (object or array).
    if head[:1] in ("{", "["):
        return _process_json(text, headers)
    if "://" not in text:
        dec = _b64(text)
        if not dec or "://" not in dec:
            # base64 may also wrap a JSON profile feed
            if dec and dec.lstrip()[:1] in ("{", "["):
                return _process_json(dec, headers)
            die("could not decode subscription (not a base64 / plain link list)")
        text = dec
        if dec.lstrip()[:1] in ("{", "["):
            return _process_json(dec, headers)
    nodes = []
    seen_ids = set()
    for i, line in enumerate(text.splitlines()):
        if i >= MAX_LINES or len(nodes) >= MAX_NODES:
            break
        nd = node_from_link(line)
        if not nd:
            continue
        if nd["id"] in seen_ids:        # drop exact duplicates
            continue
        seen_ids.add(nd["id"])
        nodes.append(nd)
    for n, nd in enumerate(nodes, 1):
        nd["n"] = n
    supported = sum(1 for x in nodes if x["recognized"])
    if not nodes:
        die("subscription contained no proxy links")
    if supported == 0:
        die("subscription has no supported nodes (all unrecognized)")
    meta = {"count": len(nodes), "supported": supported, "format": "links"}
    meta.update(_meta_from_headers(headers))
    return {"schema": SCHEMA_VERSION, "meta": meta, "nodes": nodes}


# ---- network (SSRF-safe, DNS-rebinding-safe) ------------------------------
def _norm_origin(u):
    """(scheme, host, port) with default ports normalized so a redirect to an
    explicit :443 from an implicit one is still treated as same-origin."""
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    port = u.port if u.port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, port)


def _validate_fetch_url(url):
    if not isinstance(url, str) or not url \
            or len(url.encode("utf-8", "replace")) > MAX_LINK:
        die("subscription URL is empty or too long")
    if _CONTROL_RE.search(url):
        die("subscription URL contains control characters")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError:
        die("malformed subscription URL")
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        die("only https:// subscription URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        die("credentials in subscription URL authority are not supported")
    if parsed.fragment:
        die("subscription URL fragments are not supported")
    return parsed


def _validate_header_value(value, label, maximum):
    if not isinstance(value, str) or len(value) > maximum \
            or _CONTROL_RE.search(value) or any(ord(ch) < 0x20 or ord(ch) > 0x7e
                                                for ch in value):
        die("%s must contain printable ASCII only" % label)
    return value


def _idna_host(host):
    """ASCII host suitable for a Host header / SNI; encode IDN names, else die."""
    try:
        host.encode("ascii")
        return host
    except UnicodeEncodeError:
        try:
            return host.encode("idna").decode("ascii")
        except Exception:
            die("subscription host is not a valid domain name")


def _net():
    """Import and return the network-only stdlib modules on first use, so the
    purely-local subcommands never pay for them. Cached on the function object."""
    if not hasattr(_net, "_m"):
        import http.client
        import socket
        import ssl
        import time
        from urllib.parse import urljoin
        _net._m = (socket, ssl, http.client, time, urljoin)
    return _net._m


def _public_ips(host, deadline=None):
    """All validated public IPs for host (every resolved address), or die. A
    non-global/special-purpose address anywhere in the result set is rejected
    (CGNAT, private, loopback, link-local, reserved, multicast, etc.)."""
    socket, _ssl, _hc, _t, _uj = _net()
    # PROXY_UNIFI_SUB_ALLOW_PRIVATE=1 disables the SSRF guard (tests only).
    allow_private = os.environ.get("PROXY_UNIFI_SUB_ALLOW_PRIVATE") == "1"
    if deadline is None:
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except Exception as e:
            die("could not resolve host: %s" % e)
    else:
        # getaddrinfo has no portable timeout. Resolve in a daemon thread and
        # bound how long the fetch waits; a wedged libc resolver cannot hold the
        # subscription worker past its global deadline.
        import queue
        import threading
        result = queue.Queue(maxsize=1)

        def resolve():
            try:
                result.put((socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP), None))
            except Exception as exc:
                result.put((None, exc))
        thread = threading.Thread(target=resolve)
        thread.daemon = True
        thread.start()
        thread.join(_remaining(deadline))
        if thread.is_alive():
            die("DNS resolution exceeded the subscription time budget")
        infos, resolve_error = result.get_nowait()
        if resolve_error is not None:
            die("could not resolve host: %s" % resolve_error)
    out = []
    seen = set()
    for info in infos:
        fam, addr = info[0], info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        ip = ipaddress.ip_address(addr)
        if not allow_private and not ip.is_global:
            die("refusing to fetch: %s resolves to a non-public address" % host)
        out.append((fam, info[4]))
    if not out:
        die("host did not resolve to any address")
    return out


def _remaining(deadline):
    _s, _ssl, _hc, time, _uj = _net()
    r = deadline - time.monotonic()
    if r <= 0:
        die("subscription request exceeded the time budget")
    return min(r, TIMEOUT)


def _https_get(url, send_hwid, hwid, ua, deadline):
    """One HTTPS GET. Tries every validated address (mixed IPv4/IPv6 safe). Each
    blocking op uses the remaining overall budget. Returns headers, body (or
    None for redirects), and the redirect location."""
    socket, ssl, http_client, _t, _uj = _net()
    u = _validate_fetch_url(url)
    host = u.hostname
    if not host:
        die("subscription URL has no host")
    port = u.port or 443
    sni = _idna_host(host)
    ctx = ssl.create_default_context()

    # connect+TLS to the first address that works (within the shared deadline)
    tls = None
    last_err = "no address"
    for family, sockaddr in _public_ips(host, deadline):
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(_remaining(deadline))
            raw.connect(sockaddr[:1] + (port,) + sockaddr[2:])
        except OSError as e:
            raw.close()
            last_err = str(e)
            continue
        try:
            raw.settimeout(_remaining(deadline))
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            break
        except (ssl.SSLError, OSError) as e:
            raw.close()
            tls = None
            last_err = str(e)
            continue
    if tls is None:
        die("could not connect to subscription host: %s" % last_err)

    try:
        tls.settimeout(_remaining(deadline))
        conn = http_client.HTTPConnection(sni, port, timeout=_remaining(deadline))
        conn.sock = tls  # noqa - HTTPConnection consumes this pinned TLS socket internally.
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        # RFC-correct Host header: include port if non-default, bracket IPv6
        hostport = sni
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                hostport = "[%s]" % host
        except ValueError:
            pass
        if port != 443:
            hostport = "%s:%d" % (hostport, port)
        hdrs = {"Host": hostport,
                "User-Agent": _validate_header_value(ua, "User-Agent", 120),
                "Accept": "*/*", "Connection": "close"}
        if send_hwid and hwid:
            hdrs["x-hwid"] = _validate_header_value(hwid, "HWID", 128)
        try:
            conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
        except (http_client.HTTPException, OSError) as e:
            die("HTTP request failed: %s" % e)
        status = resp.status
        rheaders = {k.lower(): v for k, v in resp.getheaders()}
        if status in (301, 302, 303, 307, 308):
            return rheaders, None, rheaders.get("location")
        if status != 200:
            die("HTTP error %s from subscription server" % status)
        content_length = rheaders.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_BYTES:
                    die("subscription too large (> %d compressed bytes)" % MAX_BYTES)
            except ValueError:
                die("invalid Content-Length from subscription server")
        body = bytearray()
        while True:
            try:
                tls.settimeout(_remaining(deadline))
                # read1 returns after one buffered/socket read and still handles
                # chunked framing, allowing the deadline to be checked per chunk.
                chunk = resp.read1(min(65536, MAX_BYTES + 1 - len(body)))
            except (http_client.HTTPException, OSError) as e:
                die("error reading subscription body: %s" % e)
            _remaining(deadline)
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                die("subscription too large (> %d compressed bytes)" % MAX_BYTES)
        body = bytes(body)
        enc = (rheaders.get("content-encoding") or "").strip().lower()
        if enc == "gzip":
            body = _decompress_limited(body, "gzip")
        elif enc == "deflate":
            body = _decompress_limited(body, "deflate")
        elif enc and enc != "identity":
            die("unsupported Content-Encoding '%s'" % clean(enc, 40))
        if len(body) > MAX_BYTES:
            die("subscription too large after decompression (> %d bytes)" % MAX_BYTES)
        return rheaders, body, None
    finally:
        try:
            tls.close()
        except Exception:
            pass


def _inflate(data, wbits):
    import zlib
    decoder = zlib.decompressobj(wbits)
    output = bytearray()
    for offset in range(0, len(data), 65536):
        pending = data[offset:offset + 65536]
        while pending:
            room = MAX_BYTES + 1 - len(output)
            if room <= 0:
                die("subscription too large after decompression (> %d bytes)" % MAX_BYTES)
            output.extend(decoder.decompress(pending, room))
            pending = decoder.unconsumed_tail
            if len(output) > MAX_BYTES:
                die("subscription too large after decompression (> %d bytes)" % MAX_BYTES)
    room = MAX_BYTES + 1 - len(output)
    output.extend(decoder.flush(max(1, room)))
    if len(output) > MAX_BYTES:
        die("subscription too large after decompression (> %d bytes)" % MAX_BYTES)
    if not decoder.eof or decoder.unused_data:
        die("compressed subscription has trailing or incomplete data")
    if data and len(output) > len(data) * MAX_EXPANSION_RATIO:
        die("compressed subscription exceeds the expansion-ratio limit")
    return bytes(output)


def _decompress_limited(data, encoding):
    import zlib
    try:
        if encoding == "gzip":
            return _inflate(data, 16 + zlib.MAX_WBITS)
        try:
            return _inflate(data, zlib.MAX_WBITS)
        except zlib.error:
            return _inflate(data, -zlib.MAX_WBITS)
    except SystemExit:
        raise
    except Exception:
        die("could not decompress %s subscription body" % encoding)


def fetch_url(url, hwid, ua):
    _s, _ssl, _hc, time, urljoin = _net()
    deadline = time.monotonic() + DEADLINE
    try:
        origin = _norm_origin(_validate_fetch_url(url))
    except ValueError:
        die("malformed subscription URL")
    cur = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            same_origin = _norm_origin(urlsplit(cur)) == origin
        except ValueError:
            die("malformed redirect URL")
        headers, body, loc = _https_get(
            cur, same_origin, hwid, ua, deadline)
        if body is not None:
            return body, headers
        if not loc:
            die("redirect without a Location header")
        cur = urljoin(cur, loc)
    die("too many redirects")


# ---- subcommands ----------------------------------------------------------
def _read_secret(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception as e:
        die("could not read %s: %s" % (path, e))


def cmd_fetch(args):
    if args.body_file:                         # test hook: skip the network
        with open(args.body_file, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            die("body too large")
        headers = None
    else:
        url = _read_secret(args.url_file) if args.url_file else args.url
        if not url:
            die("fetch needs --url-file/--url (or --body-file)")
        hwid = _read_secret(args.hwid_file) if args.hwid_file else args.hwid
        raw, headers = fetch_url(url, hwid, args.ua)
    # ensure_ascii=True: the on-disk catalog stays pure ASCII (\uXXXX escapes),
    # so stored text (Cyrillic / CJK labels, ...) survives being written and read
    # back regardless of the gateway's locale / stream encoding.
    json.dump(process_body(raw, headers), sys.stdout, ensure_ascii=True, indent=2)
    sys.stdout.write("\n")


_HEX64 = set("0123456789abcdef")


def _validate_node(nd):
    """Validate one catalog node's shape, or die. Returns the node."""
    if not isinstance(nd, dict):
        die("catalog has a malformed node (not an object)")
    nid = nd.get("id")
    if not (isinstance(nid, str) and len(nid) == 64 and all(c in _HEX64 for c in nid)):
        die("catalog node has an invalid id")
    if not isinstance(nd.get("n"), int) or nd["n"] < 1:
        die("catalog node has an invalid index")
    if not isinstance(nd.get("recognized"), bool):
        die("catalog node has an invalid 'recognized' flag")
    sch = nd.get("scheme")
    if nd.get("kind") == "pool" or sch == "json":
        # a JSON balancer/pool profile node: validate it carries raw profile JSON
        prof = nd.get("profile")
        if not isinstance(prof, str) or not prof.strip() or len(prof) > MAX_PROFILE:
            die("catalog pool node has an invalid profile")
    else:
        if not isinstance(sch, str) or sch not in SUPPORTED:
            die("catalog node has an invalid scheme")
        link = nd.get("link")
        if not isinstance(link, str) or "://" not in link \
                or len(link.encode("utf-8", "replace")) > MAX_LINK:
            die("catalog node has an invalid link")
        if _CONTROL_RE.search(link):
            die("catalog node link contains control characters")
    for f in ("label", "server", "reason", "engine", "variant"):
        if not isinstance(nd.get(f, ""), str):
            die("catalog node field '%s' is not a string" % f)
    return nd


def _migrate(cat):
    """Bring an older catalog up to the current schema, or return None if it
    cannot be migrated safely (caller then forces a refresh)."""
    nodes = cat.get("nodes")
    if not isinstance(nodes, list):
        return None
    # schema 1 (pre-versioning): had 'supported' instead of 'recognized', short
    # 8-char ids, and no 'schema' key. We can't reconstruct full-hash ids from the
    # old short ones, so a stored selection won't match -> force a refresh.
    if cat.get("schema") != SCHEMA_VERSION:
        return None
    return cat


def _load(path):
    try:
        if os.path.getsize(path) > MAX_BYTES * 8:
            die("catalog is too large")
        with open(path, "r", encoding="utf-8") as fh:
            cat = json.load(fh)
    except Exception as e:
        die("could not read catalog: %s" % e)
    if not isinstance(cat, dict) or not isinstance(cat.get("nodes"), list):
        die("catalog is malformed")
    if _migrate(cat) is None:
        die("subscription catalog is from an older version; run a refresh "
            "(menu -> Import or replace -> subscription -> Refresh)")
    seen_n = set()
    seen_id = set()
    for nd in cat["nodes"]:
        _validate_node(nd)
        if nd["n"] in seen_n:
            die("catalog has a duplicate node index")
        if nd["id"] in seen_id:
            die("catalog has a duplicate node id")
        seen_n.add(nd["n"])
        seen_id.add(nd["id"])
    return cat


def cmd_render(args):
    cat = _load(args.file)
    nodes = cat.get("nodes", [])
    if not nodes:
        print("(no nodes in subscription)")
        return
    selected = getattr(args, "selected", "") or ""
    for nd in nodes:
        if not nd.get("recognized"):
            mark = "x"
        elif selected and nd.get("id") == selected:
            mark = "*"
        else:
            mark = " "
        label = clean(nd.get("label", ""), LABEL_MAX) or "(no label)"
        server = clean(nd.get("server", "?"), 40)
        scheme = "ss2022" if nd.get("scheme") == "ss" \
            and nd.get("variant") == "2022" else clean(nd.get("scheme", "?"), 12)
        line = "%3d. [%s] %-9s %-24s %s" % (
            nd.get("n", 0), mark, scheme, server, label)
        if nd.get("reason"):
            prefix = "warning: " if nd.get("recognized") else ""
            line += "  (%s%s)" % (prefix, clean(nd["reason"], 60))
        print(line)


def _selection_meta(nd):
    scheme = nd.get("scheme", "")
    if scheme == "ss" and nd.get("variant") == "2022":
        scheme = "ss2022"
    return {
        "schema": 1,
        "id": nd.get("id", ""),
        "n": nd.get("n", 0),
        "kind": "pool" if (nd.get("kind") == "pool" or nd.get("scheme") == "json") else "link",
        "scheme": scheme,
        "label": nd.get("label", ""),
        "server": nd.get("server", ""),
    }


def _atomic_write_text(path, text):
    directory = os.path.dirname(path) or "."
    fd = -1
    temporary = ""
    try:
        os.makedirs(directory, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".write.", dir=directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            fd = -1
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(directory, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as e:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        die("could not write selection output: %s" % e)


def _write_selection_meta(nd, path):
    payload = json.dumps(_selection_meta(nd), ensure_ascii=True, sort_keys=True) + "\n"
    _atomic_write_text(path, payload)


def _migrate_selection_scheme(old, active_link_file):
    """Identify pre-SS2022 metadata without weakening refresh matching.

    Older releases recorded every Shadowsocks selection as ``ss``. Only migrate
    that marker when the active link is itself a recognized SS2022 node and its
    full identity matches the stored selection. A legacy SS link can therefore
    never become an SS2022 match merely because labels coincide.
    """
    if old.get("scheme") != "ss" or not active_link_file:
        return old
    try:
        with open(active_link_file, "r", encoding="utf-8") as fh:
            active_link = fh.read(MAX_LINK + 1).strip()
        if not active_link or len(active_link.encode("utf-8", "replace")) > MAX_LINK:
            return old
        active = node_from_link(active_link)
    except (OSError, UnicodeError):
        return old
    if not active or not active.get("recognized") or active.get("variant") != "2022" \
            or active.get("id") != old.get("id"):
        return old
    migrated = dict(old)
    migrated["scheme"] = "ss2022"
    return migrated


def cmd_extract(args):
    cat = _load(args.file)
    nd = next((node for node in cat.get("nodes", []) if node.get("n") == args.index), None)
    if nd is None:
        die("no node #%d in subscription" % args.index)
    kind = "pool" if (nd.get("kind") == "pool" or nd.get("scheme") == "json") else "link"
    sys.stdout.write("%s\t%s\t%s\t%s\n" % (
        nd.get("id", ""), "1" if nd.get("recognized") else "0",
        clean(nd.get("reason", ""), 60), kind))
    if not nd.get("recognized"):
        return
    try:
        _write_selection_meta(nd, args.meta_file)
        if args.payload_file:
            payload = nd.get("profile", "") if kind == "pool" else nd.get("link", "")
            _atomic_write_text(args.payload_file, payload)
    except OSError as e:
        die("could not write selection output: %s" % e)


def cmd_match(args):
    """Find one safe refresh replacement for a persisted selection.

    Exact content identity always wins. Otherwise require a unique strong match;
    ambiguity leaves the active tunnel unchanged instead of switching nodes.
    """
    cat = _load(args.file)
    try:
        with open(args.selection_file, "r", encoding="utf-8") as fh:
            old = json.load(fh)
    except Exception as e:
        die("could not read selection metadata: %s" % e)
    if not isinstance(old, dict):
        die("selection metadata is malformed")
    old = _migrate_selection_scheme(old, getattr(args, "active_link_file", ""))
    best_score = -1
    best_node = None
    best_count = 0
    for nd in cat.get("nodes", []):
        if not nd.get("recognized"):
            continue
        if nd.get("id") == old.get("id"):
            if args.meta_file:
                _write_selection_meta(nd, args.meta_file)
            sys.stdout.write("%s\t%s\t100\n" % (nd["n"], nd["id"]))
            return
        meta = _selection_meta(nd)
        if meta["kind"] != old.get("kind") or meta["scheme"] != old.get("scheme"):
            continue
        score = 30
        if meta["label"] and meta["label"] == old.get("label"):
            score += 40
        if meta["server"] and meta["server"] == old.get("server"):
            score += 30
        if meta["n"] == old.get("n"):
            score += 5
        if score > best_score:
            best_score, best_node, best_count = score, nd, 1
        elif score == best_score:
            best_count += 1
    if best_score < 70 or best_count != 1:
        sys.exit(1)
    nd = best_node
    if args.meta_file:
        _write_selection_meta(nd, args.meta_file)
    sys.stdout.write("%s\t%s\t%s\n" % (nd["n"], nd["id"], best_score))


def main():
    _utf8_stdout()
    ap = argparse.ArgumentParser(description="proxy-unifi subscription helper")
    sub = ap.add_subparsers(dest="cmd")

    f = sub.add_parser("fetch")
    f.add_argument("--url", default="")
    f.add_argument("--url-file", default="")
    f.add_argument("--hwid", default="")
    f.add_argument("--hwid-file", default="")
    # Happ/Remnawave-style providers return JSON catalogs only to compatible
    # app User-Agents; callers may still override this for other providers.
    f.add_argument("--ua", default="Happ/2.0")
    f.add_argument("--body-file", default="")
    f.set_defaults(fn=cmd_fetch)

    r = sub.add_parser("render")
    r.add_argument("--file", required=True)
    r.add_argument("--selected", default="")   # id of the active node -> "[*]"
    r.set_defaults(fn=cmd_render)

    extract = sub.add_parser("extract")
    extract.add_argument("--file", required=True)
    extract.add_argument("--index", type=int, required=True)
    extract.add_argument("--meta-file", required=True)
    extract.add_argument("--payload-file", default="")
    extract.set_defaults(fn=cmd_extract)

    mt = sub.add_parser("match")
    mt.add_argument("--file", required=True)
    mt.add_argument("--selection-file", required=True)
    mt.add_argument("--meta-file", default="")
    mt.add_argument("--active-link-file", default="")
    mt.set_defaults(fn=cmd_match)

    dispatch_subcommand(ap)


if __name__ == "__main__":
    main()
