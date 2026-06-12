#!/bin/sh
# shellcheck disable=SC2015  # cmd && ok || bad is intentional; ok()/bad() never fail.
# tests/run.sh - repeatable test suite for proxy-unifi (D28).
#
# Runs three tiers:
#   1. static  - shellcheck + dash -n + python compile on all sources (always).
#   2. parsers - generator/sub/json parsing + fuzz (always; pure Python, no network).
#   3. engine  - real xray-core / sing-box validation of generated configs, and a
#                sandboxed CLI lifecycle (only if the binaries are available; the
#                harness downloads them to a cache the first time when --download).
#
# Usage:
#   tests/run.sh             # static + parser tests (+ engine tests if cached)
#   tests/run.sh --download  # also fetch xray/sing-box into tests/.cache first
#
# Exit non-zero if any test fails. POSIX sh.
# NOTE: no 'set -e' — individual tests are expected to fail without aborting the run.
set -u

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
SRC="$ROOT/src"
CACHE="$ROOT/tests/.cache"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# -------------------------------------------------------------------------
# tier 1: static analysis
# -------------------------------------------------------------------------
static_tests() {
    echo "== static =="
    if have shellcheck; then
        if shellcheck -s sh "$SRC/proxy-unifi" "$SRC/on_boot.sh" "$ROOT/install.sh" "$ROOT/tests/run.sh" >/dev/null 2>&1
        then ok "shellcheck"; else bad "shellcheck"; fi
    else printf '  skip shellcheck (not installed)\n'; fi
    if have dash; then
        _d=0
        for f in "$SRC/proxy-unifi" "$SRC/on_boot.sh" "$ROOT/install.sh"; do
            dash -n "$f" 2>/dev/null || _d=1
        done
        if [ "$_d" = 0 ]; then ok "dash -n"; else bad "dash -n"; fi
    else printf '  skip dash -n (not installed)\n'; fi
    if python3 -m py_compile "$SRC"/mkconfig.py "$SRC"/mksingbox.py "$SRC"/mksub.py "$SRC"/mkjson.py 2>/dev/null
    then ok "python compile"; else bad "python compile"; fi
    rm -rf "$SRC/__pycache__"

    # external-exposure guard: the rendered systemd unit must firewall the
    # sing-box (0.0.0.0) WG port BEFORE it binds, and must NOT firewall xray
    # (loopback-only) -- clearing any stale rule instead.
    _ud="$(mktemp -d)"
    cat > "$_ud/h.sh" <<'SH'
SBIN=/b/sing-box; XRAY=/b/xray; CONFIG=/c/config.json; POOL_DIR=/c/pool
BIN_DIR=/b; ROOT=/r; SERVICE_FILE="$WORK/unit"
current_engine() { echo "$ENG"; }
SH
    awk '/^write_service\(\) \{/,/^}/' "$SRC/proxy-unifi" >> "$_ud/h.sh"
    echo 'write_service' >> "$_ud/h.sh"
    _fw_ok=1
    ENG=singbox  WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStartPre=-/b/proxy-unifi _fw-lock$'  "$_ud/unit" || _fw_ok=0
    grep -q '^ExecStopPost=-/b/proxy-unifi _fw-unlock$' "$_ud/unit" || _fw_ok=0
    ENG=xray     WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStartPre=-/b/proxy-unifi _fw-unlock$' "$_ud/unit" || _fw_ok=0
    grep -q '_fw-lock' "$_ud/unit" && _fw_ok=0          # xray must NOT lock a port
    [ "$_fw_ok" = 1 ] && ok "singbox WG port firewalled (unit)" || bad "singbox WG port firewalled (unit)"
    rm -rf "$_ud"
}

# -------------------------------------------------------------------------
# tier 2: parser tests (no network, no engine)
# -------------------------------------------------------------------------
# expect mkconfig/mksingbox to ACCEPT (exit 0) or REJECT (exit !=0) a link, and
# never emit a Python traceback.
expect() {  # <gen> <link> <accept|reject> <name>
    out="$(python3 "$SRC/$1" --link "$2" --port 51821 --secret-key AAAA --peer-pubkey BBBB 2>&1)"; rc=$?
    if printf '%s' "$out" | grep -q 'Traceback'; then bad "$4 (traceback)"; return; fi
    if [ "$3" = accept ] && [ "$rc" = 0 ]; then ok "$4"
    elif [ "$3" = reject ] && [ "$rc" != 0 ]; then ok "$4"
    else bad "$4 (rc=$rc want $3)"; fi
}

parser_tests() {
    echo "== parsers =="
    KEY=cvttX9u3nd7XD16gF4LJ09KjFZ0ZN4x9nk2TQePX5jk
    VM="vmess://$(printf '{"add":"h","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"ws","tls":"tls","host":"h","path":"/w"}' | base64 | tr -d '\n')"
    # accepted forms
    expect mkconfig.py "vless://u@h:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=$KEY&sid=ab&sni=a&fp=chrome" accept "vless reality"
    expect mkconfig.py "$VM" accept "vmess base64-json"
    expect mkconfig.py "vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?type=ws&security=tls&path=%2Fw&host=a&sni=a" accept "vmess URI form"
    expect mkconfig.py "trojan://pw@h:443?security=tls&sni=a" accept "trojan"
    expect mkconfig.py "ss://$(printf 'aes-256-gcm:pw' | base64 | tr -d '\n')@h:8388" accept "ss plain"
    expect mkconfig.py "vless://u@h:443?type=kcp&security=none" accept "mKCP plain"
    expect mksingbox.py "hysteria2://pw@h:443?sni=h" accept "hysteria2"
    expect mksingbox.py "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?sni=h" accept "tuic"
    expect mksingbox.py "ss://$(printf 'aes-256-gcm:pw' | base64 | tr -d '\n')@h:8388?plugin=obfs-local%3Bobfs%3Dhttp" accept "ss+obfs"
    # rejected forms (security / removed transports / bad input)
    expect mkconfig.py "vless://u@h:443?security=tls&allowInsecure=1&sni=a" reject "allowInsecure rejected"
    expect mkconfig.py "vless://u@h:443?security=tls&type=quic&sni=a" reject "quic rejected"
    expect mkconfig.py "vless://u@h:443?type=kcp&seed=x" reject "mKCP seed rejected"
    expect mkconfig.py "vless://u@-evil:443?security=tls&sni=a" reject "leading-hyphen host"
    expect mkconfig.py "vless://u@h:notaport?security=tls&sni=a" reject "bad port"
    expect mkconfig.py "ss://$(printf 'aes-256-gcm:pw@host:notaport' | base64 | tr -d '\n')" reject "ss legacy bad port"
    expect mkconfig.py "naive+https://x@h:443" reject "unsupported scheme"

    # host injection: ESC byte must be rejected (no traceback)
    out="$(python3 "$SRC/mkconfig.py" --link "$(printf 'vless://u@h\033[2Jx:443?security=tls&sni=a')" --port 51821 --secret-key AAAA --peer-pubkey BBBB 2>&1)" || true
    if printf '%s' "$out" | grep -qi 'control\|unsafe\|malformed'; then ok "ESC host rejected"; else bad "ESC host rejected"; fi

    # mksub: classification + safety (pure python)
    python3 - "$SRC" <<'PY' && ok "mksub parser corpus" || bad "mksub parser corpus"
import sys, base64, json
sys.path.insert(0, sys.argv[1])
import mksub
def body(lines): return base64.b64encode(("\n".join(lines)).encode())
# good list (vless + hysteria2 + unsupported plugin)
cat = mksub.process_body(body([
  "vless://u@h:443#ok",
  "hysteria2://pw@h:443#hy",
  "ss://%s@h:8388?plugin=kcptun#x" % base64.b64encode(b"aes-256-gcm:pw").decode(),
]))
assert cat["schema"] == 2, cat
assert cat["meta"]["count"] == 3, cat
assert cat["meta"]["supported"] == 2, cat
assert all(len(n["id"]) == 64 for n in cat["nodes"])
# uppercase scheme normalized
n = mksub.node_from_link("VLESS://u@h:443#x"); assert n["link"].startswith("vless://"), n
# control bytes / oversize / dup dropped
assert mksub.node_from_link("vless://u@h:443\x00evil") is None
assert mksub.node_from_link("vless://u@h:443?x=" + "a"*9000) is None
# label sanitization keeps unicode, drops ESC
got = mksub.clean("Ru \x1b[31mX")
assert "\x1b" not in got and "Нидерланды" in mksub.clean("Нидерланды 🇳🇱"), got
# empty / html / no-outbounds-json bodies rejected
for b in [b"", base64.b64encode(b"nothing here"), b"<html></html>", base64.b64encode(b'{"x":1}')]:
    try:
        mksub.process_body(b); raise AssertionError("accepted bad body")
    except SystemExit:
        pass
# JSON balancer profile feed (Remnawave/Happ) parses into selectable pool nodes
prof = {"remarks": "DE Auto", "outbounds": [
            {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "a.example.com", "port": 443}]}},
            {"protocol": "vless", "tag": "proxy-2", "settings": {"vnext": [{"address": "b.example.com", "port": 443}]}},
            {"protocol": "blackhole", "tag": "block"}],
        "routing": {"balancers": [{"tag": "B", "selector": ["proxy"], "strategy": {"type": "leastLoad"}}],
                    "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "B"}]}}
pcat = mksub.process_body(json.dumps([prof]).encode())
assert pcat["meta"]["format"] == "json" and pcat["meta"]["count"] == 1, pcat
pn = pcat["nodes"][0]
assert pn["kind"] == "pool" and pn["recognized"] and pn["members"] == 2 and pn["strategy"] == "leastLoad", pn
assert json.loads(pn["profile"])["remarks"] == "DE Auto"
# a 0.0.0.0 placeholder profile (App-not-supported / device-limit) is rejected
ph = {"remarks": "App not supported", "outbounds": [
          {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "0.0.0.0", "port": 1}]}}]}
try:
    mksub.process_body(json.dumps([ph]).encode()); raise AssertionError("accepted placeholder")
except SystemExit:
    pass
# a 0.0.0.0 placeholder LINK is also flagged unsupported
assert mksub.node_from_link("vless://u@0.0.0.0:1#x")["recognized"] is False
# CGNAT blocked by SSRF guard
import socket
g = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: [(2,1,6,"",("100.64.0.1",443))]
try:
    mksub._public_ips("x"); raise AssertionError("CGNAT allowed")
except SystemExit:
    pass
finally:
    socket.getaddrinfo = g
print("mksub-ok")
PY

    # mkjson: balancer profile validation + overlay tag matching (pure python)
    python3 - "$SRC" <<'PY' && ok "mkjson profile validation" || bad "mkjson profile validation"
import sys, json
sys.path.insert(0, sys.argv[1])
import mkjson
prof = {
  "log": {"loglevel": "warning", "access": "/Users/x/log"},
  "inbounds": [{"tag": "socks", "protocol": "socks", "port": 10808,
                "sniffing": {"enabled": True, "destOverride": ["tls"]}}],
  "outbounds": [{"protocol": "vless", "tag": "proxy"},
                {"protocol": "vless", "tag": "proxy-2"},
                {"protocol": "freedom", "tag": "direct"}],
  "routing": {"balancers": [{"tag": "B", "selector": ["proxy"],
                             "strategy": {"type": "leastPing"}}],
              "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "B"}]},
}
idx, ib = mkjson.validate_profile(prof)
assert ib["tag"] == "socks"
m, strat, tag = mkjson._balancer_info(prof)
assert m == 2 and strat == "leastPing" and tag == "B", (m, strat, tag)
clean = mkjson.sanitize_provider(prof)
assert "access" not in clean["log"]      # platform path stripped
# SECURITY: a hostile profile's extra inbounds (open relay / dokodemo to LAN) and
# control-plane blocks must be dropped, leaving the overlay as the sole inbound.
evil = json.loads(json.dumps(prof))
evil["inbounds"].append({"tag": "EVIL", "protocol": "socks", "listen": "0.0.0.0", "port": 1080})
evil["inbounds"].append({"tag": "DOKO", "protocol": "dokodemo-door", "listen": "0.0.0.0", "port": 1234,
                         "settings": {"address": "169.254.169.254", "port": 80}})
evil["api"] = {"tag": "api", "services": ["HandlerService"]}
evil["reverse"] = {"bridges": [{"tag": "br", "domain": "x"}]}
sc = mkjson.sanitize_provider(evil)
assert "inbounds" not in sc, "provider inbounds must be stripped"
for k in ("api", "stats", "metrics", "policy", "reverse"):
    assert k not in sc, "%s must be stripped" % k
assert sc["outbounds"] == evil["outbounds"] and sc["routing"] == evil["routing"]  # resolution intact
# source/user routing must be rejected
bad = json.loads(json.dumps(prof))
bad["routing"]["rules"].append({"type": "field", "source": ["10.0.0.0/8"], "outboundTag": "direct"})
try:
    mkjson.validate_profile(bad); raise AssertionError("accepted source routing")
except SystemExit:
    pass
print("mkjson-ok")
PY
}

# -------------------------------------------------------------------------
# tier 3: engine tests (need real xray / sing-box)
# -------------------------------------------------------------------------
find_xray()   { [ -x "$CACHE/xray" ] && echo "$CACHE/xray"; }
find_singbox(){ [ -x "$CACHE/sing-box" ] && echo "$CACHE/sing-box"; }

download_engines() {
    mkdir -p "$CACHE"
    _os="$(uname -s | tr '[:upper:]' '[:lower:]')"; _m="$(uname -m)"
    case "$_m" in arm64|aarch64) _xa=arm64-v8a; _sa=arm64;; x86_64|amd64) _xa=64; _sa=amd64;; *) echo "unknown arch"; return 1;; esac
    case "$_os" in darwin) _xos=macos; _sos=darwin;; linux) _xos=linux; _sos=linux;; *) echo "unknown os"; return 1;; esac
    echo "  downloading xray ($_xos-$_xa) ..."
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-${_xos}-${_xa}.zip" -o "$CACHE/x.zip" && unzip -oq "$CACHE/x.zip" -d "$CACHE" && chmod +x "$CACHE/xray"
    _tag="$(curl -fsSLI https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null | tr -d '\r' | awk -F'/tag/' 'tolower($0)~/location:/{print $2}' | awk '{print $1}' | tail -1)"; _v="${_tag#v}"
    echo "  downloading sing-box $_tag ($_sos-$_sa) ..."
    curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/${_tag}/sing-box-${_v}-${_sos}-${_sa}.tar.gz" -o "$CACHE/sb.tgz" && tar xzf "$CACHE/sb.tgz" -C "$CACHE" && cp "$(find "$CACHE" -name sing-box -type f | head -1)" "$CACHE/sing-box"
}

engine_tests() {
    XR="$(find_xray || true)"; SG="$(find_singbox || true)"
    if [ -z "$XR" ] || [ -z "$SG" ]; then
        printf '== engine == (skipped: run with --download to fetch xray/sing-box)\n'
        return
    fi
    echo "== engine =="
    XP="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
    UP="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
    _d="$(mktemp -d)"
    gx() { python3 "$SRC/mkconfig.py" --link "$1" --port 51821 --secret-key "$XP" --peer-pubkey "$UP" > "$_d/c.json" 2>/dev/null \
           && "$XR" run -test -config "$_d/c.json" -format json >/dev/null 2>&1; }
    gs() { python3 "$SRC/mksingbox.py" --link "$1" --port 51821 --secret-key "$XP" --peer-pubkey "$UP" > "$_d/s.json" 2>/dev/null \
           && "$SG" check -c "$_d/s.json" >/dev/null 2>&1; }
    KEY="$("$XR" x25519 2>/dev/null | awk -F': ' '/Password|Public/{print $2}' | tail -1)"
    gx "vless://u@h:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=$KEY&sid=ab&sni=a&fp=chrome" && ok "xray vless reality" || bad "xray vless reality"
    gx "trojan://pw@h:443?security=tls&sni=a" && ok "xray trojan" || bad "xray trojan"
    gx "vless://u@h:443?type=kcp&security=none" && ok "xray mKCP" || bad "xray mKCP"
    gs "hysteria2://pw@h:443?sni=h" && ok "singbox hysteria2" || bad "singbox hysteria2"
    gs "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?sni=h" && ok "singbox tuic" || bad "singbox tuic"
    # balancer pool: build overlay + validate merged confdir
    printf '%s' "$XP" > "$_d/sk"; printf '%s' "$UP" > "$_d/pk"
    # profile carries a hostile extra inbound on 0.0.0.0; sanitizer must drop it.
    cat > "$_d/profile.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10808,"settings":{"udp":true},"sniffing":{"enabled":true,"destOverride":["tls"]}},{"tag":"EVIL","protocol":"socks","listen":"0.0.0.0","port":1080,"settings":{"udp":true}}],"outbounds":[{"protocol":"freedom","tag":"proxy"},{"protocol":"freedom","tag":"proxy-2"},{"protocol":"blackhole","tag":"block"}],"routing":{"balancers":[{"tag":"B","selector":["proxy"],"strategy":{"type":"leastPing"},"fallbackTag":"block"}],"rules":[{"type":"field","network":"tcp,udp","balancerTag":"B"}]},"burstObservatory":{"subjectSelector":["proxy"],"pingConfig":{"destination":"https://www.gstatic.com/generate_204","interval":"1m","timeout":"3s"}}}
EOF
    mkdir -p "$_d/pool"
    if python3 "$SRC/mkjson.py" overlay --profile "$_d/profile.json" \
         --out-provider "$_d/pool/01-provider.json" --out-overlay "$_d/pool/99-overlay.json" \
         --port 51821 --secret-key-file "$_d/sk" --peer-pubkey-file "$_d/pk" >/dev/null 2>&1 \
       && "$XR" run -test -confdir "$_d/pool" >/dev/null 2>&1 \
       && ! grep -q '0\.0\.0\.0' "$_d/pool/01-provider.json"
    then ok "xray balancer pool (-confdir)"; else bad "xray balancer pool (-confdir)"; fi
    rm -rf "$_d"
}

# -------------------------------------------------------------------------
# tier 4: network (local self-signed TLS server; needs openssl). Exercises the
# real fetch path against the response framings that bit us in the field:
# chunked transfer-encoding and gzip content-encoding.
# -------------------------------------------------------------------------
network_tests() {
    have openssl || { printf '== network == (skipped: openssl not found)\n'; return; }
    echo "== network =="
    _d="$(mktemp -d)"
    openssl req -x509 -newkey rsa:2048 -keyout "$_d/key.pem" -out "$_d/cert.pem" -days 1 \
        -nodes -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1 \
        || { bad "network: cert gen"; rm -rf "$_d"; return; }
    cat > "$_d/srv.py" <<'PYEOF'
import socket, ssl, sys, base64, gzip
port, mode = int(sys.argv[1]), sys.argv[2]
body = base64.b64encode(("vless://u@nl.example.com:443?security=tls&sni=a#NL\n"*3).encode())
if mode == "chunked":
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n"
            b"profile-update-interval: 6\r\nConnection: close\r\n\r\n"
            + ("%x\r\n" % len(body)).encode() + body + b"\r\n0\r\n\r\n")
else:  # gzip
    gz = gzip.compress(body)
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(gz)) + gz
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[3], sys.argv[4])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(5)
sys.stderr.write("ready\n"); sys.stderr.flush()
while True:
    c, _ = s.accept()
    try:
        t = ctx.wrap_socket(c, server_side=True); t.recv(4096); t.sendall(resp); t.close()
    except Exception:
        pass
PYEOF
    _fetch() {  # <mode> <port> <name>
        python3 "$_d/srv.py" "$2" "$1" "$_d/cert.pem" "$_d/key.pem" >/dev/null 2>&1 &
        _srv=$!; sleep 2
        printf 'https://127.0.0.1:%s/sub' "$2" > "$_d/url.txt"
        _out="$(PROXY_UNIFI_SUB_ALLOW_PRIVATE=1 SSL_CERT_FILE="$_d/cert.pem" \
            python3 "$SRC/mksub.py" fetch --url-file "$_d/url.txt" 2>&1)"
        kill "$_srv" 2>/dev/null; wait "$_srv" 2>/dev/null
        if printf '%s' "$_out" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["meta"]["count"]==1 else 1)' 2>/dev/null
        then ok "$3"; else bad "$3"; fi
    }
    _fetch chunked 18581 "fetch chunked transfer-encoding"
    _fetch gzip    18582 "fetch gzip content-encoding"
    rm -rf "$_d"
}

# -------------------------------------------------------------------------
case "${1:-}" in --download) download_engines || echo "  (engine download failed)";; esac
static_tests
parser_tests
engine_tests
network_tests
echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = 0 ]
