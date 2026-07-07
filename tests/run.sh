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
sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# -------------------------------------------------------------------------
# tier 1: static analysis
# -------------------------------------------------------------------------
static_tests() {
    echo "== static =="
    if have shellcheck; then
        if shellcheck -s sh "$SRC/proxy-unifi" "$SRC/on_boot.sh" "$ROOT/install.sh" \
            "$ROOT/tests/run.sh" "$ROOT/tests/lifecycle.sh" >/dev/null 2>&1
        then ok "shellcheck"; else bad "shellcheck"; fi
    else printf '  skip shellcheck (not installed)\n'; fi
    if have dash; then
        _d=0
        for f in "$SRC/proxy-unifi" "$SRC/on_boot.sh" "$ROOT/install.sh" "$ROOT/tests/lifecycle.sh"; do
            dash -n "$f" 2>/dev/null || _d=1
        done
        if [ "$_d" = 0 ]; then ok "dash -n"; else bad "dash -n"; fi
    else printf '  skip dash -n (not installed)\n'; fi
    if python3 -m py_compile "$SRC"/mkxray.py "$SRC"/mksingbox.py "$SRC"/mksub.py "$SRC"/mkjson.py "$SRC"/proxylib.py "$SRC"/safeexec.py 2>/dev/null
    then ok "python compile"; else bad "python compile"; fi
    rm -rf "$SRC/__pycache__"

    # A timed-out validator must terminate its complete process group, not leave
    # a grandchild consuming resources after the wrapper returns.
    _sd="$(mktemp -d)"
    # shellcheck disable=SC2016 # $!/\$1 must expand inside the child shell
    python3 "$SRC/safeexec.py" --user "$(id -un)" --timeout 1 --memory-mb 64 --fsize-mb 1 -- \
        sh -c 'sleep 30 & echo $! > "$1/child"; wait' sh "$_sd" >/dev/null 2>"$_sd/error"
    _src=$?; _child="$(cat "$_sd/child" 2>/dev/null || true)"; _dead=1
    [ -n "$_child" ] && kill -0 "$_child" 2>/dev/null && _dead=0
    if [ "$_src" = 124 ] && [ "$_dead" = 1 ]; then ok "safe validator timeout kills process group"
    else bad "safe validator timeout kills process group"; [ "$_dead" = 1 ] || kill "$_child" 2>/dev/null || true; fi
    rm -rf "$_sd"
    if [ "$(uname -s)" = Linux ]; then
        python3 "$SRC/safeexec.py" --user "$(id -un)" --timeout 10 --memory-mb 64 --fsize-mb 1 -- \
            python3 -c 'x=bytearray(96*1024*1024); __import__("time").sleep(2)' >/dev/null 2>&1
        [ "$?" = 125 ] && ok "safe validator enforces resident-memory limit" \
            || bad "safe validator enforces resident-memory limit"
    fi

    if grep -E -- '--(link|secret-key|peer-pubkey)[[:space:]]+"?\$' "$SRC/proxy-unifi" >/dev/null 2>&1; then
        bad "proxy credentials and keys stay out of child argv"
    else
        ok "proxy credentials and keys stay out of child argv"
    fi

    _ud="$(mktemp -d)"
    {
        # shellcheck disable=SC2016 # $1 belongs to the generated helper script.
        echo '_uint() { case "$1" in ""|*[!0-9]*) return 1;; *) return 0;; esac; }'
        sed -n '/^load_settings() {/,/^}/p' "$SRC/proxy-unifi"
        cat <<'SH'
SETTINGS="$1"; SUB_USER_AGENT="proxy-unifi/1.1"
load_settings
[ "$SUB_USER_AGENT" = "proxy-unifi/1.1" ]
SH
    } > "$_ud/ua-settings.sh"
    python3 - "$_ud/settings" <<'PY'
import sys
value = "".join(chr(x) for x in (0x43a, 0x438, 0x440, 0x438, 0x43b, 0x43b, 0x438, 0x446, 0x430))
open(sys.argv[1], "w", encoding="utf-8").write('SUB_USER_AGENT="%s"\n' % value)
PY
    if sh "$_ud/ua-settings.sh" "$_ud/settings"; then ok "settings User-Agent rejects non-ASCII"
    else bad "settings User-Agent rejects non-ASCII"; fi
    rm -rf "$_ud"

    _ed="$(mktemp -d)"
    {
        sed -n '/^wg_endpoint() {/,/^}/p' "$SRC/proxy-unifi"
        cat <<'SH'
WG_LISTEN="127.0.0.1"; WG_PORT="51821"
[ "$(wg_endpoint)" = "127.0.0.1:51821" ] || exit 1
WG_LISTEN="2001:db8::1"; WG_PORT="51821"
[ "$(wg_endpoint)" = "[2001:db8::1]:51821" ] || exit 1
SH
    } > "$_ed/endpoint.sh"
    if sh "$_ed/endpoint.sh"; then ok "CLI WireGuard endpoint formats IPv6"
    else bad "CLI WireGuard endpoint formats IPv6"; fi
    rm -rf "$_ed"

    _dd="$(mktemp -d)"
    {
        cat <<'SH'
download_to() {
    case "$1" in
        *good*) printf ok > "$2"; return 0 ;;
        *) return 1 ;;
    esac
}
SH
        sed -n '/^DOWNLOAD_URL_USED=/,/^}/p' "$SRC/proxy-unifi"
        cat <<'SH'
download_any_to "$1/out" 10 https://bad.example/file https://good.example/file || exit 1
[ "$DOWNLOAD_URL_USED" = "https://good.example/file" ] || exit 1
[ "$(cat "$1/out")" = ok ]
SH
    } > "$_dd/download-any.sh"
    if sh "$_dd/download-any.sh" "$_dd"; then ok "core downloader tries fallback URL"
    else bad "core downloader tries fallback URL"; fi
    rm -rf "$_dd"

    # The installer-wide rollback must restore scripts, both cores, and geo
    # assets from one retained promotion backup.
    _id="$(mktemp -d)"
    mkdir -p "$_id/live" "$_id/backup"
    for _f in proxy-unifi mkxray.py mksingbox.py mksub.py mkjson.py proxylib.py safeexec.py \
              xray sing-box geoip.dat geosite.dat; do
        printf old > "$_id/backup/$_f"; printf new > "$_id/live/$_f"
    done
    printf old > "$_id/backup/on_boot.sh"; printf new > "$_id/on_boot.sh"; : > "$_id/marker"
    cat > "$_id/restore.sh" <<SH
PROMOTION_MARKER='$_id/marker'
PROMOTION_BACKUP='$_id/backup'
BIN_DIR='$_id/live'
ONBOOT_DST='$_id/on_boot.sh'
SH
    awk '/^restore_promotion\(\) \{/,/^}/' "$ROOT/install.sh" >> "$_id/restore.sh"
    echo 'restore_promotion' >> "$_id/restore.sh"
    _install_restore=1
    if sh "$_id/restore.sh"; then
        for _f in proxy-unifi xray sing-box geoip.dat geosite.dat; do
            [ "$(cat "$_id/live/$_f")" = old ] || _install_restore=0
        done
        [ "$(cat "$_id/on_boot.sh")" = old ] || _install_restore=0
        [ ! -e "$_id/marker" ] || _install_restore=0
    else
        _install_restore=0
    fi
    [ "$_install_restore" = 1 ] && ok "installer rollback restores scripts, cores, and assets" \
        || bad "installer rollback restores scripts, cores, and assets"
    rm -rf "$_id"

    _bd="$(mktemp -d)"
    mkdir -p "$_bd/archive-root/src" "$_bd/work"
    for _f in proxy-unifi mkxray.py mksingbox.py mksub.py mkjson.py proxylib.py safeexec.py on_boot.sh; do
        printf 'bundle:%s\n' "$_f" > "$_bd/archive-root/src/$_f"
    done
    python3 - "$_bd/source.tgz" "$_bd/archive-root" <<'PY'
import sys
import tarfile
with tarfile.open(sys.argv[1], "w:gz") as archive:
    archive.add(sys.argv[2], arcname="proxy-unifi-test")
PY
    cat > "$_bd/bundle.sh" <<SH
WORKDIR='$_bd/work'
PYTHON=python3
PROJECT_REPO='ignored'
PROXY_UNIFI_RAW=''
bounded_curl() { cp '$_bd/source.tgz' "\$2"; }
SCRIPT_DIR=''
REPO_RAW='https://invalid'
CACHEBUST=1
SH
    {
        sed -n '/^prepare_source_bundle() {/,/^}/p' "$ROOT/install.sh"
        sed -n '/^fetch() {/,/^}/p' "$ROOT/install.sh"
        cat <<'SH'
printf '%040d\n' 1 > "$WORKDIR/repo-sha"
prepare_source_bundle || exit 1
fetch mksingbox.py "$WORKDIR/out" 0644 || exit 1
grep -q '^bundle:mksingbox.py$' "$WORKDIR/out"
SH
    } >> "$_bd/bundle.sh"
    if sh "$_bd/bundle.sh"; then ok "installer source archive fallback"
    else bad "installer source archive fallback"; fi
    rm -rf "$_bd"

    _ld="$(mktemp -d)"
    cat > "$_ld/listeners.sh" <<'SH'
have() { return 0; }
ss() {
    echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port'
    case "$1" in
        -lun) echo 'UNCONN 0 0 127.0.0.1:51821 0.0.0.0:*' ;;
        -ltn) echo 'LISTEN 0 4096 127.0.0.1:1080 0.0.0.0:*' ;;
    esac
}
SH
    sed -n '/^_socket_listening() {/,/^tcp_socket_listening()/p' "$SRC/proxy-unifi" >> "$_ld/listeners.sh"
    cat >> "$_ld/listeners.sh" <<'SH'
socket_listening 51821 && ! socket_listening 1080 \
    && tcp_socket_listening 1080 && ! tcp_socket_listening 51821
SH
    if sh "$_ld/listeners.sh"; then ok "listener checks distinguish UDP and TCP"
    else bad "listener checks distinguish UDP and TCP"; fi
    rm -rf "$_ld"

    # external-exposure guard: the rendered systemd unit must firewall the
    # sing-box (0.0.0.0) WG port BEFORE it binds, and must NOT firewall xray
    # (loopback-only) -- clearing any stale rule instead.
    _ud="$(mktemp -d)"
    cat > "$_ud/h.sh" <<'SH'
SBIN=/b/sing-box; XRAY=/b/xray; CONFIG=/c/config.json; POOL_DIR=/c/pool
BIN_DIR=/b; ROOT=/r; SERVICE_FILE="$WORK/unit"
current_engine() { echo "$ENG"; }
prepare_service_permissions() { :; }
systemctl() { :; }
atomic_write() { cat > "$1"; }
SH
    awk '/^write_service\(\) \{/,/^}/' "$SRC/proxy-unifi" >> "$_ud/h.sh"
    echo 'write_service' >> "$_ud/h.sh"
    _fw_ok=1
    ENG=singbox  WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStartPre=+/b/proxy-unifi _fw-lock$'  "$_ud/unit" || _fw_ok=0
    grep -q '^ExecStopPost=-+/b/proxy-unifi _fw-unlock$' "$_ud/unit" || _fw_ok=0
    ENG=xray     WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStartPre=-+/b/proxy-unifi _fw-unlock$' "$_ud/unit" || _fw_ok=0
    grep -q '_fw-lock' "$_ud/unit" && _fw_ok=0          # xray must NOT lock a port
    [ "$_fw_ok" = 1 ] && ok "singbox WG port firewalled (unit)" || bad "singbox WG port firewalled (unit)"
    rm -rf "$_ud"

    # Exercise firewall ownership and IPv6 fail-closed behavior against a stateful
    # iptables mock rather than only grepping the rendered unit.
    _fd="$(mktemp -d)"
    cat > "$_fd/fw.sh" <<'SH'
FW_CHAIN=PROXY_UNIFI_WG; WG_PORT=51821; D="$WORK"; FAIL6=0
load_settings() { :; }; err() { :; }; have() { command -v "$1" >/dev/null 2>&1; }
mock_iptables() {
    _fam="$1"; shift; _base="$D/$_fam"
    case "$1:$2" in
        -N:*) [ ! -f "$_base.chain" ] || return 1; : > "$_base.chain" ;;
        -F:*) [ -f "$_base.chain" ] || return 1; rm -f "$_base.rule" ;;
        -A:*) printf '%s\n' "$6" > "$_base.rule" ;;
        -C:INPUT) [ -f "$_base.jump" ] ;;
        -C:*) [ -f "$_base.rule" ] && [ "$(cat "$_base.rule")" = "$6" ] ;;
        -I:INPUT) : > "$_base.jump" ;;
        -D:INPUT) rm -f "$_base.jump" ;;
        -X:*) rm -f "$_base.chain" ;;
        *) return 1 ;;
    esac
}
iptables() { mock_iptables v4 "$@"; }
ip6tables() { [ "$FAIL6" = 0 ] || return 1; mock_iptables v6 "$@"; }
SH
    sed -n '/^FW_CHAIN=/,/^ensure_service_user()/p' "$SRC/proxy-unifi" | sed '$d' >> "$_fd/fw.sh"
    cat >> "$_fd/fw.sh" <<'SH'
_ipv6_enabled() { return 0; }
fw_lock && fw_is_locked 51821 || exit 1
[ -f "$D/v4.jump" ] && [ -f "$D/v6.jump" ] || exit 1
fw_unlock
[ ! -e "$D/v4.jump" ] && [ ! -e "$D/v6.jump" ] || exit 1
FAIL6=1
if fw_lock; then exit 1; fi
[ ! -e "$D/v4.jump" ] && [ ! -e "$D/v4.chain" ] || exit 1
SH
    if WORK="$_fd" sh "$_fd/fw.sh"; then ok "firewall guard owns rules and fails closed on IPv6"
    else bad "firewall guard owns rules and fails closed on IPv6"; fi
    rm -rf "$_fd"
}

# -------------------------------------------------------------------------
# tier 2: parser tests (no network, no engine)
# -------------------------------------------------------------------------
# expect mkxray/mksingbox to ACCEPT (exit 0) or REJECT (exit !=0) a link, and
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
    expect mkxray.py "vless://u@h:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=$KEY&sid=ab&sni=a&fp=chrome" accept "vless reality"
    expect mkxray.py "$VM" accept "vmess base64-json"
    expect mkxray.py "vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?type=ws&security=tls&path=%2Fw&host=a&sni=a" accept "vmess URI form"
    expect mkxray.py "trojan://pw@h:443?security=tls&sni=a" accept "trojan"
    expect mkxray.py "ss://$(printf 'aes-256-gcm:pw' | base64 | tr -d '\n')@h:8388" accept "ss plain"
    expect mkxray.py "ss://$(printf 'aes-256-gcm:pw@[2001:4860:4860::8888]:8388' | base64 | tr -d '\n')" accept "ss legacy IPv6"
    expect mkxray.py "vless://u@h:443?type=kcp&security=none" accept "mKCP plain"
    expect mksingbox.py "hysteria2://pw@h:443?sni=h" accept "hysteria2"
    expect mksingbox.py "hysteria2://pw@h:443?mport=4000-5000" reject "hysteria2 port hopping"
    expect mksingbox.py "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?sni=h" accept "tuic"
    expect mksingbox.py "ss://$(printf 'aes-256-gcm:pw' | base64 | tr -d '\n')@h:8388?plugin=obfs-local%3Bobfs%3Dhttp" accept "ss+obfs"
    # rejected forms (security / removed transports / bad input)
    expect mkxray.py "vless://u@h:443?security=tls&allowInsecure=1&sni=a" reject "allowInsecure rejected"
    expect mkxray.py "vless://u@h:443?security=tls&type=quic&sni=a" reject "quic rejected"
    expect mkxray.py "vless://u@h:443?type=kcp&seed=x" reject "mKCP seed rejected"
    expect mkxray.py "vless://u@-evil:443?security=tls&sni=a" reject "leading-hyphen host"
    expect mkxray.py "vless://u@bad_name:443?security=tls&sni=a" reject "malformed domain host"
    expect mkxray.py "vless://u@h:notaport?security=tls&sni=a" reject "bad port"
    expect mkxray.py "ss://$(printf 'aes-256-gcm:pw@host:notaport' | base64 | tr -d '\n')" reject "ss legacy bad port"
    expect mkxray.py "naive+https://x@h:443" reject "unsupported scheme"
    expect mkxray.py "vless://u@h:443?security=tls&sni=a&unknownSemantic=x" reject "unknown query field rejected"
    expect mkxray.py "vless://u@h:443?security=tls&sni=a&sni=b" reject "duplicate query field rejected"
    expect mkxray.py "vless://u@h:443?security=tls&type=ws&net=tcp&sni=a" reject "conflicting query aliases rejected"
    expect mkxray.py "vless://u@h:443?security=tls&sni=a&allowInsecure=maybe" reject "invalid TLS boolean rejected"
    expect mkxray.py "vless://u@h:443?security=none&type=tcp&pbk=$KEY" reject "irrelevant security field rejected"
    expect mkxray.py "vless://u@h:443?security=tls&type=tcp&sni=a&authority=front.example" reject "irrelevant transport field rejected"
    expect mkxray.py "trojan://pw@h:443?security=tls&sni=a&flow=xtls-rprx-vision" reject "removed Trojan flow rejected"
    expect mkxray.py "vmess://u@h:443?flow=xtls-rprx-vision" reject "irrelevant VMess flow rejected"
    _unsafe_extra="$(python3 -c 'import json,urllib.parse; print(urllib.parse.quote(json.dumps({"downloadSettings":{"address":"127.0.0.1","port":80}})))')"
    expect mkxray.py "vless://u@h:443?security=tls&type=xhttp&sni=a&extra=$_unsafe_extra" reject "private XHTTP extra target rejected"
    _bad_vmess="$(printf '{"add":"h","port":443,"id":"u"}' | base64 | tr -d '\n' | sed 's/^/!/')"
    expect mkxray.py "vmess://$_bad_vmess" reject "invalid base64 characters rejected"
    expect mksingbox.py "hysteria2://pw@h:443?sni=h&obfs=salamander" reject "incomplete hysteria2 obfs rejected"
    expect mksingbox.py "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?sni=h&udp_over_stream=maybe" reject "invalid TUIC boolean rejected"

    # host injection: ESC byte must be rejected (no traceback)
    out="$(python3 "$SRC/mkxray.py" --link "$(printf 'vless://u@h\033[2Jx:443?security=tls&sni=a')" --port 51821 --secret-key AAAA --peer-pubkey BBBB 2>&1)" || true
    if printf '%s' "$out" | grep -qi 'control\|unsafe\|malformed'; then ok "ESC host rejected"; else bad "ESC host rejected"; fi

    python3 - "$SRC" <<'PY' && ok "current share-link fields preserved" || bad "current share-link fields preserved"
import sys,urllib.parse
sys.path.insert(0,sys.argv[1])
import mkxray,mksingbox
extra=urllib.parse.quote('{"scMaxEachPostBytes":1000000}',safe='')
fm=urllib.parse.quote('{"tcp":[{"type":"sudoku"}]}',safe='')
link="vless://u@h:443?security=tls&type=grpc&sni=a&authority=front.example&mode=multi&vcn=cert.example&pcs=abcd"
out,_,_=mkxray.parse_vless(link)
grpc=out["streamSettings"]["grpcSettings"]; tls=out["streamSettings"]["tlsSettings"]
assert grpc["authority"]=="front.example" and grpc["multiMode"] is True
assert tls["verifyPeerCertByName"]=="cert.example" and tls["pinnedPeerCertSha256"]=="abcd"
out,_,_=mkxray.parse_vless("vless://u@h:443?security=tls&type=xhttp&sni=a&extra="+extra+"&fm="+fm)
assert out["streamSettings"]["xhttpSettings"]["extra"]["scMaxEachPostBytes"]==1000000
assert out["streamSettings"]["finalmask"]["tcp"][0]["type"]=="sudoku"
out,_,_=mksingbox.parse_tuic("tuic://u:p@h:443?sni=h&network=tcp")
assert out["network"]=="tcp"
PY

    # mksub: classification + safety (pure python)
    python3 - "$SRC" <<'PY' && ok "mksub parser corpus" || bad "mksub parser corpus"
import sys, base64, json, gzip, contextlib, io, os, tempfile, types
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
assert cat["nodes"][2]["reason"] == "unsupported SIP003 plugin", cat
assert all(len(n["id"]) == 64 for n in cat["nodes"])
# uppercase scheme normalized
n = mksub.node_from_link("VLESS://u@h:443#x"); assert n["link"].startswith("vless://"), n
# URI-form VMess labels and legacy VMess identity are parsed without duplicate
# base64/JSON work; provider labels are part of subscription row identity.
n = mksub.node_from_link("vmess://u@h:443#Москва🎯"); assert n["label"] == "Москва🎯", n
vm1 = {"v":"2","ps":"old","add":"public.example","port":443,"id":"u"}
vm2 = {"id":"u","port":443,"add":"public.example","ps":"new","v":"2"}
vl1 = "vmess://" + base64.b64encode(json.dumps(vm1).encode()).decode()
vl2 = "vmess://" + base64.b64encode(json.dumps(vm2).encode()).decode()
assert mksub.node_from_link(vl1)["id"] != mksub.node_from_link(vl2)["id"]
same_server = [
  "ss://%s@max.ru:1234#%s" % (
      base64.b64encode(b"aes-256-gcm:pw").decode(),
      label)
  for label in ("DE", "NL", "US", "FR", "PL", "TR", "JP", "GB")
]
cat_same = mksub.process_body(body(same_server))
assert cat_same["meta"]["count"] == 8, cat_same
assert len({n["id"] for n in cat_same["nodes"]}) == 8
mojibake_de = bytes.fromhex("f09f87a9f09f87aa").decode("latin-1") + "⭐ VPN | Германия ♾️"
assert mksub.clean(mojibake_de, 80).startswith("🇩🇪⭐"), mksub.clean(mojibake_de, 80)
mojibake_de = bytes.fromhex("f09f87a9f09f87aa").decode("cp1252") + "⭐ VPN | Германия ♾️"
assert mksub.clean(mojibake_de, 80).startswith("🇩🇪⭐"), mksub.clean(mojibake_de, 80)
# control bytes / oversize / dup dropped
assert mksub.node_from_link("vless://u@h:443\x00evil") is None
assert mksub.node_from_link("vless://u@h:443?x=" + "a"*9000) is None
assert mksub.node_from_link("vless://u@h:443#" + "🎯"*3000) is None
bad_encoded = body(["vless://u@h:443"]).decode()
try:
    mksub.process_body((bad_encoded[:4] + "!" + bad_encoded[4:]).encode())
    raise AssertionError("accepted injected non-base64 character")
except SystemExit:
    pass
# label sanitization: ANSI dropped, Unicode/emoji preserved
got = mksub.clean("Ru \x1b[31mX")
assert got == "Ru X", got
assert mksub.clean("Нидерланды 🇳🇱", 40) == "Нидерланды 🇳🇱"
assert mksub.clean("🇩🇪🎯 Автовыбор | Германия", 80) == "🇩🇪🎯 Автовыбор | Германия"
assert mksub.clean("🇺🇸 США", 40) == "🇺🇸 США"
assert mksub.clean("München España Montréal", 80) == "München España Montréal"
full = "🇩🇪🎯".encode("utf-8").decode("latin-1") + " Автовыбор"     # full mojibake
assert "🇩🇪🎯" in mksub.clean(full, 80), mksub.clean(full, 80)
assert mksub.clean("日本 经由", 40) == "日本 经由"                     # CJK kept
assert mksub.clean("plain ascii", 40) == "plain ascii"
# compressed output is capped after inflation, not only before it
try:
    mksub._decompress_limited(gzip.compress(b"x"*(mksub.MAX_BYTES+1)),"gzip")
    raise AssertionError("accepted decompression bomb")
except SystemExit:
    pass
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
# Some providers wrap a full Xray JSON profile inside an ss:// row. The catalog
# must expose that row as a JSON pool, not as an ordinary Shadowsocks link.
encoded_prof = base64.urlsafe_b64encode(json.dumps(prof).encode()).decode().rstrip("=")
wrapped = "ss://%s@max.ru:1234#%s" % (encoded_prof, mojibake_de)
wn = mksub.node_from_link(wrapped)
assert wn["kind"] == "pool" and wn["scheme"] == "json" and wn["members"] == 2, wn
assert wn["engine"] == "xraypool" and json.loads(wn["profile"])["remarks"] == "DE Auto"
wcat = mksub.process_body(body([wrapped]))
assert wcat["meta"]["format"] == "links" and wcat["nodes"][0]["kind"] == "pool", wcat
with contextlib.redirect_stdout(io.StringIO()) as output:
    with tempfile.TemporaryDirectory() as tmp:
        catalog=os.path.join(tmp,"wrapped-catalog")
        with open(catalog,"w") as f: json.dump(wcat,f)
        mksub.cmd_render(types.SimpleNamespace(file=catalog,selected=""))
rendered = output.getvalue()
assert "json" in rendered and "🇩🇪⭐" in rendered, rendered
# Selection extraction loads the catalog once and emits metadata + payload.
with tempfile.TemporaryDirectory() as tmp:
    catalog=os.path.join(tmp,"catalog"); meta=os.path.join(tmp,"meta"); payload=os.path.join(tmp,"payload")
    with open(catalog,"w") as output: json.dump(pcat,output)
    args=types.SimpleNamespace(file=catalog,index=1,meta_file=meta,payload_file=payload)
    with contextlib.redirect_stdout(io.StringIO()) as output: mksub.cmd_extract(args)
    assert output.getvalue().split("\t")[:2] == [pn["id"],"1"]
    with open(meta) as source: assert json.load(source)["id"] == pn["id"]
    with open(payload) as source: assert json.load(source)["remarks"] == "DE Auto"
    assert oct(os.stat(meta).st_mode & 0o777) == "0o600"
    assert oct(os.stat(payload).st_mode & 0o777) == "0o600"
    assert not [name for name in os.listdir(tmp) if name.startswith(".write.")]
    refreshed=os.path.join(tmp,"refreshed")
    args=types.SimpleNamespace(file=catalog,selection_file=meta,meta_file=refreshed)
    with contextlib.redirect_stdout(io.StringIO()) as output: mksub.cmd_match(args)
    assert output.getvalue().split("\t")[:2] == ["1",pn["id"]]
    with open(refreshed) as source: assert json.load(source)["id"] == pn["id"]
    try:
        args=types.SimpleNamespace(file=catalog,selection_file=meta,meta_file=tmp)
        with contextlib.redirect_stdout(io.StringIO()): mksub.cmd_match(args)
        raise AssertionError("accepted unwritable metadata target")
    except SystemExit as e:
        assert e.code == 2
# a 0.0.0.0 placeholder profile (App-not-supported / device-limit) is rejected
ph = {"remarks": "App not supported", "outbounds": [
          {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "0.0.0.0", "port": 1}]}}]}
try:
    mksub.process_body(json.dumps([ph]).encode()); raise AssertionError("accepted placeholder")
except SystemExit:
    pass
# a 0.0.0.0 placeholder LINK is also flagged unsupported
assert mksub.node_from_link("vless://u@0.0.0.0:1#x")["recognized"] is False
# private subscription destinations are not activatable by default
assert mksub.node_from_link("vless://u@192.168.1.1:443#x")["recognized"] is False
# private targets in legacy encoded formats must not bypass the same policy
vm_private = "vmess://" + base64.b64encode(json.dumps({"add":"192.168.1.2","port":443,"id":"u"}).encode()).decode()
ss_private = "ss://" + base64.b64encode(b"aes-256-gcm:pw@192.168.1.3:8388").decode()
assert mksub.node_from_link(vm_private)["recognized"] is False
assert mksub.node_from_link(ss_private)["recognized"] is False
# Xray Trojan/SS profile shapes use settings.servers and must classify correctly
for proto in ("trojan", "shadowsocks"):
    shape={"outbounds":[{"protocol":proto,"tag":"proxy","settings":{"servers":[{"address":"public.example","port":443}]}}]}
    assert mksub._classify_profile(shape)[0] is True, (proto,mksub._classify_profile(shape))
# Current direct settings.address shape is also classified and safety-checked.
http_shape={"outbounds":[{"protocol":"http","tag":"proxy","settings":{"address":"public.example","port":3128}}]}
assert mksub._classify_profile(http_shape)[0] is True
# cosmetic remarks/key ordering do not change JSON profile identity
p1=dict(prof); p1["remarks"]="one"
p2=json.loads(json.dumps(p1,sort_keys=True)); p2["remarks"]="two"
c1=mksub.process_body(json.dumps([p1]).encode())["nodes"][0]["id"]
c2=mksub.process_body(json.dumps([p2]).encode())["nodes"][0]["id"]
assert c1==c2,(c1,c2)
# malformed shapes are rejected cleanly, never traversed into a TypeError
badshape=json.loads(json.dumps(prof)); badshape["routing"]["rules"]=None
assert mksub._classify_profile(badshape)[0] is False
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
# request/header ambiguities are rejected before any network operation
for bad_url in ("http://example.com/sub", "https://u:p@example.com/sub",
                "https://example.com/sub#fragment", "https://example.com/\r\nX: y"):
    try:
        mksub._validate_fetch_url(bad_url); raise AssertionError("accepted bad URL")
    except SystemExit:
        pass
assert mksub._validate_header_value("proxy-unifi/1.0", "User-Agent", 120) == "proxy-unifi/1.0"
for bad_header in ("bad\r\nX: y", "emoji-\U0001f600", "\u043a\u0438\u0440\u0438\u043b\u043b\u0438\u0446\u0430"):
    try:
        mksub._validate_header_value(bad_header, "User-Agent", 120)
        raise AssertionError("accepted bad header")
    except SystemExit:
        pass
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
  "outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "a.example", "port": 443}]}},
                {"protocol": "vless", "tag": "proxy-2", "settings": {"vnext": [{"address": "b.example", "port": 443}]}},
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
assert prof["log"]["access"] == "/Users/x/log"  # source profile stays immutable
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
# nested local-file primitives must be rejected before Xray validation
unsafe = json.loads(json.dumps(prof))
unsafe["outbounds"][0]["streamSettings"]={"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/dev/zero"}]}}
try:
    mkjson.validate_profile(unsafe); raise AssertionError("accepted provider local file")
except SystemExit:
    pass
# rules tied to a removed secondary inbound must not silently change semantics
removed = json.loads(json.dumps(prof))
removed["inbounds"].append({"tag":"http","protocol":"http"})
removed["routing"]["rules"].append({"type":"field","inboundTag":["http"],"outboundTag":"proxy"})
try:
    mkjson.validate_profile(removed); raise AssertionError("accepted removed inbound dependency")
except SystemExit:
    pass
# references to missing graph nodes must not survive into an ambiguously routed profile
missing = json.loads(json.dumps(prof))
missing["routing"]["rules"][0]["balancerTag"] = "missing"
try:
    mkjson.validate_profile(missing); raise AssertionError("accepted missing balancer reference")
except SystemExit:
    pass
# provider-controlled DNS aliases and freedom redirects cannot tunnel into local networks
for mutate in ("dns", "redirect"):
    local = json.loads(json.dumps(prof))
    if mutate == "dns":
        local["dns"] = {"servers":["1.1.1.1"], "hosts":{"public.example":"169.254.169.254"}}
    else:
        local["outbounds"].append({"protocol":"freedom","tag":"redir",
                                    "settings":{"redirect":"127.0.0.1:80"}})
    try:
        mkjson.validate_profile(local); raise AssertionError("accepted private %s target" % mutate)
    except SystemExit:
        pass
dns_forms = json.loads(json.dumps(prof))
dns_forms["dns"]={"servers":["tcp://1.1.1.1:53","tcp+local://8.8.8.8:53",
                             "https+local://dns.google/dns-query","quic+local://dns.adguard.com"]}
mkjson.validate_profile(dns_forms)
private_dns = json.loads(json.dumps(prof)); private_dns["dns"]={"servers":["192.168.1.1:53"]}
try:
    mkjson.validate_profile(private_dns); raise AssertionError("accepted private DNS host:port")
except SystemExit:
    pass
private_http = json.loads(json.dumps(prof))
private_http["outbounds"].append({"protocol":"http","tag":"http-private",
                                  "settings":{"address":"127.0.0.1","port":3128}})
try:
    mkjson.validate_profile(private_http); raise AssertionError("accepted private direct-address outbound")
except SystemExit:
    pass
# An unknown proxy destination shape must not bypass address validation.
unknown_target = json.loads(json.dumps(prof))
unknown_target["outbounds"].append({"protocol":"future-proxy","tag":"future",
                                    "settings":{"endpointHost":"127.0.0.1","endpointPort":443}})
try:
    mkjson.validate_profile(unknown_target); raise AssertionError("accepted unknown destination schema")
except SystemExit:
    pass
# Xray XHTTP may carry a second dial target inside downloadSettings.
xhttp = json.loads(json.dumps(prof))
xhttp["outbounds"][0]["streamSettings"]={"xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":80}}}
try:
    mkjson.validate_profile(xhttp); raise AssertionError("accepted private XHTTP download target")
except SystemExit:
    pass
# provider geodata jobs can replace local assets and are never part of pool routing semantics
with_geodata = json.loads(json.dumps(prof)); with_geodata["geodata"]={"cron":"* * * * *"}
assert "geodata" not in mkjson.sanitize_provider(with_geodata)
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
    _xurl="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-${_xos}-${_xa}.zip"
    curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 "$_xurl" -o "$CACHE/x.zip" \
        && curl -fsSL --connect-timeout 15 --max-time 60 --retry 3 "$_xurl.dgst" -o "$CACHE/x.dgst" \
        || return 1
    _xwant="$(awk -F'= ' 'tolower($1)~/sha2-256/{print tolower($2)}' "$CACHE/x.dgst" | tr -d ' \r' | head -1)"
    [ -n "$_xwant" ] && [ "$(sha256_of "$CACHE/x.zip")" = "$_xwant" ] || return 1
    unzip -oq "$CACHE/x.zip" -d "$CACHE" && chmod +x "$CACHE/xray" \
        && "$CACHE/xray" version >/dev/null 2>&1 || return 1
    _tag="$(curl -fsSLI --connect-timeout 15 --max-time 60 --retry 3 https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null | tr -d '\r' | awk -F'/tag/' 'tolower($0)~/location:/{print $2}' | awk '{print $1}' | tail -1)"; _v="${_tag#v}"
    [ -n "$_v" ] || return 1
    echo "  downloading sing-box $_tag ($_sos-$_sa) ..."
    _sbdir="$CACHE/sing-box-${_v}-${_sos}-${_sa}"
    rm -rf "$_sbdir"
    _sbname="sing-box-${_v}-${_sos}-${_sa}.tar.gz"
    curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 \
        "https://github.com/SagerNet/sing-box/releases/download/${_tag}/${_sbname}" -o "$CACHE/sb.tgz" \
        && curl -fsSL --connect-timeout 15 --max-time 60 --retry 3 \
        "https://api.github.com/repos/SagerNet/sing-box/releases/tags/${_tag}" -o "$CACHE/sb-release.json" \
        || return 1
    _sbwant="$(python3 - "$CACHE/sb-release.json" "$_sbname" <<'PY'
import json,sys
for asset in json.load(open(sys.argv[1],encoding="utf-8")).get("assets",[]):
    if asset.get("name")==sys.argv[2] and str(asset.get("digest","")).startswith("sha256:"):
        print(asset["digest"].split(":",1)[1]); break
PY
)"
    [ -n "$_sbwant" ] && [ "$(sha256_of "$CACHE/sb.tgz")" = "$_sbwant" ] \
        && tar xzf "$CACHE/sb.tgz" -C "$CACHE" \
        && [ -x "$_sbdir/sing-box" ] \
        && cp "$_sbdir/sing-box" "$CACHE/sing-box.new" \
        && mv -f "$CACHE/sing-box.new" "$CACHE/sing-box" \
        && chmod +x "$CACHE/sing-box" \
        && "$CACHE/sing-box" version | grep -q "version $_v"
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
    gx() { python3 "$SRC/mkxray.py" --link "$1" --port 51821 --secret-key "$XP" --peer-pubkey "$UP" > "$_d/c.json" 2>/dev/null \
           && "$XR" run -test -config "$_d/c.json" -format json >/dev/null 2>&1; }
    gs() { python3 "$SRC/mksingbox.py" --link "$1" --port 51821 --secret-key "$XP" --peer-pubkey "$UP" > "$_d/s.json" 2>/dev/null \
           && "$SG" check -c "$_d/s.json" >/dev/null 2>&1; }
    KEY="$("$XR" x25519 2>/dev/null | awk -F': ' '/Password|Public/{print $2}' | tail -1)"
    gx "vless://u@h:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=$KEY&sid=ab&sni=a&fp=chrome" && ok "xray vless reality" || bad "xray vless reality"
    gx "trojan://pw@h:443?security=tls&sni=a" && ok "xray trojan" || bad "xray trojan"
    gx "vless://u@h:443?type=kcp&security=none" && ok "xray mKCP" || bad "xray mKCP"
    _pcs="$(printf '%064d' 0)"
    gx "vless://u@h:443?security=tls&type=grpc&sni=a&authority=front.example&mode=multi&vcn=cert.example&pcs=$_pcs&user_agent=ua&idle_timeout=60&health_check_timeout=20&permit_without_stream=true&initial_windows_size=65536" \
        && ok "xray current TLS/gRPC share fields" || bad "xray current TLS/gRPC share fields"
    _xextra="$(python3 -c 'import json,urllib.parse; print(urllib.parse.quote(json.dumps({"scMaxEachPostBytes":1000000})))')"
    _xfm="$(python3 -c 'import json,urllib.parse; print(urllib.parse.quote(json.dumps({"tcp":[]})))')"
    gx "vless://u@h:443?security=tls&type=xhttp&sni=a&extra=$_xextra&fm=$_xfm" \
        && ok "xray current XHTTP/FinalMask share fields" || bad "xray current XHTTP/FinalMask share fields"
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

    if sh "$ROOT/tests/lifecycle.sh" "$XR" >/dev/null 2>&1; then ok "sandboxed CLI lifecycle + rollback"
    else bad "sandboxed CLI lifecycle + rollback"; fi
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
case "${1:-}" in --download) download_engines || { echo "  engine download failed"; exit 1; };; esac
static_tests
parser_tests
engine_tests
network_tests
echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = 0 ]
