#!/bin/sh
# shellcheck disable=SC2015  # cmd && ok || bad is intentional; ok()/bad() never fail.
# tests/run.sh - repeatable test suite for proxy-unifi (D28).
#
# Runs three tiers:
#   1. static  - shellcheck + dash -n + python compile on all sources (always).
#   2. parsers - generator/sub/json parsing + fuzz (always; pure Python, no network).
#   3. engine  - real xray-core / sing-box / optional AWG-core validation, and a
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
# py_case <name> [args...] runs the Python test program on stdin and reports one
# result. Its output (expected rejection messages, progress) is shown only on
# failure, so a passing run stays readable and a failing one keeps its traceback.
py_case() {
    _pc_name="$1"; shift
    if _pc_out="$(python3 - "$@" 2>&1)"; then ok "$_pc_name"
    else bad "$_pc_name"; printf '%s\n' "$_pc_out" | sed 's/^/       /'; fi
}
# A killed process stays a zombie until its parent reaps it; orphans go to PID 1,
# and some container inits never reap. kill -0 still succeeds on a zombie, which
# holds no resources, so only a live (non-zombie) process counts as surviving.
proc_alive() {
    kill -0 "$1" 2>/dev/null || return 1
    case "$(ps -o stat= -p "$1" 2>/dev/null)" in Z*) return 1 ;; esac
}
sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# start_bulk_server <dir>: serve 64 MB per GET on a free loopback port and set
# _bulk_pid/_bulk_port. bench_lib <dir> writes the CLI's bench helper as a lib.
start_bulk_server() {
    cat > "$1/bulk.py" <<'BULK'
import http.server, os, sys
class Bulk(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        chunk, count = bytes(1 << 20), 64
        self.send_response(200)
        self.send_header("Content-Length", str(len(chunk) * count))
        self.end_headers()
        try:
            for _ in range(count):
                self.wfile.write(chunk)
        except OSError:
            pass
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Bulk)
with open(sys.argv[1] + ".tmp", "w") as f: f.write(str(server.server_address[1]))
os.rename(sys.argv[1] + ".tmp", sys.argv[1])
server.serve_forever()
BULK
    python3 "$1/bulk.py" "$1/bulk.port" >/dev/null 2>&1 &
    _bulk_pid=$!; _i=0
    while [ ! -s "$1/bulk.port" ] && [ "$_i" -lt 100 ]; do
        _i=$((_i + 1)); sleep 0.05 2>/dev/null || sleep 1
    done
    _bulk_port="$(cat "$1/bulk.port" 2>/dev/null)"
}
bench_lib() {
    {
        # shellcheck disable=SC2016 # $1 belongs to the generated library.
        echo 'have() { command -v "$1" >/dev/null 2>&1; }'
        echo 'py() { python3 "$@"; }'
        sed -n '/^BENCH_STREAMS=/p; /^_bench_run() {/,/^}/p' "$SRC/proxy-unifi"
    } > "$1/bench-lib.sh"
}

# fn_src <function>...: print those functions from the CLI, one-liners included.
fn_src() {
    for _fn in "$@"; do
        awk -v name="$_fn" '
            !inside && index($0, name "() {") == 1 {
                print
                if ($0 !~ /}[[:space:]]*$/) inside = 1
                next
            }
            inside { print; if ($0 ~ /^}/) inside = 0 }
        ' "$SRC/proxy-unifi"
    done
}

# -------------------------------------------------------------------------
# tier 1: static analysis
# -------------------------------------------------------------------------
static_tests() {
    echo "== static =="
    # ShellCheck is the slowest static check; run it alongside the others and
    # report it at the end of this tier.
    _sc_log=""
    if have shellcheck; then
        _sc_log="$(mktemp)"
        shellcheck -s sh "$SRC/proxy-unifi" "$SRC/on_boot.sh" "$ROOT/install.sh" \
            "$ROOT/tests/run.sh" "$ROOT/tests/lifecycle.sh" "$ROOT/tests/ingress-lab.sh" > "$_sc_log" 2>&1 &
        _sc_pid=$!
    else printf '  skip shellcheck (not installed)\n'; fi
    if have dash; then
        _d=0
        for f in "$SRC/proxy-unifi" "$SRC/on_boot.sh" "$ROOT/install.sh" "$ROOT/tests/lifecycle.sh" \
                 "$ROOT/tests/ingress-lab.sh"; do
            dash -n "$f" 2>/dev/null || _d=1
        done
        if [ "$_d" = 0 ]; then ok "dash -n"; else bad "dash -n"; fi
    else printf '  skip dash -n (not installed)\n'; fi
    # The embedded unifi-common unit must stay loadable: an unbalanced quote in
    # ExecStart makes systemd drop the line and refuse the whole unit.
    _ud="$(mktemp -d)"
    sed -n "/^    cat > \"\$_unit\" <<'EOF'/,/^EOF/p" "$ROOT/install.sh" | sed '1d;$d' > "$_ud/udm-boot.service"
    sed "s|fi'\\\\'\$|fi'\\\\''|" "$_ud/udm-boot.service" > "$_ud/broken.service"
    if python3 - "$_ud/udm-boot.service" <<'PY'
import shlex, subprocess, sys
line = [l for l in open(sys.argv[1]) if l.startswith("ExecStart=")][0][10:].rstrip("\n")
argv = shlex.split(line)
assert argv[:2] == ["bash", "-c"] and len(argv) == 3
subprocess.check_call(["bash", "-n", "-c", argv[2]])
PY
    then ok "unifi-common boot unit parses"; else bad "unifi-common boot unit parses"; fi
    if have systemd-analyze; then
        if systemd-analyze verify "$_ud/udm-boot.service" >/dev/null 2>&1 \
           && ! systemd-analyze verify "$_ud/broken.service" >/dev/null 2>&1
        then ok "systemd verifies unifi-common boot unit"; else bad "systemd verifies unifi-common boot unit"; fi
    fi
    rm -rf "$_ud"
    if python3 -m py_compile "$SRC"/mkxray.py "$SRC"/mksingbox.py "$SRC"/mksub.py "$SRC"/mkawg.py "$SRC"/mkjson.py "$SRC"/proxylib.py "$SRC"/safeexec.py 2>/dev/null
    then ok "python compile"; else bad "python compile"; fi
    rm -rf "$SRC/__pycache__"
    if grep -Fq "sys.version_info < (3, 9)" "$ROOT/install.sh" \
       && grep -Fq "Python 3.9 or newer is required" "$ROOT/install.sh" \
       && ! grep -F "Python 3.7" "$SRC"/*.py >/dev/null 2>&1
    then ok "Python 3.9 gateway floor"; else bad "Python 3.9 gateway floor"; fi

    # A timed-out validator must terminate its complete process group, not leave
    # a grandchild consuming resources after the wrapper returns.
    _sd="$(mktemp -d)"
    # shellcheck disable=SC2016 # $!/\$1 must expand inside the child shell
    python3 "$SRC/safeexec.py" --user "$(id -un)" --timeout 1 --memory-mb 64 --fsize-mb 1 -- \
        sh -c 'trap "" TERM; sleep 30 & trap "" TERM; echo $! > "$1/child"; wait' sh "$_sd" >/dev/null 2>"$_sd/error"
    _src=$?; _child="$(cat "$_sd/child" 2>/dev/null || true)"; _dead=1
    [ -n "$_child" ] && proc_alive "$_child" && _dead=0
    if [ "$_src" = 124 ] && [ "$_dead" = 1 ]; then ok "safe validator timeout kills process group"
    else bad "safe validator timeout kills process group"; [ "$_dead" = 1 ] || kill "$_child" 2>/dev/null || true; fi
    rm -rf "$_sd"
    if [ "$(uname -s)" = Linux ]; then
        python3 "$SRC/safeexec.py" --user "$(id -un)" --timeout 10 --memory-mb 64 --fsize-mb 1 -- \
            python3 -c 'import os,time; os.fork() or (x:=bytearray(96*1024*1024),time.sleep(2)); time.sleep(2)' >/dev/null 2>&1
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
        echo 'SUB_USER_AGENT_DEFAULT="Happ/2.0"'
        echo 'SUB_USER_AGENT_LEGACY_DEFAULT="proxy-unifi/1.1"'
        sed -n '/^load_settings() {/,/^}/p' "$SRC/proxy-unifi"
    } > "$_ud/ua-lib.sh"
    cat > "$_ud/ua-check.sh" <<'SH'
. "$1"
SETTINGS="$2"; SUB_USER_AGENT="$SUB_USER_AGENT_DEFAULT"
load_settings
[ "$SUB_USER_AGENT" = "$3" ]
SH
    python3 - "$_ud/settings" <<'PY'
import sys
value = "".join(chr(x) for x in (0x43a, 0x438, 0x440, 0x438, 0x43b, 0x43b, 0x438, 0x446, 0x430))
open(sys.argv[1], "w", encoding="utf-8").write('SUB_USER_AGENT="%s"\n' % value)
PY
    if sh "$_ud/ua-check.sh" "$_ud/ua-lib.sh" "$_ud/settings" "Happ/2.0"; then ok "settings User-Agent rejects non-ASCII"
    else bad "settings User-Agent rejects non-ASCII"; fi
    printf '%s\n' 'SUB_USER_AGENT="proxy-unifi/1.1"' > "$_ud/settings"
    if sh "$_ud/ua-check.sh" "$_ud/ua-lib.sh" "$_ud/settings" "Happ/2.0"; then ok "settings User-Agent migrates legacy default"
    else bad "settings User-Agent migrates legacy default"; fi
    printf '%s\n' 'SUB_USER_AGENT="Streisand/1.0"' > "$_ud/settings"
    if sh "$_ud/ua-check.sh" "$_ud/ua-lib.sh" "$_ud/settings" "Streisand/1.0"; then ok "settings User-Agent preserves custom value"
    else bad "settings User-Agent preserves custom value"; fi
    rm -rf "$_ud"

    _ed="$(mktemp -d)"
    {
        sed -n '/^wg_endpoint() {/,/^}/p' "$SRC/proxy-unifi"
        sed -n '/^format_endpoint() {/,/^}/p' "$SRC/proxy-unifi"
        cat <<'SH'
WG_LISTEN="127.0.0.1"; WG_PORT="51821"
[ "$(wg_endpoint)" = "127.0.0.1:51821" ] || exit 1
WG_LISTEN="2001:db8::1"; WG_PORT="51821"
[ "$(wg_endpoint)" = "[2001:db8::1]:51821" ] || exit 1
[ "$(format_endpoint "2001:db8::2" 443)" = "[2001:db8::2]:443" ] || exit 1
[ "$(format_endpoint "vpn.example" 443)" = "vpn.example:443" ] || exit 1
SH
    } > "$_ed/endpoint.sh"
    if sh "$_ed/endpoint.sh"; then ok "CLI WireGuard endpoint formats IPv6"
    else bad "CLI WireGuard endpoint formats IPv6"; fi
    rm -rf "$_ed"

    _ping_proxy="$(sed -n '/^_probe_start() {/,/^}/p;/^ping_proxy() {/,/^}/p' "$SRC/proxy-unifi")"
    # shellcheck disable=SC2016 # Match literal variables in the extracted source.
    if printf '%s\n' "$_ping_proxy" | grep -Fq '_proxy_scheme="socks5h"' \
       && printf '%s\n' "$_ping_proxy" | grep -Fq '_proxy_scheme="socks5"' \
       && printf '%s\n' "$_ping_proxy" | grep -Fq '"${_proxy_scheme}://127.0.0.1:${_port}"'
    then ok "AWG latency probe resolves before SOCKS"; else bad "AWG latency probe resolves before SOCKS"; fi

    _hd="$(mktemp -d)"
    {
        echo 'py() { python3 "$@"; }'
        sed -n 's/^AWG_CORE_VERSION="\([^"]*\)"/AWG_CORE_VERSION="\1"/p' "$SRC/proxy-unifi"
        sed -n '/^xray_min_safe_sha256() {/,/^}/p' "$SRC/proxy-unifi"
        sed -n '/^awg_core_sha256() {/,/^}/p' "$SRC/proxy-unifi"
        sed -n '/^xray_tag_at_least() {/,/^}/p' "$SRC/proxy-unifi"
        cat <<'SH'
[ "$(xray_min_safe_sha256 64)" = aa11c3685c71da0ffc71e511db50404609e7e963bb914b048f59a6a00af8930e ]
[ "$(xray_min_safe_sha256 arm64-v8a)" = 89cfe01674d7c9f6847b7dd9389537be9acb3b9dc3c6cb9fdeba87a3e4e57fc1 ]
[ "$(xray_min_safe_sha256 arm32-v7a)" = c623b8d08d02d7a20be697619fde11c6745efb08ac5cb332ab0ff15fe567aad6 ]
! xray_min_safe_sha256 mips >/dev/null 2>&1
[ "$AWG_CORE_VERSION" = 1.1.0 ]
[ "$(awg_core_sha256 amd64)" = 70f5a34514a25ab53ccc47011a8be11a2a497df08f1a0d90117708c92876202e ]
[ "$(awg_core_sha256 arm64)" = 68cd53823b7a6e386c161ce08e194a5b061a27ffc058b6dfbc480abf1eb63f52 ]
[ "$(awg_core_sha256 armv7)" = 7a547f4ded5e4fe90bbdcabc9bfe20383140a7e397c54a02494715729a381aa7 ]
! awg_core_sha256 mips >/dev/null 2>&1
xray_tag_at_least v26.7.11 v26.7.11
xray_tag_at_least v27.1.1 v26.7.11
! xray_tag_at_least v26.7.10 v26.7.11
! xray_tag_at_least latest v26.7.11 >/dev/null 2>&1
SH
    } > "$_hd/hashes.sh"
    if sh "$_hd/hashes.sh"; then ok "core security floors and immutable digests"
    else bad "core security floors and immutable digests"; fi
    rm -rf "$_hd"

    _ad="$(mktemp -d)"
    mkdir -p "$_ad/package"
    cat > "$_ad/package/amnezia-box" <<'SH'
#!/bin/sh
[ "${1:-}" = version ] || exit 2
echo 'sing-box version proxy-unifi-awg-1.1.0'
SH
    chmod 0755 "$_ad/package/amnezia-box"
    python3 - "$_ad/good.tgz" "$_ad/package" "$_ad/bad.tgz" <<'PY'
import io,sys,tarfile
with tarfile.open(sys.argv[1], "w:gz") as archive:
    archive.add(sys.argv[2], arcname="proxy-unifi-amnezia-box")
with tarfile.open(sys.argv[3], "w:gz") as archive:
    member=tarfile.TarInfo("../escape")
    member.size=1
    archive.addfile(member,io.BytesIO(b"x"))
PY
    cat > "$_ad/install-awg.sh" <<'SH'
set -eu
BIN_DIR="$WORK/bin"; ABIN="$BIN_DIR/amnezia-box"; RUN_DIR=""
AWG_CORE_VERSION=1.1.0; AWG_CORE_TAG=awg-core-v1.1.0
AWG_CORE_RELEASES=https://invalid.example
have() { command -v "$1" >/dev/null 2>&1; }
sb_arch() { echo arm64; }
ensure_run_dir() { RUN_DIR="$WORK/run"; mkdir -p "$RUN_DIR"; }
download_to() { cp "$ARCHIVE" "$2"; }
awg_core_sha256() { printf '%s\n' "$EXPECTED"; }
verify_sha256() {
    _got="$(python3 - "$1" <<'PY'
import hashlib,sys
print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())
PY
)"
    [ "$_got" = "$2" ]
}
py() { python3 "$@"; }
current_engine() { echo xray; }
info() { :; }; err() { :; }; c_grn() { :; }
core_version() { "$1" version | head -1; }
SH
    sed -n '/^safe_untar() {/,/^}/p; /^cmd_install_awg() {/,/^}/p' "$SRC/proxy-unifi" >> "$_ad/install-awg.sh"
    cat >> "$_ad/install-awg.sh" <<'SH'
cmd_install_awg
[ -x "$ABIN" ]
"$ABIN" version | grep -q 'proxy-unifi-awg-1.1.0'
[ ! -e "$ABIN.new" ] && [ ! -e "$ABIN.bak" ] && [ ! -e "$ABIN.bak.new" ]
SH
    _good_digest="$(sha256_of "$_ad/good.tgz")"
    _bad_digest="$(sha256_of "$_ad/bad.tgz")"
    _awg_install_ok=1
    WORK="$_ad/work" ARCHIVE="$_ad/good.tgz" EXPECTED="$_good_digest" \
        sh "$_ad/install-awg.sh" || _awg_install_ok=0
    _old_core="$(sha256_of "$_ad/work/bin/amnezia-box")"
    if WORK="$_ad/work" ARCHIVE="$_ad/bad.tgz" EXPECTED="$_bad_digest" \
        sh "$_ad/install-awg.sh" >/dev/null 2>&1; then
        _awg_install_ok=0
    fi
    [ ! -e "$_ad/work/escape" ] || _awg_install_ok=0
    [ "$(sha256_of "$_ad/work/bin/amnezia-box")" = "$_old_core" ] \
        || _awg_install_ok=0
    [ "$_awg_install_ok" = 1 ] && ok "AWG core installer validates and safely promotes archive" \
        || bad "AWG core installer validates and safely promotes archive"
    rm -rf "$_ad"

    # The installer-wide rollback must restore scripts, all cores, and geo
    # assets from one retained promotion backup.
    _id="$(mktemp -d)"
    mkdir -p "$_id/live" "$_id/backup"
    for _f in proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py \
              xray sing-box amnezia-box geoip.dat geosite.dat; do
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
        for _f in proxy-unifi mkawg.py xray sing-box amnezia-box geoip.dat geosite.dat; do
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

    # Before restoring older scripts, a rollback removes the kernel WireGuard
    # path with the new ones (older scripts may not know it); a successful
    # install leaves the running path alone.
    _id="$(mktemp -d)"
    mkdir -p "$_id/bin"
    printf '#!/bin/sh\necho "cli $*" >> "%s/log"\n' "$_id" > "$_id/bin/proxy-unifi"
    chmod 755 "$_id/bin/proxy-unifi"
    {
        cat <<SH
KERNEL_INGRESS_MARKER='$_id/kernel'; PROMOTION_MARKER='$_id/promotion'
SERVICE_STATE_MARKER='$_id/state'; BIN_DIR='$_id/bin'; LOG_FILE='$_id/log'
SH
        cat <<'SH'
ACTIVE_PID=""
log() { echo "$*" >> "$LOG_FILE"; }
systemctl() { log "systemctl $*"; }
restore_promotion() { log restore_promotion; }
restore_service_state() { log restore_service_state; }
release_install_lock() { :; }
red() { :; }
SH
        awk '/^teardown_kernel_ingress\(\) \{/,/^}/; /^cleanup\(\) \{/,/^}/' "$ROOT/install.sh"
        # shellcheck disable=SC2016 # expanded by the generated script
        echo 'WORKDIR="$(mktemp -d)"; cleanup 1'
    } > "$_id/cleanup.sh"
    _rollback() {  # <markers...>: run the installer's cleanup, print its calls
        rm -f "$_id/log" "$_id/kernel" "$_id/promotion" "$_id/state"
        for _m in "$@"; do : > "$_id/$_m"; done
        sh "$_id/cleanup.sh" 2>/dev/null
        tr '\n' ';' < "$_id/log"
    }
    _teardown_ok=1
    [ "$(_rollback kernel promotion state)" = "systemctl stop proxy-unifi.service;cli _ingress-down;restore_promotion;restore_service_state;" ] \
        || _teardown_ok=0
    [ "$(_rollback promotion state)" = "restore_promotion;restore_service_state;" ] || _teardown_ok=0
    [ "$(_rollback kernel)" = "restore_promotion;restore_service_state;" ] || _teardown_ok=0
    [ "$_teardown_ok" = 1 ] && ok "installer rollback removes the kernel path first" \
        || bad "installer rollback removes the kernel path first"
    rm -rf "$_id"

    _bd="$(mktemp -d)"
    mkdir -p "$_bd/archive-root/src" "$_bd/work"
    for _f in proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py on_boot.sh; do
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
fetch mkawg.py "$WORKDIR/out" 0644 || exit 1
grep -q '^bundle:mkawg.py$' "$WORKDIR/out"
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
    SBIN=/b/sing-box; ABIN=/b/amnezia-box; XRAY=/b/xray; CONFIG=/c/config.json; POOL_DIR=/c/pool
BIN_DIR=/b; ROOT=/r; SERVICE_FILE="$WORK/unit"; INGRESS_OVERLAY=/run/x/ingress.json
current_engine() { echo "$ENG"; }
ingress_wanted() { [ "${KERNEL:-0}" = 1 ]; }
prepare_service_permissions() { :; }
systemctl() { :; }
atomic_write() { cat > "$1"; }
cpu_count() { echo "${NCPU:-4}"; }
SH
    {
        sed -n '/^CORE_GO[A-Z]*=/p' "$SRC/proxy-unifi"
        sed -n '/^core_gomaxprocs() {/,/^}/p' "$SRC/proxy-unifi"
        awk '/^write_service\(\) \{/,/^}/' "$SRC/proxy-unifi"
        echo 'write_service'
    } >> "$_ud/h.sh"
    # Every start first removes a kernel ingress left by an Xray core.
    _pre_down='ExecStartPre=-+/b/proxy-unifi _ingress-down'
    _fw_ok=1
    ENG=singbox  WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    [ "$(grep '^ExecStartPre=' "$_ud/unit")" = "$_pre_down
ExecStartPre=+/b/proxy-unifi _fw-lock" ] || _fw_ok=0
    grep -q '^ExecStopPost=-+/b/proxy-unifi _fw-unlock$' "$_ud/unit" || _fw_ok=0
    ENG=awg      WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStart=/b/amnezia-box run -c /c/config.json$' "$_ud/unit" || _fw_ok=0
    [ "$(grep '^ExecStartPre=' "$_ud/unit")" = "$_pre_down
ExecStartPre=+/b/proxy-unifi _fw-lock" ] || _fw_ok=0
    grep -q '^ExecStopPost=-+/b/proxy-unifi _fw-unlock$' "$_ud/unit" || _fw_ok=0
    ENG=xray     WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    [ "$(grep '^ExecStartPre=' "$_ud/unit")" = "$_pre_down" ] || _fw_ok=0
    grep -q '_fw-lock' "$_ud/unit" && _fw_ok=0          # xray must NOT lock a port
    [ "$_fw_ok" = 1 ] && ok "singbox/AWG WG port firewalled (unit)" || bad "singbox/AWG WG port firewalled (unit)"
    # Kernel ingress: built before the core, loaded last, torn down after it;
    # only then may the core bind transparent sockets.
    _ki_ok=1
    grep -q '^ExecStart=/b/xray run -config /c/config.json$' "$_ud/unit" || _ki_ok=0
    grep -q '^CapabilityBoundingSet=$' "$_ud/unit" || _ki_ok=0
    grep -q '^AmbientCapabilities=$' "$_ud/unit" || _ki_ok=0
    ENG=xraypool WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStart=/b/xray run -confdir /c/pool$' "$_ud/unit" || _ki_ok=0
    KERNEL=1 ENG=xray WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    [ "$(grep '^ExecStartPre=' "$_ud/unit")" = 'ExecStartPre=+/b/proxy-unifi _ingress-up' ] || _ki_ok=0
    grep -q '^ExecStopPost=-+/b/proxy-unifi _ingress-down$' "$_ud/unit" || _ki_ok=0
    grep -q '^ExecStart=/b/xray run -config /c/config.json -config /run/x/ingress.json$' "$_ud/unit" || _ki_ok=0
    grep -q '^CapabilityBoundingSet=CAP_NET_RAW$' "$_ud/unit" || _ki_ok=0
    grep -q '^AmbientCapabilities=CAP_NET_RAW$' "$_ud/unit" || _ki_ok=0
    grep -q '^NoNewPrivileges=true$' "$_ud/unit" || _ki_ok=0
    KERNEL=1 ENG=xraypool WORK="$_ud" sh "$_ud/h.sh" 2>/dev/null
    grep -q '^ExecStart=/b/xray run -config /c/pool/01-provider.json -config /c/pool/99-overlay.json -config /run/x/ingress.json$' "$_ud/unit" || _ki_ok=0
    [ "$_ki_ok" = 1 ] && ok "kernel WireGuard ingress wired into the unit" \
        || bad "kernel WireGuard ingress wired into the unit"
    # The core's parallelism comes from GOMAXPROCS (no quota, default weight in
    # its own cgroup), and its Go heap stays below the unit's memory ceiling.
    _cpu_ok=1
    grep -q '^CPUQuota=' "$_ud/unit" && _cpu_ok=0
    grep -q '^CPUWeight=' "$_ud/unit" && _cpu_ok=0
    grep -q '^Environment=GOGC=' "$_ud/unit" && _cpu_ok=0
    grep -q '^CPUAccounting=yes$' "$_ud/unit" || _cpu_ok=0
    grep -q '^Environment=GOMAXPROCS=3$' "$_ud/unit" || _cpu_ok=0
    grep -q '^MemoryMax=512M$' "$_ud/unit" || _cpu_ok=0
    grep -q '^Environment=GOMEMLIMIT=384MiB$' "$_ud/unit" || _cpu_ok=0
    # shellcheck disable=SC2016 # $NCPU and $c expand in the generated script
    {
        echo 'cpu_count() { echo "$NCPU"; }'
        sed -n '/^core_gomaxprocs() {/,/^}/p' "$SRC/proxy-unifi"
        echo 'for c in 1:1 2:2 3:2 4:3 8:7; do [ "$(NCPU=${c%:*} core_gomaxprocs)" = "${c#*:}" ] || exit 1; done'
    } > "$_ud/procs.sh"
    sh "$_ud/procs.sh" || _cpu_ok=0
    [ "$_cpu_ok" = 1 ] && ok "service unit sizes Go threads to leave a CPU free" \
        || bad "service unit sizes Go threads to leave a CPU free"
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

    # Kernel ingress only for Xray cores on loopback with single IPv4 tunnel
    # addresses and the tools present.
    _kd="$(mktemp -d)"
    {
        cat <<'SH'
have() { case "$1" in ip|wg|iptables) [ "${NO_TOOLS:-0}" = 0 ] ;; *) command -v "$1" >/dev/null 2>&1 ;; esac; }
current_engine() { echo "$ENG"; }
SH
        fn_src _ingress_ipv4 ingress_supported ingress_configured ingress_wanted
        cat <<'SH'
for good in 10.7.0.1/32 10.7.0.1 192.168.1.255; do _ingress_ipv4 "$good" >/dev/null || exit 1; done
[ "$(_ingress_ipv4 10.7.0.1/32)" = 10.7.0.1 ] || exit 1
for bad in "" 10.7.0.1/24 10.7.0 10.7.0.1.5 10.7.0.256 fd00::1 10.7.0.1,10.7.0.2 .1.2.3 1..2.3; do
    if _ingress_ipv4 "$bad" >/dev/null; then echo "accepted '$bad'"; exit 1; fi
done
INGRESS=kernel; WG_LISTEN=127.0.0.1; XRAY_ADDR=10.7.0.1/32; UNIFI_ADDR=10.7.0.2/32
for ENG in xray xraypool; do ingress_wanted || exit 1; done
for ENG in singbox awg; do if ingress_wanted; then exit 1; fi; done
ENG=xray
if INGRESS=userspace ingress_wanted; then exit 1; fi
if WG_LISTEN=0.0.0.0 ingress_wanted; then exit 1; fi
if XRAY_ADDR=10.7.0.1/32,fd00::1/128 ingress_wanted; then exit 1; fi
if NO_TOOLS=1 ingress_wanted; then exit 1; fi
exit 0
SH
    } > "$_kd/decide.sh"
    if sh "$_kd/decide.sh"; then ok "kernel ingress only where it applies"
    else bad "kernel ingress only where it applies"; fi

    # The kernel overlay follows Xray's merge of the loaded configs and keeps
    # the private-target block Xray gives WireGuard inbounds on direct routes.
    {
        echo 'py() { python3 "$@"; }'
        echo 'INGRESS_HOST_IP=169.254.77.1; INGRESS_PORT=41820'
        fn_src ingress_overlay_for
    } > "$_kd/overlay.sh"
    if python3 - "$_kd" <<'PY'
import json, os, subprocess, sys
work = sys.argv[1]
wg = {"tag": "in", "protocol": "wireguard", "sniffing": {"enabled": True, "routeOnly": True}}
def overlay(*configs):
    paths = []
    for number, config in enumerate(configs):
        paths.append(os.path.join(work, "c%d.json" % number))
        json.dump(config, open(paths[-1], "w"))
    run = subprocess.run(["sh", "-c", '. "$0/overlay.sh"; ingress_overlay_for "$@"', work] + paths,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return json.loads(run.stdout) if run.returncode == 0 else None
allow = {"action": "allow", "ip": ["10.1.1.1/32"]}
result = overlay({"inbounds": [wg], "outbounds": [
    {"tag": "proxy", "protocol": "vless"},
    {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [allow]}},
    {"tag": "alias", "protocol": "direct"}, {"tag": "block", "protocol": "blackhole"}]})
inbound, = result["inbounds"]
assert (inbound["tag"], inbound["protocol"], inbound["port"]) == ("in", "dokodemo-door", 41820)
assert inbound["sniffing"] == wg["sniffing"]
direct, alias = result["outbounds"]
assert direct["tag"] == "direct" and direct["settings"]["finalRules"][0] == allow
assert direct["settings"]["finalRules"][1]["action"] == "block"
assert {"10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16"} <= set(direct["settings"]["finalRules"][1]["ip"])
assert alias["tag"] == "alias" and alias["settings"]["finalRules"][0]["action"] == "block"
# Nothing to guard: no outbounds in the overlay.
assert "outbounds" not in overlay({"inbounds": [wg], "outbounds": [{"tag": "p", "protocol": "vless"}]})
# A lone untagged direct outbound is replaced in place; beside another
# untagged outbound it cannot be, so kernel mode is refused.
assert overlay({"inbounds": [wg], "outbounds": [{"protocol": "freedom"}, {"tag": "p", "protocol": "vless"}]})
assert overlay({"inbounds": [wg], "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole"}]}) is None
# Later configs replace by tag, as Xray merges them.
socks = {"tag": "in", "protocol": "socks"}
assert overlay({"inbounds": [socks]}, {"inbounds": [wg]})["inbounds"][0]["tag"] == "in"
assert overlay({"inbounds": [wg]}, {"inbounds": [socks]}) is None
assert overlay({"inbounds": [wg, dict(wg, tag="other")]}) is None
PY
    then ok "kernel overlay keeps Xray's private-target guard"
    else bad "kernel overlay keeps Xray's private-target guard"; fi

    # Health: in kernel mode the kernel holds the WireGuard port and the core
    # must own the transparent listener; otherwise the core owns the port.
    {
        cat <<'SH'
WG_PORT=51821; INGRESS_PORT=41820; INGRESS_ACTIVE="$WORK/active"; SERVICE_NAME=proxy-unifi
have() { return 0; }
systemctl() { printf 'ActiveState=active\nMainPID=%s\n' "$$"; }
ss() {
    echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
    case "$1" in
        -lun|-lunp) [ -z "${UDP:-}" ] || echo "UNCONN 0 0 0.0.0.0:51821 0.0.0.0:* $UDP" ;;
        -ltn|-ltnp) [ -z "${TCP:-}" ] || echo "LISTEN 0 4096 169.254.77.1:41820 0.0.0.0:* $TCP" ;;
    esac
}
SH
        fn_src ingress_active _socket_listening socket_listening tcp_socket_listening \
            socket_owned_by_pid service_healthy
        cat <<'SH'
own="users:((\"xray\",pid=$$,fd=3))"; other='users:(("xray",pid=1,fd=3))'
UDP="$own" service_healthy || exit 1
if UDP="$other" service_healthy; then exit 1; fi
if UDP=" " TCP="$own" service_healthy; then exit 1; fi
: > "$INGRESS_ACTIVE"
UDP=" " TCP="$own" service_healthy || exit 1
if UDP=" " TCP="$other" service_healthy; then exit 1; fi
if TCP="$own" service_healthy; then exit 1; fi
exit 0
SH
    } > "$_kd/health.sh"
    if WORK="$_kd" sh "$_kd/health.sh"; then ok "health check follows the ingress mode"
    else bad "health check follows the ingress mode"; fi
    rm -f "$_kd/active"

    # A profile the kernel path cannot take is still imported (with a warning);
    # the service then runs it on Xray's WireGuard.
    {
        cat <<'SH'
ETC_DIR="$WORK"; SERVICE_GROUP="$(id -gn)"; XRAY=/x
chown() { :; }   # the CLI hands the overlay to root; CI does not run as root
ingress_configured() { return 0; }
ingress_overlay_for() { [ "${OVERLAY:-1}" = 1 ] || { echo "no tagged inbound" >&2; return 1; }; echo '{}'; }
validate_as_service() { [ "${LOADS:-1}" = 1 ]; }
fatal() { echo "fatal $*"; exit 9; }
c_ylw() { echo "$*"; }
SH
        fn_src validate_ingress_overlay
        cat <<'SH'
[ -z "$(validate_ingress_overlay a.json b.json)" ] || exit 1
_out="$(OVERLAY=0 validate_ingress_overlay a.json)" || exit 1
case "$_out" in *"(no tagged inbound)"*"Xray's WireGuard"*) : ;; *) exit 1 ;; esac
_out="$(LOADS=0 validate_ingress_overlay a.json)" || exit 1
case "$_out" in *"(xray rejected the kernel-mode overlay)"*) : ;; *) exit 1 ;; esac
for _left in "$WORK"/.ingress.*; do [ ! -e "$_left" ] || exit 1; done   # no temp overlay left
SH
    } > "$_kd/validate.sh"
    if WORK="$_kd" sh "$_kd/validate.sh"; then ok "an unsuitable profile is imported with a warning"
    else bad "an unsuitable profile is imported with a warning"; fi

    # A core that fails its health check on the kernel path is restarted once on
    # Xray's WireGuard; if that fails too, the next start tries the kernel again.
    {
        cat <<'SH'
CONFIG="$WORK/config.json"; POOL_DIR="$WORK/pool"; SERVICE_NAME=proxy-unifi
INGRESS_RUN="$WORK/run"; INGRESS_FAILS="$WORK/run/failures"
log() { echo "$*" >> "$WORK/calls"; }
systemctl() { log "$1"; }
sleep() { :; }
c_ylw() { log warn; }
ingress_wanted() { [ "${WANTED:-1}" = 1 ]; }
service_healthy() {
    if [ -e "$INGRESS_FAILS" ]; then [ "${USERSPACE:-1}" = 1 ]; else [ "${KERNEL:-1}" = 1 ]; fi
}
SH
        fn_src ingress_retry restart_service _restart_healthy
        cat <<'SH'
: > "$CONFIG"; mkdir -p "$INGRESS_RUN"
calls() { rm -f "$WORK/calls"; restart_service; printf 'rc=%s ' "$?"; tr '\n' ' ' < "$WORK/calls"; }
[ "$(calls)" = "rc=0 restart " ] || exit 1
[ ! -e "$INGRESS_FAILS" ] || exit 1
[ "$(KERNEL=0 calls)" = "rc=0 restart restart warn " ] || exit 1
[ "$(cat "$INGRESS_FAILS")" = 3 ] || exit 1
[ "$(KERNEL=0 USERSPACE=0 calls)" = "rc=1 restart restart " ] || exit 1
[ ! -e "$INGRESS_FAILS" ] || exit 1
[ "$(WANTED=0 KERNEL=0 calls)" = "rc=1 restart " ] || exit 1
SH
    } > "$_kd/restart.sh"
    if WORK="$_kd" sh "$_kd/restart.sh"; then ok "a kernel path that fails its health check falls back"
    else bad "a kernel path that fails its health check falls back"; fi

    # The guard timer leaves a starting or stopping unit to its own hooks,
    # repairs the kernel path while the core runs, and removes it after.
    {
        cat <<'SH'
SERVICE_NAME=proxy-unifi; INGRESS_ACTIVE="$WORK/active"; INGRESS_FAILS="$WORK/fails"
log() { echo "$*" >> "$WORK/calls"; }
systemctl() { case "$1" in show) echo "ActiveState=$STATE" ;; restart) log restart ;; esac; }
ip() { [ "${LINKS:-1}" = 1 ]; }
current_engine() { echo "$ENG"; }
fw_lock() { log fw_lock; }
fw_unlock() { log fw_unlock; }
ingress_down() { log ingress_down; rm -f "$INGRESS_ACTIVE"; }
service_healthy() { [ "${HEALTHY:-1}" = 1 ]; }
_ingress_count_failure() { log count_failure; }
_ingress_rules_ok() { log rules_ok; [ "${RULES_OK:-1}" = 1 ]; }
_ingress_rules_add() { log rules_add; }
SH
        fn_src ingress_active _unit_state fw_reconcile
        cat <<'SH'
calls() { rm -f "$WORK/calls"; fw_reconcile; { tr '\n' ' ' < "$WORK/calls"; } 2>/dev/null; }
ENG=xray
[ "$(STATE=activating calls)" = "" ] || exit 1
[ "$(STATE=deactivating calls)" = "" ] || exit 1
[ "$(STATE=active calls)" = "fw_unlock " ] || exit 1
: > "$INGRESS_ACTIVE"
[ "$(STATE=activating calls)" = "" ] || exit 1
echo 2 > "$INGRESS_FAILS"
[ "$(STATE=active HEALTHY=0 calls)" = "fw_lock rules_ok " ] || exit 1
[ -f "$INGRESS_FAILS" ] || exit 1      # not healthy: the failures still count
[ "$(STATE=active calls)" = "fw_lock rules_ok " ] || exit 1
[ ! -e "$INGRESS_FAILS" ] || exit 1    # seen healthy: the count starts over
[ "$(STATE=active RULES_OK=0 calls)" = "fw_lock rules_ok rules_add " ] || exit 1
[ "$(STATE=active LINKS=0 calls)" = "fw_lock count_failure restart " ] || exit 1
[ "$(STATE= calls)" = "" ] || exit 1   # systemd did not answer: change nothing
[ -f "$INGRESS_ACTIVE" ] || exit 1
[ "$(STATE=failed calls)" = "ingress_down fw_unlock " ] || exit 1
ENG=singbox
[ "$(STATE=active calls)" = "fw_lock " ] || exit 1
[ "$(STATE=inactive calls)" = "fw_unlock " ] || exit 1
SH
    } > "$_kd/reconcile.sh"
    if WORK="$_kd" sh "$_kd/reconcile.sh"; then ok "guard reconciles by unit state"
    else bad "guard reconciles by unit state"; fi

    # bench line 3 finds the UniFi client by the peer key it dials.
    {
        cat <<'SH'
WG_DIR="$WORK"
have() { return 0; }
SH
        fn_src unifi_client_if
        cat <<'SH'
echo 'OURKEY=' > "$WORK/wg_public.key"
wg() { printf 'wgsrv1\tROAD=\nwgclt1\tOTHER=\nwgclt2\tOURKEY=\n'; }
[ "$(unifi_client_if)" = wgclt2 ] || exit 1
wg() { printf 'wgclt1\tOTHER=\n'; }
[ -z "$(unifi_client_if)" ] || exit 1
SH
    } > "$_kd/client.sh"
    if WORK="$_kd" sh "$_kd/client.sh"; then ok "bench finds the UniFi client interface"
    else bad "bench finds the UniFi client interface"; fi
    rm -rf "$_kd"

    if [ -n "$_sc_log" ]; then
        if wait "$_sc_pid"; then ok "shellcheck"
        else bad "shellcheck"; cat "$_sc_log"; fi
        rm -f "$_sc_log"
    fi
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

ss_test_key() {  # byte length -> deterministic standard-base64 PSK
    python3 - "$1" <<'PY'
import base64,sys
size=int(sys.argv[1])
print(base64.b64encode(bytes((n % 251) + 1 for n in range(size))).decode())
PY
}

ss_test_link() {  # method password [query] -> SIP002 link
    python3 - "$1" "$2" "${3:-}" <<'PY'
import base64,sys
credentials=base64.urlsafe_b64encode((sys.argv[1]+":"+sys.argv[2]).encode()).decode().rstrip("=")
print("ss://%s@h:8388%s#SS2022" % (credentials,sys.argv[3]))
PY
}

parser_tests() {
    echo "== parsers =="
    KEY=cvttX9u3nd7XD16gF4LJ09KjFZ0ZN4x9nk2TQePX5jk
    VM="vmess://$(printf '{"add":"h","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"ws","tls":"tls","host":"h","path":"/w"}' | base64 | tr -d '\n')"
    SS16="$(ss_test_key 16)"; SS32="$(ss_test_key 32)"; SS15="$(ss_test_key 15)"
    SS22A128="$(ss_test_link 2022-blake3-aes-128-gcm "$SS16")"
    SS22A128_UNPADDED="$(ss_test_link 2022-blake3-aes-128-gcm "$(printf '%s' "$SS16" | tr -d '=')")"
    SS22A256="$(ss_test_link 2022-blake3-aes-256-gcm "$SS32")"
    SS22CHACHA="$(ss_test_link 2022-blake3-chacha20-poly1305 "$SS32")"
    SS22CHACHA_MULTI="$(ss_test_link 2022-blake3-chacha20-poly1305 "$SS32:$SS32")"
    SS22MULTI="$(ss_test_link 2022-blake3-aes-128-gcm "$SS16:$SS16")"
    SS22CHAIN="$(ss_test_link 2022-blake3-aes-256-gcm "$SS32:$SS32:$SS32")"
    SS22COMPAT="$(ss_test_link 2022-blake3-aes-128-gcm "$SS32")"
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
    expect mksingbox.py "$SS22A128" accept "SS2022 AES-128"
    expect mksingbox.py "$SS22A128_UNPADDED" accept "SS2022 unpadded key normalization"
    expect mksingbox.py "$SS22A256" accept "SS2022 AES-256"
    expect mksingbox.py "$SS22CHACHA" accept "SS2022 ChaCha20"
    expect mksingbox.py "$SS22MULTI" accept "SS2022 multi-user key"
    expect mksingbox.py "$SS22CHAIN" accept "SS2022 relay identity chain"
    expect mkxray.py "$SS22COMPAT" accept "SS2022 Xray 32-byte AES-128 compatibility"
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
    expect mksingbox.py "hysteria2://pw@h:443?insecure=1" reject "sing-box TLS disable rejected"
    expect mksingbox.py "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?allowInsecure=true" reject "TUIC TLS disable rejected"
    expect mksingbox.py "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?sni=h&udp_over_stream=maybe" reject "invalid TUIC boolean rejected"
    expect mksingbox.py "$(ss_test_link 2022-blake3-aes-128-gcm "$SS15")" reject "SS2022 short key rejected"
    expect mkxray.py "$(ss_test_link 2022-blake3-aes-256-gcm "$SS16")" reject "SS2022 wrong AES-256 key rejected"
    expect mksingbox.py "$(ss_test_link 2022-blake3-chacha20-poly1305 'not_base64!')" reject "SS2022 invalid base64 rejected"
    expect mksingbox.py "$(ss_test_link 2022-blake3-aes-128-gcm "$SS16::$SS16")" reject "SS2022 empty identity key rejected"
    expect mksingbox.py "$SS22CHACHA_MULTI" reject "SS2022 ChaCha20 multi-user rejected"
    expect mksingbox.py "$(ss_test_link 2022-BLAKE3-AES-128-GCM "$SS16")" reject "SS2022 method case rejected"
    expect mkxray.py "$(ss_test_link 2022-blake3-aes-192-gcm "$SS16")" reject "unknown SS2022 method rejected"
    expect mksingbox.py "$SS22COMPAT" reject "SS2022 nonstandard key kept off sing-box"
    expect mksingbox.py "$(ss_test_link 2022-blake3-aes-128-gcm "$SS16" '?plugin=kcptun')" reject "SS2022 unsupported plugin rejected"

    # host injection: ESC byte must be rejected (no traceback)
    out="$(python3 "$SRC/mkxray.py" --link "$(printf 'vless://u@h\033[2Jx:443?security=tls&sni=a')" --port 51821 --secret-key AAAA --peer-pubkey BBBB 2>&1)" || true
    if printf '%s' "$out" | grep -qi 'control\|unsafe\|malformed'; then ok "ESC host rejected"; else bad "ESC host rejected"; fi

    py_case "current share-link fields preserved" "$SRC" <<'PY'
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

    py_case "SS2022 strict classifier and key fuzz" "$SRC" <<'PY'
import base64,contextlib,io,random,string,sys
sys.path.insert(0,sys.argv[1])
import mkxray,mksingbox,proxylib
def key(size): return base64.b64encode(bytes((n % 251)+1 for n in range(size))).decode()
def link(method,password,query=""):
    credentials=base64.urlsafe_b64encode((method+":"+password).encode()).decode().rstrip("=")
    return "ss://%s@h:8388%s" % (credentials,query)
k16,k32=key(16),key(32)
standard=link("2022-blake3-aes-128-gcm",k16)
compat=link("2022-blake3-aes-128-gcm",k32)
assert mkxray.ss_engine(standard)=="singbox"
assert mkxray.ss_engine(compat)=="xray"
assert mkxray.ss_engine(link("aes-256-gcm","password"))=="xray"
assert mkxray.ss_engine(link("aes-256-gcm","password","?plugin=obfs-local"))=="singbox"
out,_,_=mksingbox.parse_ss(standard)
assert out["method"]=="2022-blake3-aes-128-gcm" and "multiplex" not in out
assert out["password"]==k16
with contextlib.redirect_stderr(io.StringIO()):
    try: mksingbox.parse_ss(compat); raise AssertionError("compat key reached sing-box")
    except SystemExit: pass
for method,size in proxylib.SS2022_KEY_BYTES.items():
    valid=key(size)
    assert proxylib.shadowsocks_2022_key_info(method,valid)==(True,"",False)
    multi=proxylib.shadowsocks_2022_key_info(method,valid+":"+valid)
    if method=="2022-blake3-chacha20-poly1305":
        assert multi[0] is True and "AES-GCM" in multi[1]
    else:
        assert multi==(True,"",False)
        assert proxylib.shadowsocks_2022_key_info(
            method,":".join([valid]*3))==(True,"",False)
        assert proxylib.shadowsocks_2022_key_info(
            method,":".join([valid]*proxylib.SS2022_MAX_KEYS))==(True,"",False)
        assert "1-%d" % proxylib.SS2022_MAX_KEYS in proxylib.shadowsocks_2022_key_info(
            method,":".join([valid]*(proxylib.SS2022_MAX_KEYS+1)))[1]
rng=random.Random(2022)
alphabet=string.ascii_letters+string.digits+"+/=_:-! \t"
for _ in range(20000):
    candidate="".join(rng.choice(alphabet) for _ in range(rng.randrange(0,100)))
    result=proxylib.shadowsocks_2022_key_info(
        "2022-blake3-aes-256-gcm",candidate,allow_xray_compat=False)
    assert len(result)==3 and result[0] is True and isinstance(result[1],str)
    if not result[1]:
        parts=candidate.split(":")
        assert 1<=len(parts)<=proxylib.SS2022_MAX_KEYS
        assert all(len(base64.b64decode(p+"="*(-len(p)%4),validate=True))==32 for p in parts)
PY

    # mksub: classification + safety (pure python)
    py_case "mksub parser corpus" "$SRC" <<'PY'
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
# SS2022 is identified separately, routed through sing-box, and kept distinct
# from legacy Shadowsocks during refresh matching.
k16 = base64.b64encode(bytes(range(16))).decode()
k32 = base64.b64encode(bytes(range(32))).decode()
def sslink(method,password,suffix=""):
    cred=base64.urlsafe_b64encode((method+":"+password).encode()).decode().rstrip("=")
    return "ss://%s@h:8388%s#Москва🎯" % (cred,suffix)
ss2022=mksub.node_from_link(sslink("2022-blake3-aes-128-gcm",k16))
assert ss2022["recognized"] and ss2022["engine"]=="singbox" and ss2022["variant"]=="2022", ss2022
assert mksub._selection_meta(ss2022)["scheme"]=="ss2022"
chain=mksub.node_from_link(sslink("2022-blake3-aes-256-gcm",":".join([k32]*3)))
assert chain["recognized"] and chain["engine"]=="singbox" and chain["variant"]=="2022", chain
chacha_multi=mksub.node_from_link(
    sslink("2022-blake3-chacha20-poly1305",k32+":"+k32))
assert not chacha_multi["recognized"] and "AES-GCM" in chacha_multi["reason"], chacha_multi
legacy=mksub.node_from_link(sslink("aes-256-gcm","password"))
assert legacy["engine"]=="xray" and mksub._selection_meta(legacy)["scheme"]=="ss"
compat=mksub.node_from_link(sslink("2022-blake3-aes-128-gcm",k32))
assert compat["recognized"] and compat["engine"]=="xray" and "compatibility" in compat["reason"], compat
bad=mksub.node_from_link(sslink("2022-blake3-aes-256-gcm",k16))
assert not bad["recognized"] and "32 bytes" in bad["reason"], bad
unknown=mksub.node_from_link(sslink("2022-blake3-aes-128-gcm",k16,"?uot=1"))
assert not unknown["recognized"] and "query parameter" in unknown["reason"], unknown
with tempfile.TemporaryDirectory() as directory:
    path=os.path.join(directory,"catalog.json")
    ss2022["n"]=1
    json.dump({"schema":mksub.SCHEMA_VERSION,"meta":{},"nodes":[ss2022]},open(path,"w"))
    output=io.StringIO()
    with contextlib.redirect_stdout(output):
        mksub.cmd_render(types.SimpleNamespace(file=path,selected=""))
    assert "ss2022" in output.getvalue() and "Москва🎯" in output.getvalue(), output.getvalue()
    active_path=os.path.join(directory,"active-link")
    open(active_path,"w").write(ss2022["link"])
    old_meta=mksub._selection_meta(ss2022); old_meta["scheme"]="ss"
    migrated=mksub._migrate_selection_scheme(old_meta,active_path)
    assert migrated["scheme"]=="ss2022"
    old_meta_path=os.path.join(directory,"old-selection.json")
    json.dump(old_meta,open(old_meta_path,"w"))
    rotated_key=base64.b64encode(bytes(range(1,17))).decode()
    rotated=mksub.node_from_link(sslink("2022-blake3-aes-128-gcm",rotated_key))
    rotated["n"]=1
    json.dump({"schema":mksub.SCHEMA_VERSION,"meta":{},"nodes":[rotated]},open(path,"w"))
    refreshed_meta=os.path.join(directory,"refreshed-selection.json")
    output=io.StringIO()
    with contextlib.redirect_stdout(output):
        mksub.cmd_match(types.SimpleNamespace(
            file=path,selection_file=old_meta_path,meta_file=refreshed_meta,
            active_link_file=active_path))
    assert output.getvalue().startswith("1\t%s\t" % rotated["id"]), output.getvalue()
    assert json.load(open(refreshed_meta))["scheme"]=="ss2022"
    open(active_path,"w").write(legacy["link"])
    assert mksub._migrate_selection_scheme(old_meta,active_path)["scheme"]=="ss"
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
assert mksub.clean("left\ud800right", 40) == "leftright"
assert mksub.clean("Нидерланды 🇳🇱", 40) == "Нидерланды 🇳🇱"
assert mksub.clean("🇩🇪🎯 Автовыбор | Германия", 80) == "🇩🇪🎯 Автовыбор | Германия"
assert mksub.clean("🇺🇸 США", 40) == "🇺🇸 США"
assert mksub.clean("München España Montréal", 80) == "München España Montréal"
full = "🇩🇪🎯".encode("utf-8").decode("latin-1") + " Автовыбор"     # full mojibake
assert "🇩🇪🎯" in mksub.clean(full, 80), mksub.clean(full, 80)
old_safe = os.environ.get("PROXY_UNIFI_TERMINAL_SAFE_EMOJI")
os.environ["PROXY_UNIFI_TERMINAL_SAFE_EMOJI"] = "1"
try:
    assert mksub.clean("🇩🇪🛜 Москва", 80) == "[DE] Wi-Fi Москва"
    assert mksub.clean("🇺🇸⭐ VPN | США", 80) == "[US] ⭐ VPN | США"
finally:
    if old_safe is None:
        os.environ.pop("PROXY_UNIFI_TERMINAL_SAFE_EMOJI", None)
    else:
        os.environ["PROXY_UNIFI_TERMINAL_SAFE_EMOJI"] = old_safe
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
prof = {"remarks": "DE Auto", "inbounds": [{"tag": "socks", "protocol": "socks", "settings": {}}], "outbounds": [
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
same_a = dict(prof); same_a["remarks"] = "⬆️ Автовыбор по алгоритму ⬆️"
same_b = json.loads(json.dumps(same_a, sort_keys=True))
same_cat = mksub.process_body(json.dumps([same_a, same_b]).encode())
assert same_cat["meta"]["count"] == 1, same_cat
same_b["remarks"] = "⬇️ Выбор ближайшего города ⬇️"
same_cat = mksub.process_body(json.dumps([same_a, same_b]).encode())
assert same_cat["meta"]["count"] == 2, same_cat
assert len({node["id"] for node in same_cat["nodes"]}) == 2
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
# Historical numeric IPv4 spellings must not bypass the shared non-public-target guard.
for host in ("2130706433", "0x7f000001", "0177.0.0.1", "127.1"):
    assert mksub.node_from_link("vless://u@%s:443#x" % host)["recognized"] is False, host
# Xray Trojan/SS profile shapes use settings.servers and must classify correctly
for proto in ("trojan", "shadowsocks"):
    shape={"inbounds":[{"protocol":"socks","settings":{}}],"outbounds":[{"protocol":proto,"tag":"proxy","settings":{"servers":[{"address":"public.example","port":443}]}}]}
    assert mksub._classify_profile(shape)[0] is True, (proto,mksub._classify_profile(shape))
# Current direct settings.address shape is also classified and safety-checked.
http_shape={"inbounds":[{"protocol":"socks","settings":{}}],"outbounds":[{"protocol":"http","tag":"proxy","settings":{"address":"public.example","port":3128}}]}
assert mksub._classify_profile(http_shape)[0] is True
# JSON profile key ordering does not change identity, but provider remarks do.
p1=dict(prof); p1["remarks"]="one"
p2=json.loads(json.dumps(p1,sort_keys=True))
c1=mksub.process_body(json.dumps([p1]).encode())["nodes"][0]["id"]
c2=mksub.process_body(json.dumps([p2]).encode())["nodes"][0]["id"]
assert c1==c2,(c1,c2)
p2["remarks"]="two"
c3=mksub.process_body(json.dumps([p2]).encode())["nodes"][0]["id"]
assert c1!=c3,(c1,c3)
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
PY

    # mkawg: AWG 1.5-3.1 parser, bridge generator, profile catalog, and UI safety.
    py_case "mkawg parser and UI corpus" "$SRC" <<'PY'
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import types

sys.path.insert(0, sys.argv[1])
import mkawg
import mksub

PRIVATE = base64.b64encode(bytes(range(32))).decode()
PUBLIC = base64.b64encode(bytes(reversed(range(32)))).decode()
PUBLIC2 = base64.b64encode(bytes(range(96, 128))).decode()
INNER = base64.b64encode(bytes(range(32, 64))).decode()
INNER_PEER = base64.b64encode(bytes(range(64, 96))).decode()

def text(extra="", endpoint="vpn.example:443", second_peer=False):
    peers = """[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s
PersistentKeepalive = 25
""" % (PUBLIC, endpoint)
    if second_peer:
        peers += """\n[Peer]
PublicKey = %s
AllowedIPs = 10.0.0.0/8
Endpoint = backup.example:8443
""" % PUBLIC2
    return """[Interface]
PrivateKey = %s
Address = 172.16.0.2/32
DNS = 8.8.8.8, 2001:4860:4860::8888
MTU = 1280
%s
%s""" % (PRIVATE, extra, peers)

def write(directory, value, name="profile.conf"):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as output:
        output.write(value)
    return path

def rejected(value):
    with tempfile.TemporaryDirectory() as directory:
        path = write(directory, value)
        try:
            mkawg.load_profile(path)
            raise AssertionError("accepted malformed profile")
        except mkawg.ProfileError:
            pass

awg15 = """Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0x01020304><r 16><t><d><ds><dz 2>"""
awg20 = """ListenPort = 51820
Jc = 5
Jmin = 32
Jmax = 96
S1 = 12
S2 = 24
S3 = 8
S4 = 16
H1 = 100-199
H2 = 200-299
H3 = 300-399
H4 = 400-499
I1 = <b 0x16030100><r 8>
I2 = <rc 8><rd 8>
I3 = <t><dz 2>
I4 = <b abcd>
I5 = <r 1>"""
HPK = base64.b64encode(bytes(range(128, 160))).decode()
awg30 = awg20.replace("S3 = 8", "S3 = 12") + """
HeaderProtectionKey = %s
ContentPaddingAddition = 0-64
RekeyAfterTime = 100-120
RekeyTimeout = 3-5
RejectAfterTime = 170-180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 10""" % HPK
awg31 = awg30 + """
RandomTrailers = on
DisableCookies = off"""

with tempfile.TemporaryDirectory() as directory:
    p15 = write(directory, text(awg15))
    profile15 = mkawg.load_profile(p15)
    assert profile15["version"] == "1.5"
    assert profile15["interface"]["i1"].startswith("<b 0x01020304>")
    p20 = write(directory, text(awg20, "[2001:db8::10]:51820", True), "v2.conf")
    profile20 = mkawg.load_profile(p20)
    assert profile20["version"] == "2.0" and len(profile20["peers"]) == 2
    assert profile20["peers"][0]["core_host"] == "[2001:db8::10]"
    p10 = write(directory, text(""), "v1.conf")
    assert mkawg.load_profile(p10)["version"] == "1.0"
    p30 = write(directory, text(awg30).replace("PersistentKeepalive = 25",
                                               "PersistentKeepalive = 20-30"), "v3.conf")
    profile30 = mkawg.load_profile(p30)
    assert profile30["version"] == "3.0"
    assert profile30["peers"][0]["persistent_keepalive"] == 20
    awg30_json = mkawg._endpoint_json(profile30)
    assert awg30_json["header_protection_key"] == HPK
    assert awg30_json["content_padding_addition"] == "0-64"
    assert awg30_json["rekey_timeout"] == "3-5"
    assert awg30_json["max_handshake_attempts"] == "10"
    assert "random_trailers" not in awg30_json
    p31 = write(directory, text(awg31), "v31.conf")
    profile31 = mkawg.load_profile(p31)
    assert profile31["version"] == "3.1"
    awg31_json = mkawg._endpoint_json(profile31)
    assert awg31_json["random_trailers"] is True and "disable_cookies" not in awg31_json
    pas = write(directory, text(awg31).replace("PersistentKeepalive = 25",
                                               "AdvancedSecurity = on"), "as.conf")
    assert mkawg.load_profile(pas)["version"] == "3.1"

    secret = write(directory, INNER, "inner.key")
    peer = write(directory, INNER_PEER, "peer.key")
    args = types.SimpleNamespace(socks_port=0, secret_key_file=secret,
                                 peer_pubkey_file=peer, port=51821,
                                 address="10.7.0.1/32, fd00::1/128", mtu=1340,
                                 loglevel="warn")
    config = mkawg.build_config(profile20, args)
    assert [item["tag"] for item in config["endpoints"]] == ["wg-in", "awg-out"]
    assert config["route"]["final"] == "awg-out"
    assert config["route"]["rules"] == [{"inbound": ["wg-in"], "outbound": "awg-out"}]
    assert config["endpoints"][0]["private_key"] == INNER
    assert config["endpoints"][1]["private_key"] == PRIVATE
    assert config["endpoints"][1]["h1"] == "100-199"
    assert config["endpoints"][1]["i5"] == "<r 1>"
    assert "listen_port" not in config["endpoints"][1]
    assert "outbounds" not in config and "direct" not in json.dumps(config)
    args.socks_port = 10808
    ping = mkawg.build_config(profile15, args)
    assert ping["inbounds"][0]["listen"] == "127.0.0.1"
    assert ping["route"]["final"] == "awg-out" and len(ping["endpoints"]) == 1

    with contextlib.redirect_stdout(io.StringIO()) as output:
        mkawg.print_info(profile15)
    assert PRIVATE not in output.getvalue() and PUBLIC not in output.getvalue()

    # Catalog rows preserve identity independently from the sorted display index.
    profiles = os.path.join(directory, "profiles")
    os.mkdir(profiles)
    good_id = "11111111-1111-4111-8111-111111111111"
    bad_id = "22222222-2222-4222-8222-222222222222"
    write(profiles, text(awg15), good_id + ".conf")
    write(profiles, "[Interface]\nPrivateKey = bad\n", bad_id + ".conf")
    write(profiles, "🇩🇪 Москва 🛜", good_id + ".name")
    write(profiles, "Broken", bad_id + ".name")
    map_file = os.path.join(directory, "map")
    old = os.environ.get("PROXY_UNIFI_TERMINAL_SAFE_EMOJI")
    os.environ["PROXY_UNIFI_TERMINAL_SAFE_EMOJI"] = "1"
    try:
        with contextlib.redirect_stdout(io.StringIO()) as output:
            mkawg.render_profiles(profiles, good_id, map_file)
        rendered = output.getvalue()
        assert "[*] AWG 1.5" in rendered and "[DE] Москва Wi-Fi" in rendered
        assert "invalid" in rendered and "\x1b" not in rendered
    finally:
        if old is None:
            os.environ.pop("PROXY_UNIFI_TERMINAL_SAFE_EMOJI", None)
        else:
            os.environ["PROXY_UNIFI_TERMINAL_SAFE_EMOJI"] = old
    old_columns = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "60"
    try:
        with contextlib.redirect_stdout(io.StringIO()) as output:
            mkawg.render_profiles(profiles, good_id)
        narrow = output.getvalue()
        assert "endpoint:" in narrow
        for line in narrow.splitlines():
            assert sum(mkawg.display_width(ch) for ch in line) <= 60, line
    finally:
        if old_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = old_columns
    mapping = open(map_file, encoding="ascii").read().splitlines()
    assert set(mapping) == {good_id, bad_id}
    assert (os.stat(map_file).st_mode & 0o777) == 0o600
    with contextlib.redirect_stdout(io.StringIO()) as output:
        mkawg.pick_profile(profiles, profile_id=bad_id, allow_invalid=True)
    assert output.getvalue().startswith(bad_id + "\t")
    try:
        mkawg.pick_profile(profiles, profile_id=bad_id)
        raise AssertionError("selected an invalid profile")
    except mkawg.ProfileError:
        pass
    os.unlink(os.path.join(profiles, good_id + ".name"))
    with contextlib.redirect_stdout(io.StringIO()) as output:
        mkawg.pick_profile(profiles, profile_id=good_id)
    assert output.getvalue().rstrip().endswith(good_id)

    symlink = os.path.join(directory, "profile-link")
    os.symlink(p15, symlink)
    try:
        mkawg.load_profile(symlink)
        raise AssertionError("accepted profile symlink")
    except mkawg.ProfileError:
        pass

# Malformed or dangerous semantics fail before core startup.
rejected(text(awg15).replace("PrivateKey = " + PRIVATE, "PrivateKey = invalid"))
rejected(text(awg15).replace("PrivateKey = " + PRIVATE,
                             "PrivateKey = " + base64.b64encode(bytes(32)).decode()))
rejected(text(awg15).replace("PublicKey = " + PUBLIC, "PublicKey = invalid"))
rejected(text(awg15).replace("PublicKey = " + PUBLIC,
                             "PublicKey = " + base64.b64encode(bytes(32)).decode()))
rejected(text(awg15).replace("PublicKey = " + PUBLIC,
                             "PublicKey = " + PUBLIC[:-2] + "B="))
rejected(text(awg15).replace("MTU = 1280", "MTU = 1280\nMTU = 1400"))
rejected(text(awg15).replace("MTU = 1280", "MTU = 1280\nPostUp = touch /tmp/pwn"))
rejected(text(awg15).replace("MTU = 1280", "MTU = 1280\nUnknown = value"))
rejected(text(awg15).replace("H1 = 1", "H1 = 0-4294967295"))
rejected(text(awg20).replace("H2 = 200-299", "H2 = 150-299"))
rejected(text(awg15).replace("I1 = <b 0x01020304><r 16><t><d><ds><dz 2>", "I1 = junk<b 00>"))
rejected(text(awg15).replace("I1 = <b 0x01020304><r 16><t><d><ds><dz 2>", "I1 = <r 65508>"))
rejected(text(awg15).replace("S1 = 0", "S1 = 65507"))
rejected(text(awg30).replace("S3 = 12", "S3 = 8"))
rejected(text(awg30).replace("HeaderProtectionKey = " + HPK, "HeaderProtectionKey = invalid"))
rejected(text(awg30).replace("HeaderProtectionKey = " + HPK,
                             "HeaderProtectionKey = " + base64.b64encode(bytes(32)).decode()))
rejected(text(awg30).replace("ContentPaddingAddition = 0-64", "ContentPaddingAddition = 0-65536"))
rejected(text(awg30).replace("RekeyTimeout = 3-5", "RekeyTimeout = 5-3"))
rejected(text(awg30).replace("KeepaliveTimeout = 10", "KeepaliveTimeout = 10\nKeepaliveTimeout = 11"))
rejected(text(awg31).replace("RandomTrailers = on", "RandomTrailers = maybe"))
rejected(text(awg15).replace("PersistentKeepalive = 25", "PersistentKeepalive = 30-20"))
rejected(text(awg15).replace("PersistentKeepalive = 25", "AdvancedSecurity = off"))
rejected(text(awg15).replace("Jc = 4", "Jc = " + "9" * 10000))
rejected(text(awg15).replace("H1 = 1", "H1 = " + "9" * 10000))
rejected(text(awg15).replace("<r 16>", "<r " + "9" * 10000 + ">"))
rejected(text(awg15).replace("vpn.example:443", "[2001:db8::1:443"))
rejected(text(awg15).replace("[Peer]", "[Unknown]", 1))
rejected(text(awg15).split("[Peer]", 1)[0])
rejected(text(awg15) + "\n[Peer]\nPublicKey = " + PUBLIC +
         "\nAllowedIPs = 10.0.0.0/8\nEndpoint = duplicate.example:443\n")
rejected(text(awg15).replace("Address = 172.16.0.2/32",
                             "Address = " + ",".join("10.0.0.%d/32" % n
                                                       for n in range(1, 18))))
rejected(text(awg15).replace("DNS = 8.8.8.8, 2001:4860:4860::8888",
                             "DNS = " + ",".join("dns%d.example" % n
                                                   for n in range(17))))
rejected(text(awg15).replace("AllowedIPs = 0.0.0.0/0, ::/0",
                             "AllowedIPs = " + ",".join("10.%d.0.0/16" % n
                                                          for n in range(129))))

try:
    mkawg.validate_name("safe\u202eevil")
    raise AssertionError("accepted bidirectional override in name")
except mkawg.ProfileError:
    pass
assert mkawg.validate_name("Семья 👨‍👩‍👧‍👦") == "Семья 👨‍👩‍👧‍👦"
safe = mkawg._display("日本日本日本日本", 7)
assert safe.endswith("...") and sum(mkawg.display_width(ch) for ch in safe) <= 7
assert mkawg.display_width("\ufe0f") == 0 and mkawg.display_width("\u200d") == 0
subsafe = mksub.clean("日本日本日本日本", 7)
assert subsafe.endswith("…") and sum(mksub.display_width(ch) for ch in subsafe) <= 7
assert mksub.display_width("\ufe0f") == 0 and mksub.display_width("\u200d") == 0

# CLI errors are concise and never duplicate proxylib's message or leak traceback.
with tempfile.TemporaryDirectory() as directory:
    bad = write(directory, text(awg15, "bad host:443"))
    proc = subprocess.run([sys.executable, os.path.join(sys.argv[1], "mkawg.py"),
                           "validate", "--file", bad], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode != 0 and proc.stderr.count("mkawg: error:") == 1
    assert "Traceback" not in proc.stderr
    hostile = write(directory, text(awg15).replace(
        "Address = 172.16.0.2/32", "Address = bad\x1b[2Jhost"), "hostile.conf")
    proc = subprocess.run([sys.executable, os.path.join(sys.argv[1], "mkawg.py"),
                           "validate", "--file", hostile], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode != 0 and "\x1b" not in proc.stderr
    assert not any(ord(ch) < 32 and ch not in "\r\n\t" for ch in proc.stderr)
PY

    # mkjson: balancer profile validation + overlay tag matching (pure python)
    py_case "mkjson profile validation" "$SRC" <<'PY'
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
# A non-SOCKS primary cannot be meaningfully replaced with a WireGuard inbound.
non_socks = json.loads(json.dumps(prof)); non_socks["inbounds"][0]["protocol"] = "dokodemo-door"
try:
    mkjson.validate_profile(non_socks); raise AssertionError("accepted non-SOCKS primary inbound")
except SystemExit:
    pass
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
# Xray GHSA-5wf9-h793-w73c: an IP gRPC target plus a certificate pin and no
# serverName must fail even if an older vulnerable core is restored locally.
unsafe_pin = json.loads(json.dumps(prof))
unsafe_pin["outbounds"][0] = {
    "protocol":"vless", "tag":"proxy",
    "settings":{"vnext":[{"address":"1.1.1.1","port":443,
                           "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
    "streamSettings":{"network":"grpc","security":"tls",
                      "tlsSettings":{"pinnedPeerCertSha256":"00"*32}}}
try:
    mkjson.validate_profile(unsafe_pin); raise AssertionError("accepted unsafe IP gRPC pin")
except SystemExit:
    pass
unsafe_pin["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"]="vpn.example"
mkjson.validate_profile(unsafe_pin)
# provider geodata jobs can replace local assets and are never part of pool routing semantics
with_geodata = json.loads(json.dumps(prof)); with_geodata["geodata"]={"cron":"* * * * *"}
assert "geodata" not in mkjson.sanitize_provider(with_geodata)
PY
}

# -------------------------------------------------------------------------
# tier 3: engine tests (need real xray / sing-box)
# -------------------------------------------------------------------------
find_xray()   { [ -x "$CACHE/xray" ] && echo "$CACHE/xray"; }
find_singbox(){ [ -x "$CACHE/sing-box" ] && echo "$CACHE/sing-box"; }
find_awg() {
    if [ -n "${PROXY_UNIFI_AWG_CORE:-}" ] && [ -x "$PROXY_UNIFI_AWG_CORE" ]; then
        echo "$PROXY_UNIFI_AWG_CORE"
    elif [ -x "$CACHE/amnezia-box" ]; then
        echo "$CACHE/amnezia-box"
    fi
}

download_engines() {
    mkdir -p "$CACHE"
    _os="$(uname -s | tr '[:upper:]' '[:lower:]')"; _m="$(uname -m)"
    case "$_m" in arm64|aarch64) _xa=arm64-v8a; _sa=arm64;; x86_64|amd64) _xa=64; _sa=amd64;; *) echo "unknown arch"; return 1;; esac
    case "$_os" in darwin) _xos=macos; _sos=darwin;; linux) _xos=linux; _sos=linux;; *) echo "unknown os"; return 1;; esac
    echo "  downloading xray ($_xos-$_xa) ..."
    _xtag="$(sed -n 's/^XRAY_MIN_SAFE_TAG="\([^"]*\)"/\1/p' "$SRC/proxy-unifi")"
    [ -n "$_xtag" ] || return 1
    _xurl="https://github.com/XTLS/Xray-core/releases/download/${_xtag}/Xray-${_xos}-${_xa}.zip"
    curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 "$_xurl" -o "$CACHE/x.zip" \
        && curl -fsSL --connect-timeout 15 --max-time 60 --retry 3 "$_xurl.dgst" -o "$CACHE/x.dgst" \
        || return 1
    _xwant="$(awk -F'= ' 'tolower($1)~/sha2-256/{print tolower($2)}' "$CACHE/x.dgst" | tr -d ' \r' | head -1)"
    [ -n "$_xwant" ] && [ "$(sha256_of "$CACHE/x.zip")" = "$_xwant" ] || return 1
    unzip -oq "$CACHE/x.zip" -d "$CACHE" && chmod +x "$CACHE/xray" \
        && "$CACHE/xray" version >/dev/null 2>&1 || return 1
    # One API call names the latest stable release and carries its asset digests.
    curl -fsSL --connect-timeout 15 --max-time 60 --retry 3 \
        https://api.github.com/repos/SagerNet/sing-box/releases/latest -o "$CACHE/sb-release.json" \
        || return 1
    _tag="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("tag_name",""))' \
        "$CACHE/sb-release.json")"; _v="${_tag#v}"
    [ -n "$_v" ] || return 1
    echo "  downloading sing-box $_tag ($_sos-$_sa) ..."
    _sbdir="$CACHE/sing-box-${_v}-${_sos}-${_sa}"
    rm -rf "$_sbdir"
    _sbname="sing-box-${_v}-${_sos}-${_sa}.tar.gz"
    curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 \
        "https://github.com/SagerNet/sing-box/releases/download/${_tag}/${_sbname}" -o "$CACHE/sb.tgz" \
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
        && "$CACHE/sing-box" version | grep -q "version $_v" || return 1
    # The project-owned AWG core is published for Linux only, under the same
    # pinned digest the gateway installer enforces.
    [ "$_sos" = linux ] || return 0
    _av="$(sed -n 's/^AWG_CORE_VERSION="\([^"]*\)"/\1/p' "$SRC/proxy-unifi")"
    _awant="$(sed -n "/^awg_core_sha256() {/,/^}/s/^ *$_sa) echo \"\([0-9a-f]*\)\".*/\1/p" "$SRC/proxy-unifi")"
    _aname="proxy-unifi-amnezia-box-${_av}-linux-${_sa}"
    echo "  downloading AmneziaWG core $_av ($_sa) ..."
    curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 \
        "https://github.com/palmbeachpete9/proxy-unifi/releases/download/awg-core-v${_av}/${_aname}.tar.gz" \
        -o "$CACHE/awg.tgz" || return 1
    [ -n "$_awant" ] && [ "$(sha256_of "$CACHE/awg.tgz")" = "$_awant" ] \
        && tar xzf "$CACHE/awg.tgz" -C "$CACHE" \
        && cp "$CACHE/$_aname/amnezia-box" "$CACHE/amnezia-box.new" \
        && mv -f "$CACHE/amnezia-box.new" "$CACHE/amnezia-box" \
        && "$CACHE/amnezia-box" version | grep -q "version proxy-unifi-awg-$_av"
}

engine_tests() {
    XR="$(find_xray || true)"; SG="$(find_singbox || true)"; AB="$(find_awg || true)"
    if [ -z "$XR" ] || [ -z "$SG" ]; then
        printf '== engine == (skipped: run with --download to fetch xray/sing-box)\n'
        return
    fi
    echo "== engine =="
    XP="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
    UP="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
    UUID="b831381d-6324-4d53-ad4f-8cda48b30811"
    _d="$(mktemp -d)"
    gx() { python3 "$SRC/mkxray.py" --link "$1" --port 51821 --secret-key "$XP" --peer-pubkey "$UP" > "$_d/c.json" 2>/dev/null \
           && "$XR" run -test -config "$_d/c.json" -format json >/dev/null 2>&1; }
    gs() { python3 "$SRC/mksingbox.py" --link "$1" --port 51821 --secret-key "$XP" --peer-pubkey "$UP" > "$_d/s.json" 2>/dev/null \
           && "$SG" check -c "$_d/s.json" >/dev/null 2>&1; }
    KEY="$("$XR" x25519 2>/dev/null | awk -F': ' '/Password|Public/{print $2}' | tail -1)"
    gx "vless://$UUID@h:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=$KEY&sid=ab&sni=a&fp=chrome" && ok "xray vless reality" || bad "xray vless reality"
    gx "trojan://pw@h:443?security=tls&sni=a" && ok "xray trojan" || bad "xray trojan"
    gx "vless://$UUID@h:443?type=kcp&security=none" && ok "xray mKCP" || bad "xray mKCP"
    _pcs="$(printf '%064d' 0)"
    gx "vless://$UUID@h:443?security=tls&type=grpc&sni=a&authority=front.example&mode=multi&vcn=cert.example&pcs=$_pcs&user_agent=ua&idle_timeout=60&health_check_timeout=20&permit_without_stream=true&initial_windows_size=65536" \
        && ok "xray current TLS/gRPC share fields" || bad "xray current TLS/gRPC share fields"
    _xextra="$(python3 -c 'import json,urllib.parse; print(urllib.parse.quote(json.dumps({"scMaxEachPostBytes":1000000})))')"
    _xfm="$(python3 -c 'import json,urllib.parse; print(urllib.parse.quote(json.dumps({"tcp":[]})))')"
    gx "vless://$UUID@h:443?security=tls&type=xhttp&sni=a&extra=$_xextra&fm=$_xfm" \
        && ok "xray current XHTTP/FinalMask share fields" || bad "xray current XHTTP/FinalMask share fields"
    gs "hysteria2://pw@h:443?sni=h" && ok "singbox hysteria2" || bad "singbox hysteria2"
    gs "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@h:443?sni=h" && ok "singbox tuic" || bad "singbox tuic"
    _ss16="$(ss_test_key 16)"; _ss32="$(ss_test_key 32)"
    _ssa128="$(ss_test_link 2022-blake3-aes-128-gcm "$_ss16")"
    _ssa128_unpadded="$(ss_test_link 2022-blake3-aes-128-gcm "$(printf '%s' "$_ss16" | tr -d '=')")"
    _ssa256="$(ss_test_link 2022-blake3-aes-256-gcm "$_ss32")"
    _sschacha="$(ss_test_link 2022-blake3-chacha20-poly1305 "$_ss32")"
    _ssmulti="$(ss_test_link 2022-blake3-aes-128-gcm "$_ss16:$_ss16")"
    _sschain="$(ss_test_link 2022-blake3-aes-256-gcm "$_ss32:$_ss32:$_ss32")"
    gs "$_ssa128" && ok "singbox SS2022 AES-128" || bad "singbox SS2022 AES-128"
    gs "$_ssa128_unpadded" \
        && ok "singbox SS2022 unpadded key normalization" \
        || bad "singbox SS2022 unpadded key normalization"
    gs "$_ssa256" && ok "singbox SS2022 AES-256" || bad "singbox SS2022 AES-256"
    gs "$_sschacha" && ok "singbox SS2022 ChaCha20" || bad "singbox SS2022 ChaCha20"
    gs "$_ssmulti" && ok "singbox SS2022 multi-user" || bad "singbox SS2022 multi-user"
    gs "$_sschain" && ok "singbox SS2022 relay identity chain" \
        || bad "singbox SS2022 relay identity chain"
    gx "$(ss_test_link 2022-blake3-aes-128-gcm "$_ss32")" \
        && ok "xray SS2022 AES-128 compatibility" || bad "xray SS2022 AES-128 compatibility"
    if python3 - "$_d/s.json" <<'PY'
import json,sys
out=json.load(open(sys.argv[1]))["outbounds"][0]
assert out["type"]=="shadowsocks" and out["method"].startswith("2022-blake3-")
assert "multiplex" not in out and "udp_over_tcp" not in out
PY
    then ok "SS2022 does not force server-dependent extensions"
    else bad "SS2022 does not force server-dependent extensions"; fi
    if [ -n "$AB" ]; then
        cat > "$_d/awg.conf" <<EOF
[Interface]
PrivateKey = $XP
Address = 172.16.0.2/32
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 8
S2 = 16
S3 = 4
S4 = 12
H1 = 100-199
H2 = 200-299
H3 = 300-399
H4 = 400-499
I1 = <b 0x01020304><r 8>
I2 = <rc 4><rd 4>

[Peer]
PublicKey = $UP
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:9
PersistentKeepalive = 25
EOF
        printf '%s' "$XP" > "$_d/inner.key"
        printf '%s' "$UP" > "$_d/peer.key"
        if python3 "$SRC/mkawg.py" build --file "$_d/awg.conf" \
             --secret-key-file "$_d/inner.key" --peer-pubkey-file "$_d/peer.key" \
             --port 51831 --address 10.7.0.1/32 --mtu 1340 > "$_d/awg-active.json" \
           && "$AB" check -c "$_d/awg-active.json" >/dev/null 2>&1
        then ok "amnezia-box AWG 2.0 bridge config"; else bad "amnezia-box AWG 2.0 bridge config"; fi

        _aport="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
        if python3 "$SRC/mkawg.py" build --file "$_d/awg.conf" \
             --socks-port "$_aport" > "$_d/awg-ping.json" \
           && "$AB" check -c "$_d/awg-ping.json" >/dev/null 2>&1 \
           && python3 - "$AB" "$_d/awg-ping.json" "$_aport" <<'PY'
import socket,subprocess,sys,time
proc=subprocess.Popen([sys.argv[1],"run","-c",sys.argv[2]],
                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    deadline=time.time()+8
    while time.time()<deadline:
        if proc.poll() is not None:
            raise SystemExit(1)
        try:
            with socket.create_connection(("127.0.0.1",int(sys.argv[3])),0.2):
                raise SystemExit(0)
        except OSError:
            time.sleep(0.1)
    raise SystemExit(1)
finally:
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
PY
        then ok "amnezia-box AWG endpoint runtime"; else bad "amnezia-box AWG endpoint runtime"; fi

        # Two real cores complete an AWG 3.1 handshake only with a matching
        # HeaderProtectionKey; a wrong key must keep the tunnel down.
        if python3 - "$AB" "$SRC" <<'PY'
import base64, json, os, socket, subprocess, sys, tempfile, threading, time

core, src = sys.argv[1], sys.argv[2]

def keypair():
    out = subprocess.check_output([core, "generate", "wg-keypair"], text=True)
    return [line.split(": ", 1)[1] for line in out.splitlines()]

def relay(sock):
    # amnezia-box ignores listen_port, so both cores dial this hub and it
    # forwards opaque datagrams between the two learned source addresses.
    peers = []
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            if addr not in peers:
                peers.append(addr)
            for other in peers:
                if other != addr:
                    sock.sendto(data, other)
    except OSError:
        pass

spriv, spub = keypair()
cpriv, cpub = keypair()
key = base64.b64encode(os.urandom(32)).decode()

def handshake(server_key, timeout):
    work = tempfile.mkdtemp()
    hub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hub.bind(("127.0.0.1", 0))
    threading.Thread(target=relay, args=(hub,), daemon=True).start()
    port = hub.getsockname()[1]
    with open(work + "/client.conf", "w") as conf:
        conf.write("""[Interface]
PrivateKey = %s
Address = 10.66.0.2/32
Jc = 3
Jmin = 40
Jmax = 70
S1 = 16
S2 = 24
S3 = 12
S4 = 20
H1 = 100-199
H2 = 200-299
H3 = 300-399
H4 = 400-499
I1 = <b 0x16030100><r 8>
HeaderProtectionKey = %s
ContentPaddingAddition = 0-32
RekeyTimeout = 1
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%d
PersistentKeepalive = 1-5
""" % (cpriv, key, spub, port))
    client = json.loads(subprocess.check_output(
        [sys.executable, src + "/mkawg.py", "build", "--file", work + "/client.conf",
         "--socks-port", "1", "--loglevel", "debug"]))
    # The server mirrors the client's obfuscation through the same generator.
    # Both peers initiate (the hub must learn both addresses). With equal 1 s
    # rekey timers their initiations can keep crossing, each side discarding
    # its own pending handshake, for longer than the deadline; a slower server
    # timer lets the client's next retry land unopposed.
    server = json.loads(json.dumps(client))
    server["endpoints"][0].update(
        private_key=spriv, address=["10.66.0.1/32"], header_protection_key=server_key,
        rekey_timeout="4",
        peers=[{"address": "127.0.0.1", "port": port, "public_key": cpub,
                "allowed_ips": ["10.66.0.2/32"], "persistent_keepalive_interval": 1}])
    for name, config in (("client", client), ("server", server)):
        config.pop("inbounds")
        config.pop("route")
        with open("%s/%s.json" % (work, name), "w") as output:
            json.dump(config, output)
    procs = [subprocess.Popen([core, "run", "-c", "%s/%s.json" % (work, name)],
                              stdout=subprocess.DEVNULL,
                              stderr=open("%s/%s.log" % (work, name), "w"))
             for name in ("server", "client")]
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(p.poll() is not None for p in procs):
                return False
            # Decrypted keepalives in both directions prove the handshake and
            # header-protected transport packets interoperate.
            logs = [open("%s/%s.log" % (work, name), errors="replace").read()
                    for name in ("server", "client")]
            if all("receiving keepalive packet" in log for log in logs):
                return True
            time.sleep(0.2)
        return False
    finally:
        for p in procs:
            p.terminate()
            p.wait(5)
        hub.close()

started = time.time()
assert handshake(key, 8), "AWG 3.1 handshake failed"
# A wrong key must stay down for several times as long as the matching key
# took here (RekeyTimeout = 1 retries every second), not a fixed 8 seconds.
window = max(3.0, 4 * (time.time() - started))
assert not handshake(base64.b64encode(os.urandom(32)).decode(), window), \
    "AWG 3.1 handshake ignored HeaderProtectionKey"
PY
        then ok "amnezia-box AWG 3.1 handshake"; else bad "amnezia-box AWG 3.1 handshake"; fi
    else
        printf '  skip amnezia-box validation (set PROXY_UNIFI_AWG_CORE or cache tests/.cache/amnezia-box)\n'
    fi
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
    # Kernel ingress: the overlay replaces the WireGuard inbound by tag in a
    # link config and in a pool, and the userspace (empty) overlay keeps it.
    {
        echo 'py() { python3 "$@"; }'
        echo 'INGRESS_HOST_IP=169.254.77.1; INGRESS_PORT=41820'
        fn_src ingress_overlay_for
    } > "$_d/overlay.sh"
    echo '{}' > "$_d/empty.json"
    # shellcheck disable=SC2016 # $1-$6 expand inside the child shell.
    if gx "vless://$UUID@h:443?security=tls&type=grpc&sni=a" \
       && sh -c '. "$1"; ingress_overlay_for "$2" > "$3" && ingress_overlay_for "$4" "$5" > "$6"' sh \
           "$_d/overlay.sh" "$_d/c.json" "$_d/kernel.json" \
           "$_d/pool/01-provider.json" "$_d/pool/99-overlay.json" "$_d/pool-kernel.json" \
       && "$XR" run -dump -config "$_d/c.json" -config "$_d/kernel.json" > "$_d/link.dump" 2>/dev/null \
       && "$XR" run -dump -config "$_d/pool/01-provider.json" -config "$_d/pool/99-overlay.json" \
           -config "$_d/pool-kernel.json" > "$_d/pool.dump" 2>/dev/null \
       && "$XR" run -dump -config "$_d/c.json" -config "$_d/empty.json" > "$_d/empty.dump" 2>/dev/null \
       && python3 - "$_d" <<'PY'
import json, os, sys
def dump(name):
    return json.load(open(os.path.join(sys.argv[1], name)))
for name, tag in (("link.dump", "wg-in"), ("pool.dump", "socks")):
    only, = dump(name)["inbounds"]
    assert (only["tag"], only["protocol"]) == (tag, "dokodemo-door"), only
    assert (only["listen"], only["port"]) == ("169.254.77.1", 41820), only
    assert only["streamSettings"]["sockopt"]["tproxy"] == "tproxy", only
    assert only["sniffing"]["enabled"] is True, only
def guarded(outbound):
    rules = (outbound.get("settings") or {}).get("finalRules") or []
    return bool(rules) and rules[-1]["action"] == "block" and "127.0.0.0/8" in rules[-1]["ip"]
# Direct outbounds carry the private-target block, in their original places.
link = dump("link.dump")["outbounds"]
assert [o["tag"] for o in link] == ["proxy", "direct", "block"], link
assert guarded(link[1]) and not guarded(link[0]), link
pool = dump("pool.dump")["outbounds"]
assert [o["tag"] for o in pool] == ["proxy", "proxy-2", "block"], pool
assert guarded(pool[0]) and guarded(pool[1]), pool
empty = dump("empty.dump")
only, = empty["inbounds"]
assert (only["tag"], only["protocol"]) == ("wg-in", "wireguard"), only
assert not any(guarded(o) for o in empty["outbounds"]), empty["outbounds"]
PY
    then ok "xray loads the kernel ingress overlay (link and pool)"
    else bad "xray loads the kernel ingress overlay (link and pool)"; fi
    rm -rf "$_d"

    # proxy bench: throughput and the core's CPU through a real SOCKS core that
    # runs under safeexec exactly like the CLI's probe core.
    _bd="$(mktemp -d)"
    start_bulk_server "$_bd"; bench_lib "$_bd"
    _sp="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
    printf '{"inbounds":[{"listen":"127.0.0.1","port":%s,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}' \
        "$_sp" > "$_bd/socks.json"
    python3 "$SRC/safeexec.py" --user "$(id -un)" --timeout 60 --memory-mb 512 --fsize-mb 1 -- \
        "$XR" run -config "$_bd/socks.json" >/dev/null 2>&1 &
    _sx=$!; _i=0
    until python3 -c 'import socket,sys; socket.create_connection(("127.0.0.1",int(sys.argv[1])),0.2)' "$_sp" 2>/dev/null \
          || [ "$_i" -ge 50 ]; do
        _i=$((_i + 1)); sleep 0.1 2>/dev/null || sleep 1
    done
    # shellcheck disable=SC2016 # $1-$4 expand inside the child shell.
    _r="$(sh -c '. "$1"; _bench_run 3 "$2" "$3" "$4"' sh "$_bd/bench-lib.sh" \
        "http://127.0.0.1:$_bulk_port/" "socks5h://127.0.0.1:$_sp" "$_sx")"
    kill "$_sx" "$_bulk_pid" 2>/dev/null; wait "$_sx" "$_bulk_pid" 2>/dev/null
    if printf '%s\n' "$_r" | awk 'NF == 3 && $1 > 0 && $3 > 0 { found=1 } END { exit !found }'
    then ok "bench measures a SOCKS core's throughput and CPU"
    else bad "bench measures a SOCKS core's throughput and CPU (got: $_r)"; fi
    rm -rf "$_bd"

    # A probe core must not outlive its caller: cleanup has to reach safeexec
    # itself, which then stops the core's process group.
    _pd="$(mktemp -d)"
    printf 'vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:9?security=none&type=tcp#probe' > "$_pd/link"
    {
        cat <<SH
XRAY='$XR'; MKXRAY='$SRC/mkxray.py'; SAFEEXEC='$SRC/safeexec.py'
OUTBOUND_LINK='$_pd/link'; RUN_DIR='$_pd'
SH
        cat <<'SH'
have() { command -v "$1" >/dev/null 2>&1; }
py() { python3 "$@"; }
err() { echo "$*" >&2; }
current_engine() { echo xray; }
ensure_run_dir() { :; }
ensure_service_user() { SERVICE_USER="$(id -un)"; SERVICE_GROUP="$(id -gn)"; }
chown() { :; }   # the CLI hands the run dir to root; CI does not run as root
SH
        sed -n '/^py_bin() {/,/^}/p; /^_free_port() {/,/^}/p; /^_ping_cleanup() {/,/^}/p' "$SRC/proxy-unifi"
        sed -n '/^_socket_listening() {/,/^tcp_socket_listening()/p; /^_probe_start() {/,/^}/p' "$SRC/proxy-unifi"
        cat <<'SH'
_probe_start 30 256 || exit 1
_ping_cleanup
sleep 0.5
! ps -eo args | awk -v cfg="$RUN_DIR/ping.json" 'index($0, cfg) && !/awk/' | grep -q .
SH
    } > "$_pd/probe.sh"
    if have ss && sh "$_pd/probe.sh"; then ok "probe core stops with its caller"
    elif have ss; then bad "probe core stops with its caller"
    else printf '  skip probe core cleanup (ss not installed)\n'; fi
    rm -rf "$_pd"

    # Traced so a failure's tail names the step that broke (set -e stops there).
    if sh -x "$ROOT/tests/lifecycle.sh" "$XR" >"$_d.lifecycle" 2>&1; then ok "sandboxed CLI lifecycle + rollback"
    else bad "sandboxed CLI lifecycle + rollback"; tail -n 20 "$_d.lifecycle"; fi
    rm -f "$_d.lifecycle"

    # Kernel WireGuard ingress end to end changes the host's network, so it
    # runs only as root, or with sudo where PROXY_UNIFI_LAB=1 allows it (CI).
    if [ "$(id -u)" = 0 ]; then
        _lab="$(sh "$ROOT/tests/ingress-lab.sh" "$XR" 2>&1)"; _lab_rc=$?
    elif [ "${PROXY_UNIFI_LAB:-}" = 1 ] && sudo -n true 2>/dev/null; then
        _lab="$(sudo -n sh "$ROOT/tests/ingress-lab.sh" "$XR" 2>&1)"; _lab_rc=$?
    else
        _lab="INFO needs root (or PROXY_UNIFI_LAB=1 with sudo)"; _lab_rc=77
    fi
    if [ "$_lab_rc" = 77 ]; then
        printf '  skip kernel ingress lab (%s)\n' "$(printf '%s\n' "$_lab" | sed -n 's/^INFO //p' | tail -1)"
    else
        _lab_fail=0
        while IFS= read -r _line; do
            case "$_line" in
                "PASS "*) ok "ingress lab: ${_line#PASS }" ;;
                "FAIL "*) bad "ingress lab: ${_line#FAIL }"; _lab_fail=1 ;;
                "INFO "*) printf '  info %s\n' "${_line#INFO }" ;;
                *) printf '       %s\n' "$_line" ;;
            esac
        done <<EOF
$_lab
EOF
        [ "$_lab_rc" = 0 ] || [ "$_lab_fail" = 1 ] || bad "ingress lab exited with status $_lab_rc"
    fi
}

# -------------------------------------------------------------------------
# tier 4: network (local self-signed TLS server; needs openssl). Exercises the
# real fetch path against the response framings that bit us in the field:
# chunked transfer-encoding and gzip content-encoding.
# -------------------------------------------------------------------------
network_tests() {
    have openssl || { printf '== network == (skipped: openssl not found)\n'; return; }
    echo "== network =="

    # proxy bench without a proxy: streams finish, rates add up, and no core
    # process is sampled.
    _bd="$(mktemp -d)"
    start_bulk_server "$_bd"; bench_lib "$_bd"
    # shellcheck disable=SC2016 # $1-$2 expand inside the child shell.
    _r="$(sh -c '. "$1"; _bench_run 2 "$2"' sh "$_bd/bench-lib.sh" "http://127.0.0.1:$_bulk_port/")"
    kill "$_bulk_pid" 2>/dev/null; wait "$_bulk_pid" 2>/dev/null
    if printf '%s\n' "$_r" | awk 'NF == 3 && $1 > 0 && $3 == 0 { found=1 } END { exit !found }'
    then ok "bench measures a direct download"
    else bad "bench measures a direct download (got: $_r)"; fi
    rm -rf "$_bd"
    _d="$(mktemp -d)"
    openssl req -x509 -newkey rsa:2048 -keyout "$_d/key.pem" -out "$_d/cert.pem" -days 1 \
        -nodes -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1 \
        || { bad "network: cert gen"; rm -rf "$_d"; return; }
    cat > "$_d/srv.py" <<'PYEOF'
import base64, gzip, os, socket, ssl, sys
mode, portfile = sys.argv[1], sys.argv[2]
body = base64.b64encode(("vless://u@nl.example.com:443?security=tls&sni=a#NL\n"*3).encode())
if mode == "chunked":
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n"
            b"profile-update-interval: 6\r\nConnection: close\r\n\r\n"
            + ("%x\r\n" % len(body)).encode() + body + b"\r\n0\r\n\r\n")
elif mode == "gzip":
    gz = gzip.compress(body)
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(gz)) + gz
else:  # deliberately truncated fixed-length response
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % (len(body) + 1)) + body
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[3], sys.argv[4])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(5)
# Publish the ephemeral port atomically once the socket accepts connections.
with open(portfile + ".tmp", "w") as f: f.write(str(s.getsockname()[1]))
os.rename(portfile + ".tmp", portfile)
while True:
    c, _ = s.accept()
    try:
        t = ctx.wrap_socket(c, server_side=True); t.recv(4096); t.sendall(resp); t.close()
    except Exception:
        pass
PYEOF
    _serve() {  # <mode>: start a server on a free port and write its URL
        rm -f "$_d/port"
        python3 "$_d/srv.py" "$1" "$_d/port" "$_d/cert.pem" "$_d/key.pem" >/dev/null 2>&1 &
        _srv=$!; _i=0
        while [ ! -s "$_d/port" ] && [ "$_i" -lt 100 ]; do
            _i=$((_i + 1)); sleep 0.05 2>/dev/null || sleep 1
        done
        printf 'https://127.0.0.1:%s/sub' "$(cat "$_d/port" 2>/dev/null)" > "$_d/url.txt"
    }
    _stop() { kill "$_srv" 2>/dev/null; wait "$_srv" 2>/dev/null; }
    _fetch() {  # <mode> <name>
        _serve "$1"
        _out="$(PROXY_UNIFI_SUB_ALLOW_PRIVATE=1 SSL_CERT_FILE="$_d/cert.pem" \
            python3 "$SRC/mksub.py" fetch --url-file "$_d/url.txt" 2>&1)"
        _stop
        if printf '%s' "$_out" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["meta"]["count"]==1 else 1)' 2>/dev/null
        then ok "$2"; else bad "$2"; fi
    }
    _fetch chunked "fetch chunked transfer-encoding"
    _fetch gzip    "fetch gzip content-encoding"
    _serve truncated
    if PROXY_UNIFI_SUB_ALLOW_PRIVATE=1 SSL_CERT_FILE="$_d/cert.pem" \
       python3 "$SRC/mksub.py" fetch --url-file "$_d/url.txt" >"$_d/truncated.out" 2>&1; then
        bad "fetch rejects truncated fixed-length body"
    elif grep -Fq "incomplete subscription body" "$_d/truncated.out"; then
        ok "fetch rejects truncated fixed-length body"
    else
        bad "fetch rejects truncated fixed-length body"
    fi
    _stop
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
