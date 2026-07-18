#!/bin/sh
# install.sh - installer for proxy-unifi on UniFi Cloud Gateways / UniFi OS devices.
#
# Usage (on the gateway, via SSH as root):
#   curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/main/install.sh | sh
# or, from a local clone:
#   ./install.sh
#
# It installs the persistent package under /data/proxy-unifi, downloads xray-core,
# wires up the unifi-common boot hook, and installs the systemd service.
set -eu
umask 077

REPO_RAW="${PROXY_UNIFI_RAW:-https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/main}"
PROJECT_REPO="palmbeachpete9/proxy-unifi"
ROOT="/data/proxy-unifi"
BIN_DIR="$ROOT/bin"
ONBOOT_DIR="/data/on_boot.d"
ONBOOT_DST="$ONBOOT_DIR/15-proxy-unifi.sh"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || { red "Run as root (SSH into the gateway as 'root')."; exit 1; }
[ -d /data ] || { red "/data not found - this doesn't look like a UniFi OS device."; exit 1; }

# Keep staging on /data, the same filesystem as the live package, so final
# renames are atomic. The signal trap terminates the active mutator first.
WORKDIR="$(mktemp -d "/data/.proxy-unifi-install.XXXXXX")" || { echo "could not create temp dir" >&2; exit 1; }
chmod 700 "$WORKDIR" 2>/dev/null || true
LOG="$WORKDIR/install.log"
ACTIVE_PID=""
LOCK_DIR="$ROOT/.lock"
PROMOTION_MARKER="$WORKDIR/promotion-active"
PROMOTION_BACKUP="$WORKDIR/bin-backup"

restore_promotion() {
    [ -f "$PROMOTION_MARKER" ] || return 0
    _restore_rc=0
    for _r in proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py \
              xray sing-box amnezia-box geoip.dat geosite.dat; do
        if [ -f "$PROMOTION_BACKUP/$_r.absent" ]; then rm -f "$BIN_DIR/$_r" || _restore_rc=1
        elif [ -f "$PROMOTION_BACKUP/$_r" ]; then cp -p "$PROMOTION_BACKUP/$_r" "$BIN_DIR/$_r" || _restore_rc=1
        else _restore_rc=1; fi
    done
    if [ -f "$PROMOTION_BACKUP/on_boot.sh.absent" ]; then rm -f "$ONBOOT_DST" || _restore_rc=1
    elif [ -f "$PROMOTION_BACKUP/on_boot.sh" ]; then cp -p "$PROMOTION_BACKUP/on_boot.sh" "$ONBOOT_DST" || _restore_rc=1
    else _restore_rc=1; fi
    if [ "$_restore_rc" = 0 ]; then rm -f "$PROMOTION_MARKER"; fi
    return "$_restore_rc"
}

release_install_lock() {
    if [ "$(cat "$LOCK_DIR/pid" 2>/dev/null || true)" = "$$" ]; then
        rm -rf "$LOCK_DIR" 2>/dev/null || true
    fi
}

cleanup() {
    _rc="$1"
    trap - EXIT INT TERM HUP
    [ -z "$ACTIVE_PID" ] || { kill "$ACTIVE_PID" 2>/dev/null || true; wait "$ACTIVE_PID" 2>/dev/null || true; }
    _keep_workdir=0
    if ! restore_promotion; then
        red "Automatic script rollback was incomplete; recovery backup kept at $WORKDIR"
        _keep_workdir=1
    fi
    release_install_lock
    [ "$_keep_workdir" = 1 ] || rm -rf "$WORKDIR"
    exit "$_rc"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

have() { command -v "$1" >/dev/null 2>&1; }
if have python3; then PYTHON=python3
elif have python; then PYTHON=python
else PYTHON=""
fi

bounded_curl() {
    _url="$1"; _dest="$2"; _max="$3"
    ( ulimit -f $(((_max + 511) / 512)) 2>/dev/null || exit 1
      curl -fsSL --connect-timeout 15 --max-time 120 --retry 3 \
          --max-filesize "$_max" "$_url" -o "$_dest" ) || { rm -f "$_dest"; return 1; }
    _size="$(wc -c < "$_dest" | tr -d ' ')"
    case "$_size" in ""|*[!0-9]*) rm -f "$_dest"; return 1 ;; esac
    [ "$_size" -le "$_max" ] || { rm -f "$_dest"; return 1; }
}

acquire_install_lock() {
    mkdir -p "$ROOT" || return 1
    _tries=0
    _uninitialized=0
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        _owner="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
        case "$_owner" in ""|*[!0-9]*) _owner="" ;; esac
        if [ -z "$_owner" ]; then
            _uninitialized=$((_uninitialized + 1))
            if [ "$_uninitialized" -lt 10 ]; then
                sleep 0.2 2>/dev/null || sleep 1
                continue
            fi
            rm -rf "$LOCK_DIR" 2>/dev/null || true
            _uninitialized=0
            continue
        fi
        _uninitialized=0
        if ! kill -0 "$_owner" 2>/dev/null; then
            rm -rf "$LOCK_DIR" 2>/dev/null || true
            continue
        fi
        _tries=$((_tries + 1))
        [ "$_tries" -lt 150 ] || { echo "another proxy-unifi operation is still running" >&2; return 1; }
        sleep 0.2 2>/dev/null || sleep 1
    done
    printf '%s\n' "$$" > "$LOCK_DIR/pid" \
        || { rm -rf "$LOCK_DIR" 2>/dev/null || true; return 1; }
}

preflight() {
    [ -n "$PYTHON" ] || { echo "python3 is required" >&2; return 1; }
    "$PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' \
        || { echo "Python 3.9 or newer is required" >&2; return 1; }
    have systemctl || { echo "systemctl is required" >&2; return 1; }
    for _dep in bash find sort xargs; do
        have "$_dep" || { echo "$_dep is required for boot persistence" >&2; return 1; }
    done
    have ss || { echo "ss is required for post-start socket verification" >&2; return 1; }
    have iptables || { echo "iptables is required for fail-closed sing-box protection" >&2; return 1; }
    { have wg || have openssl; } || { echo "wg or openssl is required for WireGuard keys" >&2; return 1; }
    have curl || { echo "curl is required for installation and proxy latency tests" >&2; return 1; }
    { have useradd || have adduser; } || { echo "useradd or adduser is required" >&2; return 1; }
    if [ -z "${PROXY_UNIFI_RAW:-}" ] && [ ! -f "$SCRIPT_DIR/src/proxy-unifi" ]; then
        have curl || { echo "curl is required to pin remote installs to an immutable GitHub commit" >&2; return 1; }
    fi
    _free="$(df -Pk /data 2>/dev/null | awk 'NR==2 {print $4}')"
    case "$_free" in ""|*[!0-9]*) : ;; *) [ "$_free" -ge 250000 ] || { echo "need at least 250 MB free on /data" >&2; return 1; } ;; esac

    # Pin every project file in this install run to one immutable commit so CDN
    # caching or a branch update cannot produce a mixed-version package.
    if [ -z "${PROXY_UNIFI_RAW:-}" ] && have curl; then
        _meta="$WORKDIR/proxy-unifi-commit.json"
        bounded_curl https://api.github.com/repos/palmbeachpete9/proxy-unifi/commits/main \
            "$_meta" 2097152 || return 1
        _sha="$("$PYTHON" - "$_meta" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8")).get("sha","")
print(value if len(value)==40 and all(c in "0123456789abcdef" for c in value) else "")
PY
)"
        [ -n "$_sha" ] || { echo "could not resolve immutable project commit" >&2; return 1; }
        printf '%s\n' "https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/${_sha}" > "$WORKDIR/repo-raw"
        printf '%s\n' "https://cdn.jsdelivr.net/gh/palmbeachpete9/proxy-unifi@${_sha}" > "$WORKDIR/repo-cdn"
        printf '%s\n' "$_sha" > "$WORKDIR/repo-sha"
    fi
}

# Resolve where we copy source files from: local clone if present, else download.
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")"
# Per-run nonce appended to every download URL. raw.githubusercontent.com is
# served through a CDN that caches each path for minutes; a reinstall could
# otherwise pull a STALE script (this is exactly what made an emoji fix look
# like it "didn't apply"). A unique query string is a fresh cache key => fresh file.
CACHEBUST="$(date +%s 2>/dev/null || echo $$)"
SOURCE_DIR=""

prepare_source_bundle() {
    [ -z "${PROXY_UNIFI_RAW:-}" ] || return 1
    [ -s "$WORKDIR/repo-sha" ] || return 1
    _sha="$(cat "$WORKDIR/repo-sha")"
    case "$_sha" in ""|*[!0-9a-f]*) return 1 ;; esac
    [ "${#_sha}" = 40 ] || return 1
    _bundle="$WORKDIR/source.tar.gz"
    _source="$WORKDIR/source"
    if [ -d "$_source/src" ]; then SOURCE_DIR="$_source"; return 0; fi
    bounded_curl "https://codeload.github.com/${PROJECT_REPO}/tar.gz/${_sha}" \
        "$_bundle" 10485760 || return 1
    rm -rf "$_source"
    mkdir -p "$_source/src" || return 1
    "$PYTHON" - "$_bundle" "$_source/src" <<'PY' || { rm -rf "$_source"; return 1; }
import os
import shutil
import sys
import tarfile

archive_path, outdir = sys.argv[1], sys.argv[2]
needed = set("proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py "
             "safeexec.py on_boot.sh".split())
found = set()
limit = 2 * 1024 * 1024
root = os.path.realpath(outdir)
with tarfile.open(archive_path, "r:gz") as archive:
    for member in archive.getmembers():
        parts = member.name.split("/")
        if len(parts) != 3 or parts[1] != "src" or parts[2] not in needed:
            continue
        if member.issym() or member.islnk() or member.isdev() or member.isfifo() \
                or not member.isfile():
            raise SystemExit("unsafe archive member")
        if member.size < 0 or member.size > limit:
            raise SystemExit("archive member too large")
        dest = os.path.realpath(os.path.join(outdir, parts[2]))
        if dest != root and not dest.startswith(root + os.sep):
            raise SystemExit("unsafe archive path")
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("could not extract archive member")
        with source, open(dest, "wb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
        found.add(parts[2])
missing = sorted(needed - found)
if missing:
    raise SystemExit("archive missing: " + ", ".join(missing))
PY
    SOURCE_DIR="$_source"
}

fetch_remote() {
    _base="$1"; _src="$2"; _dst="$3"; _mode="${4:-0755}"
    if have curl; then
        bounded_curl "$_base/src/$_src?cb=$CACHEBUST" "$_dst" 2097152 \
            && chmod "$_mode" "$_dst"
    elif have wget; then
        ( ulimit -f 4096 2>/dev/null || exit 1
          wget -q --timeout=30 --tries=3 -O "$_dst" "$_base/src/$_src?cb=$CACHEBUST" ) \
            && [ "$(wc -c < "$_dst" | tr -d ' ')" -le 2097152 ] \
            && chmod "$_mode" "$_dst"
    else
        return 1
    fi
}

fetch() {
    # fetch <relative-path> <dest> [mode]
    src="$1"; dst="$2"
    _raw="$REPO_RAW"; [ -s "$WORKDIR/repo-raw" ] && _raw="$(cat "$WORKDIR/repo-raw")"
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/src/$src" ]; then
        install -m "${3:-0755}" "$SCRIPT_DIR/src/$src" "$dst"
    elif [ -n "$SOURCE_DIR" ] && [ -f "$SOURCE_DIR/src/$src" ]; then
        install -m "${3:-0755}" "$SOURCE_DIR/src/$src" "$dst"
    elif [ -s "$WORKDIR/repo-cdn" ] && fetch_remote "$(cat "$WORKDIR/repo-cdn")" "$src" "$dst" "${3:-0755}"; then
        :
    elif fetch_remote "$_raw" "$src" "$dst" "${3:-0755}"; then
        :
    else
        echo "need curl/wget or a usable source archive" >&2; return 1
    fi
}

# --------------------------------------------------------------------------
# Progress bar with a light spinner (all step output is hidden -> $LOG)
# --------------------------------------------------------------------------
STEP=0
STEPS_TOTAL=5
BACKSLASH="$(printf '\134')"
_bar() {
    _f=$(( $1 * 24 / 100 )); _b=""; _i=0
    while [ "$_i" -lt 24 ]; do
        if [ "$_i" -lt "$_f" ]; then _b="${_b}#"; else _b="${_b}."; fi
        _i=$((_i + 1))
    done
    printf '[%s] %3d%%' "$_b" "$1"
}
run_step() {
    # run_step <label> <command...>
    _label="$1"; shift
    STEP=$((STEP + 1))
    _pct=$(( STEP * 100 / STEPS_TOTAL ))
    "$@" >>"$LOG" 2>&1 &
    _pid=$!
    ACTIVE_PID="$_pid"
    _i=0
    _bar_text="$(_bar "$_pct")"
    while kill -0 "$_pid" 2>/dev/null; do
        case $((_i % 4)) in 0) _sp='|' ;; 1) _sp='/' ;; 2) _sp='-' ;; *) _sp="$BACKSLASH" ;; esac
        printf '\r  %s  %s  %-40s' "$_sp" "$_bar_text" "$_label"
        _i=$((_i + 1)); sleep 0.1 2>/dev/null || sleep 1
    done
    if wait "$_pid"; then
        ACTIVE_PID=""
        printf '\r  \033[32m\342\234\223\033[0m  %s  %-40s\n' "$_bar_text" "$_label"
    else
        ACTIVE_PID=""
        printf '\r  \033[31mx\033[0m  %s  %-40s\n' "$_bar_text" "$_label"
        red "Install step failed: $_label"
        red "--- last log lines ---"
        tail -n 15 "$LOG" >&2 2>/dev/null || true
        exit 1
    fi
}

ensure_unifi_common() {
    mkdir -p "$ONBOOT_DIR"
    if systemctl list-unit-files 2>/dev/null | grep -q '^udm-boot\.service'; then
        systemctl enable udm-boot >/dev/null 2>&1
        return
    fi
    # Install the audited unifi-common persistence unit directly. Its upstream
    # remote installer fetches another mutable HEAD resource internally, which
    # would defeat this installer's immutable-commit policy.
    _unit="$WORKDIR/udm-boot.service"
    cat > "$_unit" <<'EOF'
[Unit]
Description=UniFi Common
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=bash -c 'mkdir -p /data/on_boot.d && find -L /data/on_boot.d -mindepth 1 -maxdepth 1 -type f -print0 | sort -z | xargs -0 -r -n 1 -- sh -c '\''if test -x "$0"; then echo "%n: running $0"; "$0"; else case "$0" in *.sh) echo "%n: sourcing $0"; . "$0";; *) echo "%n: ignoring $0";; esac; fi'\''
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
    install -m 0644 "$_unit" /etc/systemd/system/udm-boot.service || return 1
    systemctl daemon-reload || return 1
    systemctl enable udm-boot >/dev/null 2>&1
}
# D19: fetch every script into a staging dir first, then promote each into the
# live BIN_DIR with an atomic rename. An interrupted/failed download therefore
# never leaves a half-written or mixed-version live install; the existing files
    # stay intact. Engine binaries keep their own staged+rename logic.
_install_files_locked() {
    mkdir -p "$BIN_DIR"
    _stage="$(mktemp -d "$WORKDIR/stage.XXXXXX")" || { echo "could not stage" >&2; return 1; }
    if [ -z "${PROXY_UNIFI_RAW:-}" ]; then
        prepare_source_bundle \
            || echo "project source archive unavailable; falling back to per-file downloads" >&2
    fi
    for f in proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py on_boot.sh; do
        fetch "$f" "$_stage/$f" 0755 || { echo "fetch failed: $f" >&2; return 1; }
        [ -s "$_stage/$f" ] || { echo "empty file fetched: $f" >&2; return 1; }
    done
    # basic sanity: the main script must be a shell script
    head -1 "$_stage/proxy-unifi" | grep -q '^#!/bin/sh' || { echo "fetched proxy-unifi looks wrong" >&2; return 1; }
    sh -n "$_stage/proxy-unifi" && sh -n "$_stage/on_boot.sh" || return 1
    "$PYTHON" -m py_compile "$_stage"/*.py || return 1
    _backup="$PROMOTION_BACKUP"; mkdir -p "$_backup"
    for f in proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py \
             xray sing-box amnezia-box geoip.dat geosite.dat; do
        if [ -e "$BIN_DIR/$f" ]; then cp -p "$BIN_DIR/$f" "$_backup/$f" || return 1
        else : > "$_backup/$f.absent"; fi
    done
    if [ -e "$ONBOOT_DST" ]; then cp -p "$ONBOOT_DST" "$_backup/on_boot.sh" || return 1
    else : > "$_backup/on_boot.sh.absent"; fi
    : > "$PROMOTION_MARKER"
    # promote atomically
    for f in proxy-unifi mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py; do
        if ! mv -f "$_stage/$f" "$BIN_DIR/$f" || ! chmod 0755 "$BIN_DIR/$f"; then
            return 1
        fi
    done
    # remove the pre-rename generator name so an upgraded install isn't left with
    # a stale, unused mkconfig.py alongside mkxray.py.
    rm -f "$BIN_DIR/mkconfig.py"
    mv -f "$_stage/on_boot.sh" "$ONBOOT_DST" || return 1
    chmod 0755 "$ONBOOT_DST" || return 1
    # the safe symlink is (re)created by 'install-service'; create it here too for
    # immediate use, but never clobber an unrelated /usr/bin/proxy.
    if [ ! -e /usr/bin/proxy ] || { [ -L /usr/bin/proxy ] && [ "$(readlink /usr/bin/proxy 2>/dev/null)" = "$BIN_DIR/proxy-unifi" ]; }; then
        ln -sf "$BIN_DIR/proxy-unifi" /usr/bin/proxy || return 1
    fi
    # Keep the marker and backup through core update + service installation.
    # The parent clears it only after the final step succeeds; any later failure
    # therefore restores one coherent pre-install set of scripts and assets.
}

install_files() {
    acquire_install_lock || return 1
    if _install_files_locked; then _rc=0; else _rc=$?; fi
    if [ "$_rc" != 0 ] && ! restore_promotion; then
        return 1
    fi
    release_install_lock
    return "$_rc"
}

install_and_verify_service() {
    "$BIN_DIR/proxy-unifi" boot-recover
}

: > "$LOG" 2>/dev/null || true
printf '\n  Installing proxy-unifi\n\n'
run_step "Checking gateway prerequisites" preflight
run_step "Preparing boot persistence" ensure_unifi_common
run_step "Installing files"           install_files
run_step "Updating proxy cores"       "$BIN_DIR/proxy-unifi" update
run_step "Installing service"         install_and_verify_service
rm -f "$PROMOTION_MARKER" || { red "Could not commit installation transaction."; exit 1; }
printf '\n'
grn "Installed."
cat <<'EOF'

Run: "proxy"

...for the management menu. Then:

1. Import your proxy server or subscription link, select nodes if needed

2. Copy shown WireGuard settings into a .conf file on your computer. Then, go to:

unifi.ui.com -> Settings -> VPN -> VPN Client -> Create New -> Type: WireGuard

...and use the saved .conf file in "Upload Configuration File"

3. Route selected traffic through the created VPN profile in Policy Engine, utilising native UniFi UI and its functionality

4. Success!

Run: "proxy help" for direct commands

EOF
