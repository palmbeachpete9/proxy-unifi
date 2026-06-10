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

REPO_RAW="${PROXY_UNIFI_RAW:-https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/main}"
ROOT="/data/proxy-unifi"
BIN_DIR="$ROOT/bin"
ONBOOT_DIR="/data/on_boot.d"
ONBOOT_DST="$ONBOOT_DIR/15-proxy-unifi.sh"

# Private mode-700 workspace for the install log; never a predictable, world-
# writable /tmp pathname (which a symlink could redirect when run as root).
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/proxy-unifi-install.XXXXXX")" || { echo "could not create temp dir" >&2; exit 1; }
chmod 700 "$WORKDIR" 2>/dev/null || true
LOG="$WORKDIR/install.log"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM HUP

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || { red "Run as root (SSH into the gateway as 'root')."; exit 1; }
[ -d /data ] || { red "/data not found - this doesn't look like a UniFi OS device."; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Resolve where we copy source files from: local clone if present, else download.
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")"
fetch() {
    # fetch <relative-path> <dest> [mode]
    src="$1"; dst="$2"
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/src/$src" ]; then
        install -m "${3:-0755}" "$SCRIPT_DIR/src/$src" "$dst"
    elif have curl; then
        curl -fsSL "$REPO_RAW/src/$src" -o "$dst" && chmod "${3:-0755}" "$dst"
    elif have wget; then
        wget -qO "$dst" "$REPO_RAW/src/$src" && chmod "${3:-0755}" "$dst"
    else
        echo "need curl or wget" >&2; return 1
    fi
}

# --------------------------------------------------------------------------
# Progress bar with a light spinner (all step output is hidden -> $LOG)
# --------------------------------------------------------------------------
STEP=0
STEPS_TOTAL=4
SPIN="$(printf '|/-\134')"   # | / - \  (CD-style spinner; \134 = backslash)
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
    _i=0
    while kill -0 "$_pid" 2>/dev/null; do
        _sp=$(printf '%s' "$SPIN" | cut -c $(( _i % 4 + 1 )))
        printf '\r  %s  %s  %-40s' "$_sp" "$(_bar "$_pct")" "$_label"
        _i=$((_i + 1)); sleep 0.1 2>/dev/null || sleep 1
    done
    if wait "$_pid"; then
        printf '\r  \033[32m\342\234\223\033[0m  %s  %-40s\n' "$(_bar "$_pct")" "$_label"
    else
        printf '\r  \033[31mx\033[0m  %s  %-40s\n' "$(_bar "$_pct")" "$_label"
        red "Install step failed: $_label"
        red "--- last log lines ---"
        tail -n 15 "$LOG" >&2 2>/dev/null || true
        exit 1
    fi
}

ensure_unifi_common() {
    mkdir -p "$ONBOOT_DIR"
    if systemctl list-unit-files 2>/dev/null | grep -q '^udm-boot'; then
        return 0
    fi
    have curl || { echo "curl required to bootstrap unifi-common" >&2; return 1; }
    curl -fsSL https://raw.githubusercontent.com/unifi-utilities/unifi-common/main/remote_install.sh | sh
}
# D19: fetch every script into a staging dir first, then promote each into the
# live BIN_DIR with an atomic rename. An interrupted/failed download therefore
# never leaves a half-written or mixed-version live install; the existing files
# stay intact. Engine binaries (xray/sing-box) keep their own staged+rename logic.
install_files() {
    mkdir -p "$BIN_DIR"
    _stage="$(mktemp -d "$WORKDIR/stage.XXXXXX")" || { echo "could not stage" >&2; return 1; }
    for f in proxy-unifi mkconfig.py mksingbox.py mksub.py mkjson.py on_boot.sh; do
        fetch "$f" "$_stage/$f" 0755 || { echo "fetch failed: $f" >&2; return 1; }
        [ -s "$_stage/$f" ] || { echo "empty file fetched: $f" >&2; return 1; }
    done
    # basic sanity: the main script must be a shell script
    head -1 "$_stage/proxy-unifi" | grep -q '^#!/bin/sh' || { echo "fetched proxy-unifi looks wrong" >&2; return 1; }
    # promote atomically
    for f in proxy-unifi mkconfig.py mksingbox.py mksub.py mkjson.py; do
        mv -f "$_stage/$f" "$BIN_DIR/$f" || return 1
        chmod 0755 "$BIN_DIR/$f"
    done
    mv -f "$_stage/on_boot.sh" "$ONBOOT_DST" || return 1
    chmod 0755 "$ONBOOT_DST"
    # the safe symlink is (re)created by 'install-service'; create it here too for
    # immediate use, but never clobber an unrelated /usr/bin/proxy.
    if [ ! -e /usr/bin/proxy ] || { [ -L /usr/bin/proxy ] && [ "$(readlink /usr/bin/proxy 2>/dev/null)" = "$BIN_DIR/proxy-unifi" ]; }; then
        ln -sf "$BIN_DIR/proxy-unifi" /usr/bin/proxy
    fi
}

: > "$LOG" 2>/dev/null || true
printf '\n  Installing proxy-unifi\n\n'
run_step "Preparing boot persistence" ensure_unifi_common
run_step "Installing files"           install_files
run_step "Downloading cores (xray + sing-box)" "$BIN_DIR/proxy-unifi" install-binary
run_step "Installing service"         "$BIN_DIR/proxy-unifi" install-service
printf '\n'
grn "Installed."
cat <<'EOF'

Run: "proxy"

...for the management menu. Then:

1. Import your proxy link (VLESS/VMess/Trojan/SS/Hysteria2/TUIC) - option "1"

2. Copy shown WireGuard settings into a .conf file on your PC / Mac. Then, go to:
unifi.ui.com -> Settings -> VPN -> VPN Client -> Create New -> Type: WireGuard
...and use the created .conf for "Upload Configuration File"

3. Route selected traffic through the created VPN profile in Policy Engine, utilising native UniFi UI and its functionality.

4. Success!

proxy status     # quick health check
proxy help       # direct commands
EOF
