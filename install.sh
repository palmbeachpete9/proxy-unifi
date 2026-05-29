#!/bin/sh
# install.sh - installer for xray-unifi on UniFi Cloud Gateways / UniFi OS devices.
#
# Usage (on the gateway, via SSH as root):
#   curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/xray-unifi/main/install.sh | sh
# or, from a local clone:
#   ./install.sh
#
# It installs the persistent package under /data/xray-unifi, downloads xray-core,
# wires up the unifi-common boot hook, and installs the systemd service.
set -eu

REPO_RAW="${XRAY_UNIFI_RAW:-https://raw.githubusercontent.com/palmbeachpete9/xray-unifi/main}"
ROOT="/data/xray-unifi"
BIN_DIR="$ROOT/bin"
ONBOOT_DIR="/data/on_boot.d"
ONBOOT_DST="$ONBOOT_DIR/15-xray-unifi.sh"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
ylw() { printf '\033[33m%s\033[0m\n' "$*"; }
say() { printf '==> %s\n' "$*"; }

[ "$(id -u)" = "0" ] || { red "Run as root (SSH into the gateway as 'root')."; exit 1; }
[ -d /data ] || { red "/data not found - this doesn't look like a UniFi OS device."; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Resolve where we copy source files from: local clone if present, else download.
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")"
fetch() {
    # fetch <relative-path> <dest>
    src="$1"; dst="$2"
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/src/$src" ]; then
        install -m "${3:-0755}" "$SCRIPT_DIR/src/$src" "$dst"
    elif have curl; then
        curl -fsSL "$REPO_RAW/src/$src" -o "$dst" && chmod "${3:-0755}" "$dst"
    elif have wget; then
        wget -qO "$dst" "$REPO_RAW/src/$src" && chmod "${3:-0755}" "$dst"
    else
        red "need curl or wget"; exit 1
    fi
}

say "Checking unifi-common (udm-boot) ..."
if [ ! -d "$ONBOOT_DIR" ] || ! systemctl list-unit-files 2>/dev/null | grep -q '^udm-boot'; then
    ylw "unifi-common's boot service was not detected."
    say "Installing unifi-common (runs /data/on_boot.d scripts at every boot) ..."
    if have curl; then
        curl -fsSL https://raw.githubusercontent.com/unifi-utilities/unifi-common/main/remote_install.sh | sh \
            || { red "Failed to install unifi-common. Install it manually first:"; \
                 red "  https://github.com/unifi-utilities/unifi-common"; exit 1; }
    else
        red "curl required to bootstrap unifi-common. Install it manually:"
        red "  https://github.com/unifi-utilities/unifi-common"
        exit 1
    fi
fi
mkdir -p "$ONBOOT_DIR"

say "Installing files into $ROOT ..."
mkdir -p "$BIN_DIR"
fetch "xray-unifi" "$BIN_DIR/xray-unifi" 0755
fetch "mkconfig.py" "$BIN_DIR/mkconfig.py" 0755
ln -sf "$BIN_DIR/xray-unifi" /usr/bin/xray

say "Installing boot hook -> $ONBOOT_DST ..."
fetch "on_boot.sh" "$ONBOOT_DST" 0755

say "Downloading xray-core ..."
"$BIN_DIR/xray-unifi" install-binary

say "Installing systemd service ..."
"$BIN_DIR/xray-unifi" install-service

grn ""
grn "xray-unifi installed."
echo
echo "Next steps:"
echo "  Run:  xray"
echo "  ...for the management menu. Then:"
echo "    1) option 1  -> import your proxy link (vless/trojan/ss)"
echo "    2) option 3  -> copy the WireGuard settings into"
echo "                    unifi.ui.com -> Settings -> VPN -> VPN Client -> WireGuard"
echo "    3) Route traffic through it in Policy Engine -> Policy Table."
echo
echo "  xray status     # quick health check"
echo "  xray help       # direct commands"
