#!/bin/sh
# 15-xray-unifi.sh - executed at every boot by unifi-common's udm-boot service.
#
# UniFi OS wipes the root filesystem (/etc, /usr, systemd units, symlinks) on
# reboot and especially on firmware upgrades, but keeps /data. This hook lives
# in /data/on_boot.d/ and re-installs the systemd unit + the `xray-unifi` symlink
# from the persistent copy under /data/xray-unifi, then (re)starts the service.
set -eu

ROOT="/data/xray-unifi"
CLI="$ROOT/bin/xray-unifi"

# nothing to do if the package isn't installed
[ -x "$CLI" ] || exit 0

# expose the management CLI as `xray` on PATH (re-created each boot, /usr is ephemeral)
ln -sf "$CLI" /usr/bin/xray

# re-create + enable the systemd unit, then start (only if a link is configured)
"$CLI" install-service || true
if [ -f "$ROOT/etc/config.json" ]; then
    systemctl restart xray-unifi || systemctl start xray-unifi || true
fi
