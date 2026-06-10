#!/bin/sh
# 15-proxy-unifi.sh - executed at every boot by unifi-common's udm-boot service.
#
# UniFi OS wipes the root filesystem (/etc, /usr, systemd units, symlinks) on
# reboot and especially on firmware upgrades, but keeps /data. This hook lives
# in /data/on_boot.d/ and re-installs the systemd unit + the `proxy-unifi` symlink
# from the persistent copy under /data/proxy-unifi, then (re)starts the service.
set -eu

ROOT="/data/proxy-unifi"
CLI="$ROOT/bin/proxy-unifi"

# nothing to do if the package isn't installed
[ -x "$CLI" ] || exit 0

# re-create the systemd unit + the /usr/bin/proxy symlink (install-service does
# both, and safely: it won't clobber an unrelated /usr/bin/proxy). /usr is wiped
# each boot, so this restores it.
"$CLI" install-service || true

# Start only if a config OR pool profile is present AND autostart isn't disabled.
if { [ -f "$ROOT/etc/config.json" ] || [ -f "$ROOT/etc/pool/99-overlay.json" ]; } \
   && [ "$(cat "$ROOT/etc/autostart" 2>/dev/null || echo enabled)" != "disabled" ]; then
    systemctl restart proxy-unifi || systemctl start proxy-unifi || true
fi
