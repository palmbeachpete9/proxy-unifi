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
LOG="$ROOT/boot.log"

# nothing to do if the package isn't installed
[ -x "$CLI" ] || exit 0
umask 077
mkdir -p "$ROOT"
exec >>"$LOG" 2>&1
printf '%s proxy-unifi boot recovery starting\n' "$(date -Iseconds 2>/dev/null || date)"

# Recreate the unit/symlink/timer and recover the service under the CLI's global
# mutation lock. The CLI performs the same stabilized PID/socket health check as
# an interactive import instead of accepting a transient "active" state.
"$CLI" boot-recover
echo "proxy-unifi boot recovery completed"
