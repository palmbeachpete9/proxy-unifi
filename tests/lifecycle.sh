#!/bin/sh
# Sandboxed proxy-unifi lifecycle test. Uses a real Xray validator with mocked
# systemd/socket state; never touches /data, /etc/systemd, or /usr/bin.
set -eu

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "usage: lifecycle.sh /path/to/xray" >&2
    exit 2
fi
XRAY_SRC="$1"
REPO="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
STATE="$T/mock-state"
mkdir -p "$T/root/bin" "$T/mock-bin" "$STATE"

cleanup() {
    if [ -s "$STATE/pid" ]; then kill "$(cat "$STATE/pid")" 2>/dev/null || true; fi
    rm -rf "$T"
}
trap cleanup EXIT INT TERM HUP

for f in mkxray.py mksingbox.py mksub.py mkjson.py proxylib.py safeexec.py; do
    cp "$REPO/src/$f" "$T/root/bin/$f"
done
cp "$XRAY_SRC" "$T/root/bin/xray"
chmod 0755 "$T/root/bin"/*

# Rewrite only fixed installation paths in the throwaway CLI and inject
# non-root test identity helpers immediately before dispatch.
sed \
    -e "s|^ROOT=\"/data/proxy-unifi\"|ROOT=\"$T/root\"|" \
    -e "s|^SERVICE_FILE=.*|SERVICE_FILE=\"$T/proxy-unifi.service\"|" \
    -e "s|^REFRESH_SERVICE_FILE=.*|REFRESH_SERVICE_FILE=\"$T/proxy-unifi-refresh.service\"|" \
    -e "s|^REFRESH_TIMER_FILE=.*|REFRESH_TIMER_FILE=\"$T/proxy-unifi-refresh.timer\"|" \
    -e "s|^ONBOOT_DST=.*|ONBOOT_DST=\"$T/on_boot.sh\"|" \
    -e "s|^PROXY_LINK=\"/usr/bin/proxy\"|PROXY_LINK=\"$T/proxy\"|" \
    "$REPO/src/proxy-unifi" > "$T/root/bin/proxy-base"
awk -v user="$(id -un)" -v group="$(id -gn)" '
    /^# Dispatch$/ && !done {
        print "ensure_service_user() { SERVICE_USER=\"" user "\"; SERVICE_GROUP=\"" group "\"; }"
        print "need_root() { :; }"
        done=1
    }
    { print }
' "$T/root/bin/proxy-base" > "$T/root/bin/proxy-unifi"
chmod 0755 "$T/root/bin/proxy-unifi"

cat > "$T/mock-bin/systemctl" <<'SH'
#!/bin/sh
set -eu
D="${MOCK_STATE:?}"
cmd="$1"; shift || true
unit=""
for arg in "$@"; do case "$arg" in --*) : ;; *) unit="$arg" ;; esac; done
key="$(printf '%s' "$unit" | tr '/.' '__')"
start_service() {
    if [ -s "$D/pid" ]; then kill "$(cat "$D/pid")" 2>/dev/null || true; fi
    sleep 300 & echo $! > "$D/pid"; : > "$D/active_$key"
}
case "$cmd" in
    daemon-reload) : ;;
    enable) : > "$D/enabled_$key"; case " $* " in *" --now "*) : > "$D/active_$key" ;; esac ;;
    disable) rm -f "$D/enabled_$key"; case " $* " in *" --now "*) rm -f "$D/active_$key" ;; esac ;;
    start|restart) start_service ;;
    stop)
        rm -f "$D/active_$key"
        if [ -s "$D/pid" ]; then kill "$(cat "$D/pid")" 2>/dev/null || true; rm -f "$D/pid"; fi ;;
    is-active)
        if [ -f "$D/active_$key" ]; then [ "${1:-}" = --quiet ] || echo active; exit 0
        else [ "${1:-}" = --quiet ] || echo inactive; exit 3; fi ;;
    is-enabled)
        if [ -f "$D/enabled_$key" ]; then [ "${1:-}" = --quiet ] || echo enabled; exit 0
        else [ "${1:-}" = --quiet ] || echo disabled; exit 1; fi ;;
    show) cat "$D/pid" ;;
    *) : ;;
esac
SH

cat > "$T/mock-bin/ss" <<'SH'
#!/bin/sh
set -eu
D="${MOCK_STATE:?}"
echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
if [ -s "$D/pid" ]; then
    echo "UNCONN 0 0 127.0.0.1:51821 0.0.0.0:* users:((\"xray\",pid=$(cat "$D/pid"),fd=3))"
    echo "UNCONN 0 0 127.0.0.1:51822 0.0.0.0:* users:((\"xray\",pid=$(cat "$D/pid"),fd=3))"
fi
SH

cat > "$T/mock-bin/chown" <<'SH'
#!/bin/sh
exit 0
SH
chmod 0755 "$T/mock-bin"/*

run_cli() {
    MOCK_STATE="$STATE" PATH="$T/mock-bin:$PATH" "$T/root/bin/proxy-unifi" "$@"
}
menu_input() {
    MOCK_STATE="$STATE" PATH="$T/mock-bin:$PATH" "$T/root/bin/proxy-unifi"
}
hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_cli install-service >/dev/null
LINK='vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.1.1.1:443?security=none&type=tcp#test'
printf '1\n%s\n\n0\n' "$LINK" | menu_input >/dev/null
[ -s "$T/root/etc/config.json" ] || exit 1
[ -s "$T/root/etc/link.txt" ] || exit 1
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1
CONFIG_HASH="$(hash_file "$T/root/etc/config.json")"
LINK_HASH="$(hash_file "$T/root/etc/link.txt")"

# A parser failure after txn_begin must immediately restore the prior generation.
printf '1\n%s\n\n0\n' "${LINK%#test}&unknownSemantic=x#bad" | menu_input >/dev/null 2>&1
[ "$(hash_file "$T/root/etc/config.json")" = "$CONFIG_HASH" ]
[ "$(hash_file "$T/root/etc/link.txt")" = "$LINK_HASH" ]
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

# Settings maintenance must not start a service that was deliberately stopped.
run_cli stop >/dev/null
printf '7\n1\n51822\n\n0\n' | menu_input >/dev/null
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi
grep -q '"port": 51822' "$T/root/etc/config.json"

# Pool mode must survive key regeneration and rebuild its WireGuard overlay.
cat > "$T/profile.json" <<'EOF'
{"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10808,"settings":{"udp":true}}],"outbounds":[{"protocol":"freedom","tag":"proxy"},{"protocol":"freedom","tag":"proxy-2"},{"protocol":"blackhole","tag":"block"}],"routing":{"balancers":[{"tag":"B","selector":["proxy"],"strategy":{"type":"leastPing"},"fallbackTag":"block"}],"rules":[{"type":"field","network":"tcp,udp","balancerTag":"B"}]},"burstObservatory":{"subjectSelector":["proxy"],"pingConfig":{"destination":"https://www.gstatic.com/generate_204","interval":"1m","timeout":"3s"}}}
EOF
printf '3\n%s\n\n0\n' "$T/profile.json" | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = xraypool ]
OLD_KEY="$(cat "$T/root/etc/wg/wg_private.key")"
OLD_OVERLAY="$(hash_file "$T/root/etc/pool/99-overlay.json")"
printf '6\ny\n\n0\n' | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = xraypool ]
[ "$(cat "$T/root/etc/wg/wg_private.key")" != "$OLD_KEY" ]
[ "$(hash_file "$T/root/etc/pool/99-overlay.json")" != "$OLD_OVERLAY" ]
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

# Recovery must be repeatable after interruption between moving the live ETC
# directory away and activating its replacement. Keep the original snapshot,
# leave both swap remnants, and verify boot recovery reconstructs the snapshot.
RECOVERY_HASH="$(hash_file "$T/root/etc/pool/99-overlay.json")"
TXROOT="$T/root/.transactions"
TXDIR="$TXROOT/txn.interrupted"
mkdir -p "$TXDIR"
cp -Rp "$T/root/etc" "$TXDIR/etc"
: > "$TXDIR/had-etc"
: > "$TXDIR/runtime-state"
cp -Rp "$TXDIR/etc" "$TXDIR/restore-candidate"
mv "$T/root/etc" "$TXDIR/failed-current"
printf '%s\n' "$TXDIR" > "$TXROOT/active"
run_cli boot-recover >/dev/null
[ "$(hash_file "$T/root/etc/pool/99-overlay.json")" = "$RECOVERY_HASH" ]
[ ! -e "$TXROOT/active" ] || exit 1
[ ! -e "$TXDIR" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

echo lifecycle-ok
