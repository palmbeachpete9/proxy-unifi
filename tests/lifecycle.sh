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

for f in mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py proxylib.py safeexec.py; do
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
    show)
        printf 'MainPID=%s\n' "$(cat "$D/pid" 2>/dev/null || echo 0)"
        if [ -f "$D/active_$key" ]; then echo 'ActiveState=active'; else echo 'ActiveState=inactive'; fi ;;
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

cat > "$T/root/bin/amnezia-box" <<'SH'
#!/bin/sh
case "${1:-}" in
    version) echo 'sing-box version proxy-unifi-awg-1.0.0' ;;
    check)
        shift
        [ "${1:-}" = -c ] || exit 2
        python3 -m json.tool "$2" >/dev/null ;;
    run) sleep 300 ;;
    *) exit 2 ;;
esac
SH

cat > "$T/mock-bin/nano" <<'SH'
#!/bin/sh
target=""
for target do :; done
[ -n "$target" ] && [ -s "${MOCK_NANO_SOURCE:?}" ] || exit 1
cp "$MOCK_NANO_SOURCE" "$target"
SH
chmod 0755 "$T/mock-bin"/*
chmod 0755 "$T/root/bin/amnezia-box"

PRIVATE='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
PUBLIC='Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA='
cat > "$T/awg.conf" <<EOF
[Interface]
PrivateKey = $PRIVATE
Address = 172.16.0.2/32
DNS = 8.8.8.8, 8.8.4.4
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0x01020304><r 16>

[Peer]
PublicKey = $PUBLIC
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.5:4500
PersistentKeepalive = 25
EOF

run_cli() {
    MOCK_STATE="$STATE" MOCK_NANO_SOURCE="$T/awg.conf" PATH="$T/mock-bin:$PATH" \
        "$T/root/bin/proxy-unifi" "$@"
}
menu_input() {
    COLUMNS="${COLUMNS:-100}" MOCK_STATE="$STATE" MOCK_NANO_SOURCE="$T/awg.conf" \
        PATH="$T/mock-bin:$PATH" \
        "$T/root/bin/proxy-unifi"
}
hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_cli install-service >/dev/null

# Main CLI layout remains a fixed-width, complete menu, with AWG directly after
# subscriptions and before the Xray JSON block.
printf '0\n' | menu_input > "$T/menu.out"
python3 - "$T/menu.out" <<'PY'
import re,sys,unicodedata
text=open(sys.argv[1],encoding="utf-8").read()
plain=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
rows=[line for line in plain.splitlines() if line.startswith(("│","┌","├","└"))]
def width(line):
    return sum(0 if unicodedata.combining(ch) else
               (2 if unicodedata.east_asian_width(ch) in ("W","F") else 1)
               for ch in line)
assert rows and all(width(line)==53 for line in rows), [(width(x),x) for x in rows]
positions=[plain.index(label) for label in
           ("Manage a multi-server subscription", "Manage AmneziaWG profiles",
            "Import an Xray JSON profile")]
assert positions == sorted(positions), positions
numbers=[int(x) for x in re.findall(r"│\s+([0-9]+)\. ", plain)]
assert numbers[:22] == list(range(22)), numbers[:22]
PY

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
printf '8\n1\n51822\n\n0\n' | menu_input >/dev/null
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi
grep -q '"port": 51822' "$T/root/etc/config.json"

# Pool mode must survive key regeneration and rebuild its WireGuard overlay.
cat > "$T/profile.json" <<'EOF'
{"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10808,"settings":{"udp":true}}],"outbounds":[{"protocol":"freedom","tag":"proxy"},{"protocol":"freedom","tag":"proxy-2"},{"protocol":"blackhole","tag":"block"}],"routing":{"balancers":[{"tag":"B","selector":["proxy"],"strategy":{"type":"leastPing"},"fallbackTag":"block"}],"rules":[{"type":"field","network":"tcp,udp","balancerTag":"B"}]},"burstObservatory":{"subjectSelector":["proxy"],"pingConfig":{"destination":"https://www.gstatic.com/generate_204","interval":"1m","timeout":"3s"}}}
EOF
printf '4\n%s\n\n0\n' "$T/profile.json" | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = xraypool ]
OLD_KEY="$(cat "$T/root/etc/wg/wg_private.key")"
OLD_OVERLAY="$(hash_file "$T/root/etc/pool/99-overlay.json")"
printf '7\ny\n\n0\n' | menu_input >/dev/null
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

# AWG profile creation/listing/selection runs through the real menu and parser.
# Switching cores must preserve the existing UniFi-facing WireGuard identity.
WG_PRIVATE_HASH="$(hash_file "$T/root/etc/wg/wg_private.key")"
UNIFI_PUBLIC_HASH="$(hash_file "$T/root/etc/wg/unifi_public.key")"
printf '3\n1\n🇩🇪 Москва 🛜\n\n0\n' | menu_input > "$T/awg-create.out"
grep -q 'Saved AmneziaWG profile: \[DE\] Москва Wi-Fi' "$T/awg-create.out"
[ "$(find "$T/root/etc/awg/profiles" -name '*.conf' -type f | wc -l | tr -d ' ')" = 1 ]
[ ! -e "$T/root/etc/awg/selected" ]
[ "$(cat "$T/root/etc/engine")" = xraypool ]

printf '3\n2\n\n0\n' | menu_input > "$T/awg-list.out"
grep -q '\[ \] AWG 1.5' "$T/awg-list.out"
grep -q '\[DE\] Москва Wi-Fi' "$T/awg-list.out"
if grep -q 'ð' "$T/awg-list.out"; then exit 1; fi
python3 - "$T/awg-list.out" <<'PY'
import re,sys,unicodedata
text=open(sys.argv[1],encoding="utf-8").read()
plain=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
assert "�" not in plain and "\r" not in plain
menu=plain[plain.index("AmneziaWG profiles:"):]
numbers=[int(x) for x in re.findall(r"^  ([0-7])\. ",menu,re.MULTILINE)]
assert numbers[:7] == list(range(1,8)) and "  0. Back" in menu
rows=[line for line in plain.splitlines() if re.match(r"^\s*\d+\. \[[ *]\] AWG",line)]
def width(line):
    return sum(0 if unicodedata.combining(ch) or
               unicodedata.category(ch) in ("Mn","Me","Cf") else
               (2 if ord(ch) >= 0x1f000 or
                unicodedata.east_asian_width(ch) in ("W","F") else 1)
               for ch in line)
assert rows and all(width(line) <= 100 for line in rows), rows
PY

# The profile catalog reflows instead of wrapping columns on a narrow terminal.
COLUMNS=60 menu_input > "$T/awg-list-narrow.out" <<'EOF'
3
2

0
EOF
python3 - "$T/awg-list-narrow.out" <<'PY'
import re,sys,unicodedata
text=open(sys.argv[1],encoding="utf-8").read()
plain=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
rows=[line for line in plain.splitlines()
      if re.match(r"^\s*\d+\. \[[ *]\] AWG",line) or line.startswith("     endpoint: ")]
def width(line):
    return sum(0 if unicodedata.combining(ch) or
               unicodedata.category(ch) in ("Mn","Me","Cf") else
               (2 if ord(ch) >= 0x1f000 or
                unicodedata.east_asian_width(ch) in ("W","F") else 1)
               for ch in line)
assert any(line.startswith("     endpoint: ") for line in rows), rows
assert rows and all(width(line) <= 60 for line in rows), rows
PY

printf '3\n3\n1\n\n0\n' | menu_input > "$T/awg-select.out"
[ "$(cat "$T/root/etc/engine")" = awg ]
[ -s "$T/root/etc/awg/selected" ]
grep -q '^ExecStart=.*/amnezia-box run -c .*/config.json$' "$T/proxy-unifi.service"
python3 - "$T/root/etc/config.json" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1],encoding="utf-8"))
assert [x["tag"] for x in cfg["endpoints"]] == ["wg-in","awg-out"]
assert cfg["route"]["final"] == "awg-out"
assert cfg["route"]["rules"] == [{"inbound":["wg-in"],"outbound":"awg-out"}]
assert "outbounds" not in cfg
PY
[ "$(hash_file "$T/root/etc/wg/wg_private.key")" = "$WG_PRIVATE_HASH" ]
[ "$(hash_file "$T/root/etc/wg/unifi_public.key")" = "$UNIFI_PUBLIC_HASH" ]
run_cli status > "$T/awg-status.out"
grep -q '^engine:    awg$' "$T/awg-status.out"
printf '5\n\n0\n' | menu_input > "$T/awg-details.out"
grep -q '^Protocol:       AmneziaWG 1.5$' "$T/awg-details.out"
if grep -q "$PRIVATE" "$T/awg-details.out"; then exit 1; fi
if grep -q "$PUBLIC" "$T/awg-details.out"; then exit 1; fi

# Deleting the active profile is fail-closed and leaves no stale generated state.
printf '3\n6\n1\ny\n\n0\n' | menu_input >/dev/null
[ ! -e "$T/root/etc/awg/selected" ]
[ ! -e "$T/root/etc/config.json" ]
[ ! -e "$T/root/etc/engine" ]
[ "$(find "$T/root/etc/awg/profiles" -name '*.conf' -type f | wc -l | tr -d ' ')" = 0 ]
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi

# A stale AWG marker must never make profile maintenance replace or stop a
# different authoritative engine. Simulate damaged legacy state around edit and
# delete operations and verify the active Xray tunnel remains byte-for-byte intact.
printf '1\n%s\n\n0\n' "$LINK" | menu_input >/dev/null
printf '3\n1\nStale marker test\n\n0\n' | menu_input >/dev/null
STALE_CONF="$(find "$T/root/etc/awg/profiles" -name '*.conf' -type f -print -quit)"
STALE_ID="$(basename "$STALE_CONF" .conf)"
STALE_CONFIG_HASH="$(hash_file "$T/root/etc/config.json")"
printf '%s' "$STALE_ID" > "$T/root/etc/awg/selected"
printf '3\n4\n1\n\n0\n' | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = xray ]
[ "$(hash_file "$T/root/etc/config.json")" = "$STALE_CONFIG_HASH" ]
[ ! -e "$T/root/etc/awg/selected" ]
run_cli status 2>/dev/null | grep -q '^service:   active'
printf '%s' "$STALE_ID" > "$T/root/etc/awg/selected"
printf '3\n6\n1\ny\n\n0\n' | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = xray ]
[ "$(hash_file "$T/root/etc/config.json")" = "$STALE_CONFIG_HASH" ]
[ ! -e "$T/root/etc/awg/selected" ]
[ ! -e "$STALE_CONF" ]
run_cli status 2>/dev/null | grep -q '^service:   active'

# An invalid on-disk profile remains editable and deletable from the CLI.
BAD_ID=33333333-3333-4333-8333-333333333333
printf '%s\n' '[Interface]' 'PrivateKey = invalid' > "$T/root/etc/awg/profiles/$BAD_ID.conf"
printf '%s' 'Broken profile' > "$T/root/etc/awg/profiles/$BAD_ID.name"
chmod 600 "$T/root/etc/awg/profiles/$BAD_ID.conf" "$T/root/etc/awg/profiles/$BAD_ID.name"
printf '3\n4\n1\n\n0\n' | menu_input >/dev/null
python3 "$T/root/bin/mkawg.py" validate \
    --file "$T/root/etc/awg/profiles/$BAD_ID.conf" >/dev/null
printf '3\n6\n1\ny\n\n0\n' | menu_input >/dev/null
[ ! -e "$T/root/etc/awg/profiles/$BAD_ID.conf" ]
[ ! -e "$T/root/etc/awg/profiles/$BAD_ID.name" ]
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

echo lifecycle-ok
