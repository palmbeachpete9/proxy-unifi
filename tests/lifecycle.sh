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

for f in mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py mkfallback.py proxylib.py safeexec.py; do
    cp "$REPO/src/$f" "$T/root/bin/$f"
done
cp "$XRAY_SRC" "$T/root/bin/xray"
chmod 0755 "$T/root/bin"/*

# Rewrite only fixed installation paths in the throwaway CLI and inject
# non-root test identity helpers immediately before dispatch (and the tools
# kernel WireGuard ingress needs, so its unit rendering does not depend on this
# host; the mocked systemd never runs the unit's hooks). Service polling
# runs against the mocked systemctl, so its stability window (8 consecutive
# healthy checks) keeps its logic but not its 2-second real-time cost.
sed \
    -e "s|sleep 0\.25 2>/dev/null|sleep 0.01 2>/dev/null|" \
    -e "s|^ROOT=\"/data/proxy-unifi\"|ROOT=\"$T/root\"|" \
    -e "s|^SERVICE_FILE=.*|SERVICE_FILE=\"$T/proxy-unifi.service\"|" \
    -e "s|^REFRESH_SERVICE_FILE=.*|REFRESH_SERVICE_FILE=\"$T/proxy-unifi-refresh.service\"|" \
    -e "s|^REFRESH_TIMER_FILE=.*|REFRESH_TIMER_FILE=\"$T/proxy-unifi-refresh.timer\"|" \
    -e "s|^GUARD_SERVICE_FILE=.*|GUARD_SERVICE_FILE=\"$T/proxy-unifi-guard.service\"|" \
    -e "s|^GUARD_TIMER_FILE=.*|GUARD_TIMER_FILE=\"$T/proxy-unifi-guard.timer\"|" \
    -e "s|^FB_SERVICE_FILE=.*|FB_SERVICE_FILE=\"$T/proxy-unifi-fallback.service\"|" \
    -e "s|^FB_TIMER_FILE=.*|FB_TIMER_FILE=\"$T/proxy-unifi-fallback.timer\"|" \
    -e "s|^ONBOOT_DST=.*|ONBOOT_DST=\"$T/on_boot.sh\"|" \
    -e "s|^PROXY_LINK=\"/usr/bin/proxy\"|PROXY_LINK=\"$T/proxy\"|" \
    -e "s|^INGRESS_RUN=.*|INGRESS_RUN=\"$T/run\"|" \
    "$REPO/src/proxy-unifi" > "$T/root/bin/proxy-base"
awk -v user="$(id -un)" -v group="$(id -gn)" '
    /^# Dispatch$/ && !done {
        print "ensure_service_user() { SERVICE_USER=\"" user "\"; SERVICE_GROUP=\"" group "\"; }"
        print "need_root() { :; }"
        print "ingress_supported() { return 0; }"
        # The watchdog checks nodes through scripted results:
        # $MOCK_STATE/probe_<sub>_<first 8 hex of the node id> holds "ok MS" or "fail ERROR".
        print "_fallback_probe() { _fp=\"$MOCK_STATE/probe_${1}_$(printf %.8s \"$2\")\"; if [ -s \"$_fp\" ]; then cat \"$_fp\"; else echo \"fail unscripted\"; fi; }"
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
# Real systemctl cannot start/stop a unit by its file path.
case "$unit" in /*) echo "mock systemctl: '$unit' is a path, not a unit name" >&2; exit 1 ;; esac
key="$(printf '%s' "$unit" | tr '/.' '__')"
echo "$cmd $unit" >> "$D/systemctl.log"
start_service() {
    # The CLI holds its lock here: a dead owner would let any other caller take it.
    if [ -d "$D/../root/.lock" ] && ! kill -0 "$(cat "$D/../root/.lock/pid")" 2>/dev/null; then
        : > "$D/stale-lock"
    fi
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

cat > "$T/mock-bin/journalctl" <<'SH'
#!/bin/sh
echo "journalctl $*"
SH

cat > "$T/mock-bin/chown" <<'SH'
#!/bin/sh
exit 0
SH

cat > "$T/root/bin/amnezia-box" <<'SH'
#!/bin/sh
case "${1:-}" in
    version) echo 'sing-box version proxy-unifi-awg-1.1.0' ;;
    check)
        shift
        [ "${1:-}" = -c ] || exit 2
        python3 -m json.tool "$2" >/dev/null ;;
    run) sleep 300 ;;
    *) exit 2 ;;
esac
SH

cat > "$T/root/bin/sing-box" <<'SH'
#!/bin/sh
case "${1:-}" in
    version) echo 'sing-box version 1.13.14' ;;
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
chmod 0755 "$T/root/bin/amnezia-box" "$T/root/bin/sing-box"

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

# Main CLI layout remains a fixed-width, complete menu: subscriptions, then the
# fallback pool, then AWG, before the Xray JSON block.
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
           (" 2. Subscriptions", " 3. Fallback pool", " 4. Manage AmneziaWG profiles",
            " 5. Import an Xray JSON profile")]
assert positions == sorted(positions), positions
numbers=[int(x) for x in re.findall(r"│\s+([0-9]+)\. ", plain)]
assert numbers == list(range(23)), numbers
assert "[0-22]" in plain and "Fallback:   off" in plain
PY

LINK='vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.1.1.1:443?security=none&type=tcp#test'
printf '1\n%s\n\n0\n' "$LINK" | menu_input >/dev/null
[ -s "$T/root/etc/config.json" ] || exit 1
# A fresh install runs everything that is fast by default.
grep -q '^INGRESS="kernel"$' "$T/root/etc/settings.env"
grep -q '^LAN_ROUTE="on"$' "$T/root/etc/settings.env"
[ -s "$T/root/etc/link.txt" ] || exit 1
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1
CONFIG_HASH="$(hash_file "$T/root/etc/config.json")"
LINK_HASH="$(hash_file "$T/root/etc/link.txt")"
# Xray runs behind kernel WireGuard by default: the unit builds the path before
# the core starts and the core loads its overlay last.
grep -q '^ExecStartPre=+.*/proxy-unifi _ingress-up$' "$T/proxy-unifi.service"
grep -q '^ExecStopPost=-+.*/proxy-unifi _ingress-down$' "$T/proxy-unifi.service"
grep -q "^ExecStart=.*/xray run -config .*/config.json -config $T/run/ingress.json\$" "$T/proxy-unifi.service"
grep -q '^AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE$' "$T/proxy-unifi.service"

# A parser failure after txn_begin must immediately restore the prior generation.
printf '1\n%s\n\n0\n' "${LINK%#test}&unknownSemantic=x#bad" | menu_input >/dev/null 2>&1
[ "$(hash_file "$T/root/etc/config.json")" = "$CONFIG_HASH" ]
[ "$(hash_file "$T/root/etc/link.txt")" = "$LINK_HASH" ]
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

# Settings maintenance must not start a service that was deliberately stopped.
run_cli stop >/dev/null
printf '9\n1\n51822\n\n0\n' | menu_input >/dev/null
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi
grep -q '"port": 51822' "$T/root/etc/config.json"

# The ingress setting switches the unit between both paths and rejects others.
printf '9\n4\nuserspace\n\n0\n' | menu_input >/dev/null
grep -q '^INGRESS="userspace"$' "$T/root/etc/settings.env"
grep -q '^ExecStart=.*/xray run -config [^ ]*/config.json$' "$T/proxy-unifi.service"
grep -q '^ExecStartPre=-+.*/proxy-unifi _ingress-down$' "$T/proxy-unifi.service"
grep -q '^AmbientCapabilities=$' "$T/proxy-unifi.service"
run_cli status | grep -q "^ingress:   userspace (Xray's own WireGuard, as configured)$"
printf '9\n4\nfast\n\n0\n' | menu_input > "$T/ingress.out" 2>&1
grep -q 'ingress must be kernel|userspace' "$T/ingress.out"
grep -q '^INGRESS="userspace"$' "$T/root/etc/settings.env"
printf '9\n4\nkernel\n\n0\n' | menu_input >/dev/null
grep -q '^INGRESS="kernel"$' "$T/root/etc/settings.env"
grep -q '^ExecStartPre=+.*/proxy-unifi _ingress-up$' "$T/proxy-unifi.service"
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi

# LAN route mode is a persisted on/off setting, from the menu and the CLI, also
# while the service runs.
run_cli start >/dev/null
printf '9\n5\non\n\n0\n' | menu_input >/dev/null
grep -q '^LAN_ROUTE="on"$' "$T/root/etc/settings.env"
run_cli status | grep -q '^lan route: on, inactive until kernel WireGuard ingress runs$'
if run_cli set lan-route maybe >/dev/null 2>&1; then exit 1; fi
grep -q '^LAN_ROUTE="on"$' "$T/root/etc/settings.env"
run_cli set lan-route off >/dev/null
grep -q '^LAN_ROUTE="off"$' "$T/root/etc/settings.env"
if run_cli status | grep -q '^lan route:'; then exit 1; fi
run_cli stop >/dev/null

# Standards-compliant SS2022 switches to the existing sing-box core, preserves
# the UniFi-facing WG identity, and rolls back atomically on an invalid key.
SS_WG_PRIVATE_HASH="$(hash_file "$T/root/etc/wg/wg_private.key")"
SS_UNIFI_PUBLIC_HASH="$(hash_file "$T/root/etc/wg/unifi_public.key")"
SS2022_LINK="$(python3 - <<'PY'
import base64
key=base64.b64encode(bytes(range(16))).decode()
cred=base64.urlsafe_b64encode(("2022-blake3-aes-128-gcm:"+key).encode()).decode().rstrip("=")
print("ss://%s@1.1.1.1:8388#SS2022" % cred)
PY
)"
printf '1\n%s\n\n0\n' "$SS2022_LINK" | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = singbox ]
# Kernel ingress: sing-box runs the config its hook writes, behind its port guard.
grep -q "^ExecStart=.*/sing-box run -c $T/run/ingress.json\$" "$T/proxy-unifi.service"
[ "$(grep '^ExecStartPre=' "$T/proxy-unifi.service" | sed 's|=.*/proxy-unifi |=|')" = "ExecStartPre=_ingress-up
ExecStartPre=_fw-lock" ]
python3 - "$T/root/etc/config.json" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1],encoding="utf-8"))
assert cfg["endpoints"][0]["type"]=="wireguard"
out=cfg["outbounds"][0]
assert out["type"]=="shadowsocks" and out["method"]=="2022-blake3-aes-128-gcm"
assert "multiplex" not in out and "udp_over_tcp" not in out
assert cfg["route"]["final"]=="proxy"
PY
[ "$(hash_file "$T/root/etc/wg/wg_private.key")" = "$SS_WG_PRIVATE_HASH" ]
[ "$(hash_file "$T/root/etc/wg/unifi_public.key")" = "$SS_UNIFI_PUBLIC_HASH" ]
run_cli status > "$T/ss2022-status.out"
grep -q '^engine:    singbox$' "$T/ss2022-status.out"
grep -q '^protocol:  Shadowsocks 2022$' "$T/ss2022-status.out"
SS_CONFIG_HASH="$(hash_file "$T/root/etc/config.json")"
SS_LINK_HASH="$(hash_file "$T/root/etc/link.txt")"
BAD_SS2022_LINK="$(python3 - <<'PY'
import base64
key=base64.b64encode(bytes(range(15))).decode()
cred=base64.urlsafe_b64encode(("2022-blake3-aes-128-gcm:"+key).encode()).decode().rstrip("=")
print("ss://%s@1.1.1.1:8388#bad" % cred)
PY
)"
printf '1\n%s\n\n0\n' "$BAD_SS2022_LINK" | menu_input >/dev/null 2>&1
[ "$(cat "$T/root/etc/engine")" = singbox ]
[ "$(hash_file "$T/root/etc/config.json")" = "$SS_CONFIG_HASH" ]
[ "$(hash_file "$T/root/etc/link.txt")" = "$SS_LINK_HASH" ]
# An update or boot rebuilds the active config from the saved link, so generator
# fixes reach it; a link the generators now refuse keeps the running config.
python3 - "$T/root/etc/config.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
config["outbounds"][0]["written_by_an_older_version"] = True
json.dump(config, open(sys.argv[1], "w"))
PY
# (The sandbox has no iptables, so boot recovery stops at the firewall guard.)
run_cli boot-recover >/dev/null 2>&1 || true
[ "$(hash_file "$T/root/etc/config.json")" = "$SS_CONFIG_HASH" ]
cp "$T/root/etc/link.txt" "$T/link.saved"
sed 's/#SS2022$/?bogus=1#SS2022/' "$T/link.saved" > "$T/root/etc/link.txt"
run_cli boot-recover > "$T/rebuild.out" 2>&1 || true
grep -q 'Kept the current config: the saved link does not build with this version (unsupported link' "$T/rebuild.out"
if grep -q "$(printf '\033')\[0m)\." "$T/rebuild.out"; then exit 1; fi    # no colour codes inside the reason
[ "$(hash_file "$T/root/etc/config.json")" = "$SS_CONFIG_HASH" ]
cp "$T/link.saved" "$T/root/etc/link.txt"
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

# Pool mode must survive key regeneration and rebuild its WireGuard overlay. The
# profile, like those written for provider apps, also routes by an HTTP inbound.
cat > "$T/profile.json" <<'EOF'
{"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10808,"settings":{"udp":true}},{"tag":"http","protocol":"http","listen":"127.0.0.1","port":10809}],"outbounds":[{"protocol":"freedom","tag":"proxy"},{"protocol":"freedom","tag":"proxy-2"},{"protocol":"blackhole","tag":"block"}],"routing":{"balancers":[{"tag":"B","selector":["proxy"],"strategy":{"type":"leastPing"},"fallbackTag":"block"}],"rules":[{"type":"field","inboundTag":["http"],"outboundTag":"block"},{"type":"field","inboundTag":["socks","http"],"network":"tcp,udp","balancerTag":"B"}]},"burstObservatory":{"subjectSelector":["proxy"],"pingConfig":{"destination":"https://www.gstatic.com/generate_204","interval":"1m","timeout":"3s"}}}
EOF
printf '5\n%s\n\n0\n' "$T/profile.json" | menu_input > "$T/pool-import.out" 2>&1
[ "$(cat "$T/root/etc/engine")" = xraypool ]
grep -q "^ExecStart=.*/xray run -config .*/pool/01-provider.json -config .*/pool/99-overlay.json -config $T/run/ingress.json\$" \
    "$T/proxy-unifi.service"
if grep -q 'unsupported\|cannot use kernel WireGuard ingress' "$T/pool-import.out"; then exit 1; fi
python3 - "$T/root/etc/pool/01-provider.json" <<'PY'
import json, sys
rules = json.load(open(sys.argv[1]))["routing"]["rules"]
assert [r.get("inboundTag") for r in rules] == [["socks", "http"]], rules
PY
# The same profile from a subscription catalog saved by an earlier version,
# which marked it unsupported: the menu counts it and selecting it works.
mkdir -p "$T/root/etc/subscription"; chmod 700 "$T/root/etc/subscription"
printf 'https://sub.example/x' > "$T/root/etc/subscription/url.txt"
python3 - "$REPO/src" "$T/profile.json" "$T/root/etc/subscription/catalog.json" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
import mksub
cat = mksub.process_body(open(sys.argv[2], "rb").read().join([b"[", b"]"]))
cat["nodes"][0].update(recognized=False, members=0, server="profile",
                       reason="profile routing references an inbound removed by the WireGuard overlay")
cat["meta"]["supported"] = 0
json.dump(cat, open(sys.argv[3], "w"))
PY
rm -f "$T/root/etc/engine"
printf '2\n1\n1\n\n0\n' | menu_input > "$T/sub-select.out" 2>&1
grep -q ' 1 node ' "$T/sub-select.out"
if grep -q 'unsupported' "$T/sub-select.out"; then exit 1; fi
[ "$(cat "$T/root/etc/engine")" = xraypool ]
[ -s "$T/root/etc/subscription/selected" ]
# The single-subscription layout of earlier versions became subscription 1.
[ -s "$T/root/etc/subscription/1/url.txt" ] && [ ! -e "$T/root/etc/subscription/url.txt" ]
[ -s "$T/root/etc/subscription/1/catalog.json" ] && [ -s "$T/root/etc/subscription/1/name" ]
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "1"' \
    "$T/root/etc/subscription/selected.json"
[ ! -e "$T/root/.transactions/active" ] || exit 1
OLD_KEY="$(cat "$T/root/etc/wg/wg_private.key")"
OLD_OVERLAY="$(hash_file "$T/root/etc/pool/99-overlay.json")"
printf '8\ny\n\n0\n' | menu_input >/dev/null
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
printf '4\n1\n🇩🇪 Москва 🛜\n\n0\n' | menu_input > "$T/awg-create.out"
grep -q 'Saved AmneziaWG profile: \[DE\] Москва Wi-Fi' "$T/awg-create.out"
[ "$(find "$T/root/etc/awg/profiles" -name '*.conf' -type f | wc -l | tr -d ' ')" = 1 ]
[ ! -e "$T/root/etc/awg/selected" ]
[ "$(cat "$T/root/etc/engine")" = xraypool ]

printf '4\n2\n\n0\n' | menu_input > "$T/awg-list.out"
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
4
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

printf '4\n3\n1\n\n0\n' | menu_input > "$T/awg-select.out"
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
printf '6\n\n0\n' | menu_input > "$T/awg-details.out"
grep -q '^Protocol:       AmneziaWG 1.5$' "$T/awg-details.out"
if grep -q "$PRIVATE" "$T/awg-details.out"; then exit 1; fi
if grep -q "$PUBLIC" "$T/awg-details.out"; then exit 1; fi

# Deleting the active profile is fail-closed and leaves no stale generated state.
printf '4\n6\n1\ny\n\n0\n' | menu_input >/dev/null
[ ! -e "$T/root/etc/awg/selected" ]
[ ! -e "$T/root/etc/config.json" ]
[ ! -e "$T/root/etc/engine" ]
[ "$(find "$T/root/etc/awg/profiles" -name '*.conf' -type f | wc -l | tr -d ' ')" = 0 ]
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi

# A stale AWG marker must never make profile maintenance replace or stop a
# different authoritative engine. Simulate damaged legacy state around edit and
# delete operations and verify the active Xray tunnel remains byte-for-byte intact.
printf '1\n%s\n\n0\n' "$LINK" | menu_input >/dev/null
printf '4\n1\nStale marker test\n\n0\n' | menu_input >/dev/null
STALE_CONF="$(find "$T/root/etc/awg/profiles" -name '*.conf' -type f -print -quit)"
STALE_ID="$(basename "$STALE_CONF" .conf)"
STALE_CONFIG_HASH="$(hash_file "$T/root/etc/config.json")"
printf '%s' "$STALE_ID" > "$T/root/etc/awg/selected"
printf '4\n4\n1\n\n0\n' | menu_input >/dev/null
[ "$(cat "$T/root/etc/engine")" = xray ]
[ "$(hash_file "$T/root/etc/config.json")" = "$STALE_CONFIG_HASH" ]
[ ! -e "$T/root/etc/awg/selected" ]
run_cli status 2>/dev/null | grep -q '^service:   active'
printf '%s' "$STALE_ID" > "$T/root/etc/awg/selected"
printf '4\n6\n1\ny\n\n0\n' | menu_input >/dev/null
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
printf '4\n4\n1\n\n0\n' | menu_input >/dev/null
python3 "$T/root/bin/mkawg.py" validate \
    --file "$T/root/etc/awg/profiles/$BAD_ID.conf" >/dev/null
printf '4\n6\n1\ny\n\n0\n' | menu_input >/dev/null
[ ! -e "$T/root/etc/awg/profiles/$BAD_ID.conf" ]
[ ! -e "$T/root/etc/awg/profiles/$BAD_ID.name" ]
[ ! -e "$T/root/.transactions/active" ] || exit 1
[ ! -e "$T/root/.lock" ] || exit 1

# The benchmark validates its arguments before starting any download or core.
if run_cli bench 1 > "$T/bench.out" 2>&1; then exit 1; fi
grep -q 'bench duration must be 5-' "$T/bench.out"
if run_cli bench 5 'ftp://example.com/x' > "$T/bench.out" 2>&1; then exit 1; fi
grep -q 'bench URL must start with http:// or https://' "$T/bench.out"
run_cli help | grep -q '^  proxy bench '

# Several subscriptions: choose the subscription, then the node. A second one
# is placed by hand (the sandbox has no network).
mkdir -p "$T/root/etc/subscription/2"; chmod 700 "$T/root/etc/subscription/2"
printf 'https://two.example/s' > "$T/root/etc/subscription/2/url.txt"
printf 'Second' > "$T/root/etc/subscription/2/name"
python3 - "$REPO/src" "$T/root/etc/subscription/2/catalog.json" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
import mksub
links = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.1.1.1:443?security=none&type=tcp#two-a\n" \
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.0.0.1:443?security=none&type=tcp#two-b"
json.dump(mksub.process_body(links.encode()), open(sys.argv[2], "w"))
PY
printf '2\n1\n2\n2\n\n0\n' | menu_input > "$T/sub2.out" 2>&1
grep -q 'Second' "$T/sub2.out"
[ "$(cat "$T/root/etc/engine")" = xray ]
grep -q '@1.0.0.1:' "$T/root/etc/link.txt"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "2"' \
    "$T/root/etc/subscription/selected.json"
printf '2\n0\n' | menu_input > "$T/sub-menu.out" 2>&1
grep -q 'Active node: \[Second\] two-b' "$T/sub-menu.out"
# rename 2, then remove 1 (asks first); 2 keeps its number and its selection
printf '2\n5\n2\nRenamed\n\n0\n' | menu_input >/dev/null 2>&1
[ "$(cat "$T/root/etc/subscription/2/name")" = Renamed ]
printf '2\n4\n1\nn\n\n0\n' | menu_input >/dev/null 2>&1
[ -d "$T/root/etc/subscription/1" ]
printf '2\n4\n1\ny\n\n0\n' | menu_input >/dev/null 2>&1
[ ! -e "$T/root/etc/subscription/1" ] && [ -d "$T/root/etc/subscription/2" ]
[ -s "$T/root/etc/subscription/selected.json" ]
# a per-subscription User-Agent, then back to the default
printf '2\n8\n2\nv2rayN/7\n\n0\n' | menu_input >/dev/null 2>&1
[ "$(cat "$T/root/etc/subscription/2/ua")" = v2rayN/7 ]
printf '2\n8\n2\n\n\n0\n' | menu_input >/dev/null 2>&1
[ ! -e "$T/root/etc/subscription/2/ua" ]
# Refreshing all with no network: the failure is recorded, the catalog kept,
# and downloads never hold the lock (the stub fetch below takes 3 s).
cp "$T/root/bin/mksub.py" "$T/mksub.real"
cat > "$T/root/bin/mksub.py" <<PY
import runpy, sys, time
if sys.argv[1:2] == ["fetch"]:
    open("$T/fetching", "w").close()
    time.sleep(3)
    sys.exit("mksub: error: no network in the sandbox")
sys.argv[0] = "$T/mksub.real"
runpy.run_path("$T/mksub.real", run_name="__main__")
PY
run_cli sub-refresh-auto >/dev/null 2>&1 &
_rp=$!; _i=0
while [ ! -e "$T/fetching" ] && [ "$_i" -lt 200 ]; do _i=$((_i + 1)); sleep 0.05; done
[ -e "$T/fetching" ] && [ ! -d "$T/root/.lock" ]
wait "$_rp" || true
cp "$T/mksub.real" "$T/root/bin/mksub.py"
grep -q '^fail [0-9]* no network in the sandbox$' "$T/root/etc/subscription/2/status"
[ -s "$T/root/etc/subscription/2/catalog.json" ]
grep -q '@1.0.0.1:' "$T/root/etc/link.txt"
[ ! -e "$T/root/.lock" ] || exit 1
[ ! -e "$T/root/.transactions/active" ] || exit 1
# A refresh that finishes after its subscription was replaced (same number,
# another URL) is discarded: the new provider keeps its own nodes.
python3 - "$REPO/src" "$T/other-catalog.json" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
import mksub
json.dump(mksub.process_body(b"trojan://p@old.example.com:443?security=tls#old-provider"), open(sys.argv[2], "w"))
PY
CAT2_HASH="$(hash_file "$T/root/etc/subscription/2/catalog.json")"
rm -f "$T/fetching"
cat > "$T/root/bin/mksub.py" <<PY
import runpy, sys, time
if sys.argv[1:2] == ["fetch"]:
    open("$T/fetching", "w").close()
    time.sleep(3)
    sys.stdout.write(open("$T/other-catalog.json").read())
    sys.exit(0)
sys.argv[0] = "$T/mksub.real"
runpy.run_path("$T/mksub.real", run_name="__main__")
PY
run_cli sub-refresh-auto >/dev/null 2>&1 &
_rp=$!; _i=0
while [ ! -e "$T/fetching" ] && [ "$_i" -lt 200 ]; do _i=$((_i + 1)); sleep 0.05; done
printf 'https://replacement.example/s' > "$T/root/etc/subscription/2/url.txt"
wait "$_rp" || true
cp "$T/mksub.real" "$T/root/bin/mksub.py"
[ "$(hash_file "$T/root/etc/subscription/2/catalog.json")" = "$CAT2_HASH" ]
printf 'https://two.example/s' > "$T/root/etc/subscription/2/url.txt"
# A subscription removed while the refresh runs is skipped; the ones after it
# are still refreshed.
mkdir -p "$T/root/etc/subscription/3" "$T/root/etc/subscription/4"
printf 'https://three.example/s' > "$T/root/etc/subscription/3/url.txt"
printf 'https://four.example/s' > "$T/root/etc/subscription/4/url.txt"
cat > "$T/root/bin/mksub.py" <<PY
import runpy, shutil, sys
if sys.argv[1:2] == ["fetch"]:
    shutil.rmtree("$T/root/etc/subscription/3", ignore_errors=True)
    sys.exit("mksub: error: no network in the sandbox")
sys.argv[0] = "$T/mksub.real"
runpy.run_path("$T/mksub.real", run_name="__main__")
PY
run_cli sub-refresh-auto >/dev/null 2>&1 || true
cp "$T/mksub.real" "$T/root/bin/mksub.py"
grep -q '^fail [0-9]* no network in the sandbox$' "$T/root/etc/subscription/4/status"
rm -rf "$T/root/etc/subscription/4"

# The fallback watchdog: subscription 2 holds two-a (1.1.1.1) and two-b
# (1.0.0.1, active). The pool is built with the module directly here; the
# menu's wizard has its own checks.
cat2="$T/root/etc/subscription/2/catalog.json"
idof() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nodes"][int(sys.argv[2])]["id"])' "$cat2" "$1"; }
ida="$(idof 0)"; idb="$(idof 1)"
python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub 2 --catalog "$cat2" --index 2
python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub 2 --catalog "$cat2" --index 1
printf 'FALLBACK="on"\n' >> "$T/root/etc/settings.env"      # a later line wins in load_settings
echo "ok 40" > "$STATE/probe_2_$(printf %.8s "$ida")"
echo "fail timeout" > "$STATE/probe_2_$(printf %.8s "$idb")"
# #1 (two-b, active) is down: the switch comes on the 3rd run (FB_DOWN=3)
run_cli fallback-check >/dev/null; run_cli fallback-check >/dev/null
grep -q '@1.0.0.1:' "$T/root/etc/link.txt"
run_cli fallback-check > "$T/fb-run.out"
grep -q '@1.1.1.1:' "$T/root/etc/link.txt"
grep -q 'switch #1 -> #2' "$T/fb-run.out"
grep -q '#1 offline after 3 failed checks: timeout' "$T/root/fallback.last"
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"      # a watchdog switch keeps it on
run_cli status | grep -q '^fallback:  on, active #2 of 2'
# a held lock skips the run: not even a check is recorded
echo "ok 40" > "$STATE/probe_2_$(printf %.8s "$idb")"
FB_STATE_HASH="$(hash_file "$T/run/fallback.state")"
mkdir "$T/root/.lock"; sleep 300 & echo $! > "$T/root/.lock/pid"
run_cli fallback-check >/dev/null
[ "$(hash_file "$T/run/fallback.state")" = "$FB_STATE_HASH" ]
kill "$(cat "$T/root/.lock/pid")"; rm -rf "$T/root/.lock"
# a stopped service is never started by a run
run_cli stop >/dev/null; run_cli fallback-check >/dev/null
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi
run_cli start >/dev/null
# a stale switch is refused: the expected active node is not the real one
if run_cli _fallback-apply 2 "$idb" "$(printf '0%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64)" >/dev/null 2>&1; then exit 1; fi
grep -q '@1.1.1.1:' "$T/root/etc/link.txt"
# ... nor when the user stopped the service meanwhile (it stays stopped),
run_cli stop >/dev/null
if run_cli _fallback-apply 2 "$idb" "$ida" >/dev/null 2>&1; then exit 1; fi
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi
run_cli start >/dev/null
# ... nor to a node that left the pool meanwhile.
cp "$T/root/etc/fallback.json" "$T/pool.keep"
python3 "$T/root/bin/mkfallback.py" remove --pool "$T/root/etc/fallback.json" --position 1
if run_cli _fallback-apply 2 "$idb" "$ida" >/dev/null 2>&1; then exit 1; fi
cp "$T/pool.keep" "$T/root/etc/fallback.json"
grep -q '@1.1.1.1:' "$T/root/etc/link.txt"
# importing a link by hand turns fallback off and keeps the pool
run_cli status | grep -q '^fallback:  on, active #2 of 2'
printf '1\ny\n%s\n\n0\n' "$LINK" | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="off"' "$T/root/etc/settings.env"
[ -s "$T/root/etc/fallback.json" ]
run_cli status | grep -q '^fallback:  off'
[ ! -e "$T/root/.lock" ] || exit 1

# The fallback menu and its wizard: 2 nodes (two-b, then two-a), keep the
# order, Balanced, return to higher priority, turn it on. Turning on applies
# the highest-priority node that answers.
printf '3\n0\n' | menu_input > "$T/fb-menu.out" 2>&1
grep -q '^Fallback: off — balanced (every 20 s' "$T/fb-menu.out"
grep -q '^ 8. Turn fallback on/off$' "$T/fb-menu.out"
printf '3\n1\n2\n2\n1\n\n2\ny\ny\n\n0\n' | menu_input > "$T/fb-wizard.out" 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
[ -f "$STATE/enabled_proxy-unifi-fallback_timer" ]
grep -q '@1.0.0.1:' "$T/root/etc/link.txt"
# The watchdog's switches and errors reach the journal and 'proxy logs'.
grep -q '^SyslogLevel=notice$' "$T/proxy-unifi-fallback.service"
run_cli logs -n 5 | grep -q -- '-u proxy-unifi -u proxy-unifi-fallback -n 5'
printf '0\n' | menu_input > "$T/menu-on.out" 2>&1
grep -q 'Fallback:   on, active #1 of 2' "$T/menu-on.out"
# choosing a node by hand asks first: "n" changes nothing, "y" turns fallback
# off and keeps the pool
printf '2\n1\nn\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
grep -q '@1.0.0.1:' "$T/root/etc/link.txt"
printf '2\n1\ny\n1\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="off"' "$T/root/etc/settings.env"
grep -q '@1.1.1.1:' "$T/root/etc/link.txt"
[ ! -f "$STATE/enabled_proxy-unifi-fallback_timer" ]
[ -s "$T/root/etc/fallback.json" ]
# empty or invalid answers never save a half-built pool
cp "$T/root/etc/fallback.json" "$T/pool.before"
printf '3\n1\nx\n\n\n0\n' | menu_input >/dev/null 2>&1
printf '3\n1\n2\n2\n9\n\n\n0\n' | menu_input >/dev/null 2>&1
cmp "$T/pool.before" "$T/root/etc/fallback.json"
# reorder, remove, add, timing, return, test
printf '3\n4\n2 1\n\n0\n' | menu_input >/dev/null 2>&1
python3 -c 'import json,sys; n=json.load(open(sys.argv[1]))["nodes"]; assert [e["meta"]["label"] for e in n]==["two-a","two-b"], n' "$T/root/etc/fallback.json"
printf '3\n3\n2\n\n0\n' | menu_input >/dev/null 2>&1
python3 -c 'import json,sys; n=json.load(open(sys.argv[1]))["nodes"]; assert [e["meta"]["label"] for e in n]==["two-a"], n' "$T/root/etc/fallback.json"
printf '3\n2\n1\n2\n\n0\n' | menu_input >/dev/null 2>&1
python3 -c 'import json,sys; n=json.load(open(sys.argv[1]))["nodes"]; assert [e["meta"]["label"] for e in n]==["two-b","two-a"], n' "$T/root/etc/fallback.json"
printf '3\n5\n1\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FB_INTERVAL="10"' "$T/root/etc/settings.env" && grep -q '^FB_UP="3"' "$T/root/etc/settings.env"
printf '3\n5\n4\n700\n30\n2\n4\n8\n\n0\n' | menu_input >/dev/null 2>&1      # custom; 700 is re-asked
grep -q '^FB_INTERVAL="30"' "$T/root/etc/settings.env" && grep -q '^FB_TIMEOUT="8"' "$T/root/etc/settings.env"
printf '3\n6\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FB_RETURN="off"' "$T/root/etc/settings.env"
printf '3\n7\n\n0\n' | menu_input > "$T/fb-test.out" 2>&1
[ "$(grep -c 'online' "$T/fb-test.out")" -ge 2 ]
# turning on from the menu; removing a node while on leaves one: fallback turns off
printf '3\n8\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
printf '3\n3\n1\n\n0\n' | menu_input > "$T/fb-remove.out" 2>&1
grep -q '^FALLBACK="off"' "$T/root/etc/settings.env"
grep -q 'fewer than 2 pool nodes' "$T/fb-remove.out"
# An order is digits and spaces: "*" is refused with a hint, never expanded to file names.
printf '3\n4\n*\n\n0\n' | menu_input > "$T/fb-order.out" 2>&1
grep -q 'Enter the positions as numbers separated by spaces' "$T/fb-order.out"
if grep -q 'invalid int value' "$T/fb-order.out"; then exit 1; fi
# "Add a node" reports a damaged pool file before asking anything.
cp "$T/root/etc/fallback.json" "$T/pool.good"
printf '{"schema": 1, "nodes": [{"sub": "x"}]}' > "$T/root/etc/fallback.json"
printf '3\n2\n\n0\n' | menu_input > "$T/fb-add-bad.out" 2>&1
grep -q 'fallback pool file is malformed' "$T/fb-add-bad.out"
if grep -q 'Position in the pool' "$T/fb-add-bad.out"; then exit 1; fi
cp "$T/pool.good" "$T/root/etc/fallback.json"
[ ! -e "$T/root/.lock" ] || exit 1
[ ! -e "$T/root/.transactions/active" ] || exit 1

# "Add a node" adds to the pool as it is when saving: a change made while the
# user was picking (a refresh marking an entry missing) is kept.
{ printf '3\n2\n'; sleep 2
  python3 - "$T/root/etc/fallback.json" <<'PY'
import json, sys
pool = json.load(open(sys.argv[1]))
pool["nodes"][0]["missing"] = True
json.dump(pool, open(sys.argv[1], "w"))
PY
  printf '1\n2\n\n0\n'; } | menu_input > "$T/fb-add-race.out" 2>&1
python3 -c 'import json,sys; n=json.load(open(sys.argv[1]))["nodes"]
assert [(e["meta"]["label"], e["missing"]) for e in n] == [("two-b", False), ("two-a", True)], n' "$T/root/etc/fallback.json"
# Removing the active node from the pool says what happens next, and the next
# check moves to the best pool node. Subscription 3 is a copy of 2.
cp -Rp "$T/root/etc/subscription/2" "$T/root/etc/subscription/3"
rm -f "$T/root/etc/fallback.json"
for _e in 3:1 2:1 2:2; do
    python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub "${_e%:*}" \
        --catalog "$T/root/etc/subscription/${_e%:*}/catalog.json" --index "${_e#*:}"
done
echo "ok 40" > "$STATE/probe_3_$(printf %.8s "$ida")"
printf '3\n8\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "2"' "$T/root/etc/subscription/selected.json"
printf '3\n3\n2\n\n0\n' | menu_input > "$T/fb-remove-active.out" 2>&1
grep -q 'the next check switches to the highest-priority node that answers' "$T/fb-remove-active.out"
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
run_cli fallback-check >/dev/null
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "3"' "$T/root/etc/subscription/selected.json"
[ ! -e "$T/root/.lock" ] || exit 1

# Removing the subscription of the active node, with fallback on and 2 pool
# nodes left, says the next check switches (not "unchanged").
python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub 2 \
    --catalog "$T/root/etc/subscription/2/catalog.json" --index 1
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "3"' "$T/root/etc/subscription/selected.json"
printf '2\n4\n3\ny\n\n0\n' | menu_input > "$T/sub-remove-active.out" 2>&1
grep -q 'the next check switches to the highest-priority node that answers' "$T/sub-remove-active.out"
if grep -q 'active tunnel is unchanged' "$T/sub-remove-active.out"; then exit 1; fi
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
# A node missing after a refresh does not count against the pool's size: removing
# another node leaves fallback on, and the main menu says it is inactive.
cp -Rp "$T/root/etc/subscription/2" "$T/root/etc/subscription/4"
python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub 4 \
    --catalog "$T/root/etc/subscription/4/catalog.json" --index 1
python3 - "$T/root/etc/fallback.json" <<'PY'
import json, sys
pool = json.load(open(sys.argv[1]))
assert [(e["sub"], e["meta"]["label"]) for e in pool["nodes"]] == [("2", "two-b"), ("2", "two-a"), ("4", "two-a")], pool
pool["nodes"][1]["missing"] = True
json.dump(pool, open(sys.argv[1], "w"))
PY
printf '3\n3\n3\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
printf '0\n' | menu_input > "$T/menu-inactive.out" 2>&1
grep -q 'Fallback:   on, .*inactive: fewer than 2 pool nodes are available' "$T/menu-inactive.out"
# A new interval while fallback is on restarts the timer, so systemd uses it.
: > "$STATE/systemctl.log"
printf '3\n5\n3\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FB_INTERVAL="60"' "$T/root/etc/settings.env"
grep -q '^restart proxy-unifi-fallback.timer$' "$STATE/systemctl.log"
python3 - "$T/root/etc/fallback.json" <<'PY'
import json, sys
pool = json.load(open(sys.argv[1]))
pool["nodes"][1]["missing"] = False                                # back after a refresh
json.dump(pool, open(sys.argv[1], "w"))
PY
: > "$STATE/systemctl.log"
printf '3\n8\n\n3\n8\n\n0\n' | menu_input >/dev/null 2>&1      # off, then on again
grep -q '^restart proxy-unifi-fallback.timer$' "$STATE/systemctl.log"
[ ! -e "$T/root/.lock" ] || exit 1

[ ! -e "$STATE/stale-lock" ] || { echo "lock recorded a dead owner" >&2; exit 1; }
echo lifecycle-ok
