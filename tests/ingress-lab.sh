#!/bin/sh
# Kernel WireGuard ingress lab. As root, runs the CLI's real _ingress-up,
# _ingress-down and _fw-reconcile hooks in throwaway network namespaces and
# pushes TCP and UDP through the transparent path into a real, unprivileged
# Xray core. With kernel WireGuard and wg(8), a WireGuard client in its own
# namespace plays the UniFi VPN client, handshake included; without them a veth
# pair stands in for the tunnel and the rest of the path is the same. Uses its
# own names, addresses and chains; never touches /data or systemd.
#
# Usage: ingress-lab.sh /path/to/xray. Prints "PASS name", "FAIL name" and
# "INFO text" lines; exits 77 when this host cannot run it.
set -eu

[ $# -eq 1 ] && [ -x "$1" ] || { echo "usage: ingress-lab.sh /path/to/xray" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "INFO needs root"; exit 77; }
for _tool in ip iptables ss curl python3; do
    command -v "$_tool" >/dev/null 2>&1 || { echo "INFO needs $_tool"; exit 77; }
done
XRAY_SRC="$1"
REPO="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
NS=pu-lab; CLIENT=pu-lab-client
VETH=pu-lab-v0; WGDEV=pu-lab-wg; CDEV=pu-lab-c
HOST_IP=169.254.78.1; PORT=41829; TARGET=198.51.100.7
FAILED=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILED=1; }
info() { echo "INFO $*"; }
check() {  # <name> <command...>
    _name="$1"; shift
    if "$@"; then pass "$_name"; else fail "$_name"; fi
}

# This host must support namespaces and TPROXY.
if ! ip netns add pu-lab-probe 2>/dev/null; then echo "INFO no network namespaces"; exit 77; fi
ip netns del pu-lab-probe
if ! iptables -t mangle -N PU_LAB_PROBE 2>/dev/null; then echo "INFO no iptables mangle table"; exit 77; fi
if iptables -t mangle -A PU_LAB_PROBE -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 9 2>/dev/null; then
    _tproxy=1; else _tproxy=0; fi
iptables -t mangle -F PU_LAB_PROBE; iptables -t mangle -X PU_LAB_PROBE
[ "$_tproxy" = 1 ] || { echo "INFO no TPROXY target"; exit 77; }
MODE=veth
if command -v wg >/dev/null 2>&1 && ip link add pu-lab-probe type wireguard 2>/dev/null; then
    ip link del pu-lab-probe; MODE=wireguard
fi

T="$(mktemp -d)"
chmod 755 "$T"
mkdir -p "$T/root/bin" "$T/root/etc/wg" "$T/mock" "$T/state"
PIDS=""
cleanup() {
    for _p in $PIDS; do kill "$_p" 2>/dev/null || true; done
    [ -x "$T/root/bin/proxy-unifi" ] && PATH="$T/mock:$PATH" "$T/root/bin/proxy-unifi" _ingress-down >/dev/null 2>&1
    ip netns del "$CLIENT" 2>/dev/null || true
    ip link del "$CDEV" 2>/dev/null || true
    wait 2>/dev/null || true
    [ -n "${LAB_KEEP:-}" ] || rm -rf "$T"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# A throwaway CLI with lab names, so a real installation on this host is safe.
sed \
    -e "s|^ROOT=\"/data/proxy-unifi\"|ROOT=\"$T/root\"|" \
    -e "s|^SERVICE_FILE=.*|SERVICE_FILE=\"$T/proxy-unifi.service\"|" \
    -e "s|^INGRESS_RUN=.*|INGRESS_RUN=\"$T/run\"|" \
    -e "s|^INGRESS_NS=.*|INGRESS_NS=\"$NS\"|" \
    -e "s|^INGRESS_WG=.*|INGRESS_WG=\"$WGDEV\"|" \
    -e "s|^INGRESS_VETH=.*|INGRESS_VETH=\"$VETH\"|" \
    -e "s|^INGRESS_VETH_NS=.*|INGRESS_VETH_NS=\"pu-lab-v1\"|" \
    -e "s|^INGRESS_HOST_IP=.*|INGRESS_HOST_IP=\"$HOST_IP\"|" \
    -e "s|^INGRESS_NS_IP=.*|INGRESS_NS_IP=\"169.254.78.2\"|" \
    -e "s|^INGRESS_PORT=.*|INGRESS_PORT=\"$PORT\"|" \
    -e "s|^INGRESS_TABLE=.*|INGRESS_TABLE=\"7708\"|" \
    -e "s|^INGRESS_PREF=.*|INGRESS_PREF=\"11\"|" \
    -e "s|^INGRESS_TP_CHAIN=.*|INGRESS_TP_CHAIN=\"PU_LAB_TP\"|" \
    -e "s|^INGRESS_IN_CHAIN=.*|INGRESS_IN_CHAIN=\"PU_LAB_IN\"|" \
    -e "s|^FW_CHAIN=.*|FW_CHAIN=\"PU_LAB_WG\"|" \
    "$REPO/src/proxy-unifi" > "$T/cli"
# Without kernel WireGuard, a veth pair into the client namespace is the tunnel.
# LAB_FAIL makes the tunnel step fail, to exercise the fallback.
awk -v mode="$MODE" -v client="$CLIENT" -v cdev="$CDEV" '
    /^# Dispatch$/ && !done {
        print "_lab_wg_link=\"$(command -v _ingress_wg_link)\""
        print "_ingress_wg_link() {"
        print "    [ -z \"${LAB_FAIL:-}\" ] || { _ingress_failed=\"lab: injected failure\"; return 1; }"
        if (mode == "veth") {
            print "    _ingress_step ip link add \"$INGRESS_WG\" type veth peer name " cdev " netns " client " || return 1"
            print "    _ingress_step ip link set \"$INGRESS_WG\" netns \"$INGRESS_NS\""
        } else {
            print "    _ingress_step ip link add \"$INGRESS_WG\" type wireguard || return 1"
            print "    _ingress_step wg set \"$INGRESS_WG\" listen-port \"$WG_PORT\" private-key \"$WG_DIR/wg_private.key\" peer \"$(cat \"$WG_DIR/unifi_public.key\")\" allowed-ips 0.0.0.0/0,::/0 || return 1"
            print "    _ingress_step ip link set \"$INGRESS_WG\" netns \"$INGRESS_NS\""
        }
        print "}"
        done=1
    }
    { print }
' "$T/cli" > "$T/root/bin/proxy-unifi"
chmod 755 "$T/root/bin/proxy-unifi"
for f in proxylib.py safeexec.py mkxray.py mkjson.py; do cp "$REPO/src/$f" "$T/root/bin/$f"; done
cp "$XRAY_SRC" "$T/root/bin/xray"; chmod 755 "$T/root/bin/xray"

# The lab's systemd: the core is "active" and its MainPID is the lab core.
cat > "$T/mock/systemctl" <<SH
#!/bin/sh
case "\$1" in
    show) echo "MainPID=\$(cat "$T/state/core.pid" 2>/dev/null || echo 0)"
          echo "ActiveState=\${LAB_STATE:-active}" ;;
    is-active) [ "\${LAB_STATE:-active}" = active ] ;;
    is-enabled) echo enabled ;;
esac
SH
chmod 755 "$T/mock/systemctl"
cli() { PATH="$T/mock:$PATH" "$T/root/bin/proxy-unifi" "$@"; }

free_udp_port() {
    python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
WG_PORT="$(free_udp_port)"
if [ "$MODE" = wireguard ]; then
    wg genkey > "$T/root/etc/wg/wg_private.key"
    wg genkey > "$T/unifi_private.key"
    wg pubkey < "$T/root/etc/wg/wg_private.key" > "$T/root/etc/wg/wg_public.key"
    wg pubkey < "$T/unifi_private.key" > "$T/root/etc/wg/unifi_public.key"
else
    for k in wg_private wg_public unifi_public; do
        python3 -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())' > "$T/root/etc/wg/$k.key"
    done
fi
printf 'xray' > "$T/root/etc/engine"
printf 'WG_PORT="%s"\nINGRESS="kernel"\n' "$WG_PORT" > "$T/root/etc/settings.env"
python3 - "$T/root/etc/config.json" "$WG_PORT" "$(cat "$T/root/etc/wg/wg_private.key")" \
    "$(cat "$T/root/etc/wg/unifi_public.key")" <<'PY'
import json, sys
path, port, secret, peer = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
json.dump({
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "tag": "wg-in", "listen": "127.0.0.1", "port": port, "protocol": "wireguard",
        "settings": {"secretKey": secret, "address": ["10.7.0.1/32"], "mtu": 1340,
                     "noKernelTun": True,
                     "peers": [{"publicKey": peer, "allowedIPs": ["0.0.0.0/0", "::/0"]}]},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}}],
    # Every destination is served on loopback, keeping its port.
    "outbounds": [{"tag": "proxy", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:0"}}],
}, open(path, "w"))
PY
chmod 755 "$T/root" "$T/root/etc"; chmod 644 "$T/root/etc/config.json"

# Servers behind the "proxy": bulk HTTP, a UDP echo, and UDP echoes holding a
# wildcard port without and with SO_REUSEADDR (like gateway services do).
cat > "$T/servers.py" <<'PY'
import http.server, os, socket, sys, threading
out = sys.argv[1]
def publish(name, port):
    with open(os.path.join(out, name + ".tmp"), "w") as f:
        f.write(str(port))
    os.rename(os.path.join(out, name + ".tmp"), os.path.join(out, name))
class Bulk(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        chunk = bytes(1 << 20)
        self.send_response(200)
        self.send_header("Content-Length", str(len(chunk) * 256))
        self.end_headers()
        try:
            for _ in range(256):
                self.wfile.write(chunk)
        except OSError:
            pass
    def log_message(self, *args):
        pass
def echo(name, host, reuse):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if reuse:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 0))
    publish(name, s.getsockname()[1])
    while True:
        data, peer = s.recvfrom(2048)
        s.sendto(data, peer)
for args in (("echo", "127.0.0.1", False), ("clash", "0.0.0.0", False), ("shared", "0.0.0.0", True)):
    threading.Thread(target=echo, args=args, daemon=True).start()
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Bulk)
publish("bulk", server.server_address[1])
server.serve_forever()
PY
python3 "$T/servers.py" "$T/state" >/dev/null 2>&1 &
PIDS="$PIDS $!"
_i=0
while [ ! -s "$T/state/bulk" ] || [ ! -s "$T/state/shared" ]; do
    _i=$((_i + 1)); [ "$_i" -lt 100 ] || { fail "lab servers start"; exit 1; }
    sleep 0.05
done
BULK="$(cat "$T/state/bulk")"; ECHO="$(cat "$T/state/echo")"
CLASH="$(cat "$T/state/clash")"; SHARED="$(cat "$T/state/shared")"

start_core() {  # <overlay>: the core runs unprivileged, with CAP_NET_RAW only
    if command -v setpriv >/dev/null 2>&1; then
        XRAY_LOCATION_ASSET="$T/root/bin" setpriv --reuid=65534 --regid=65534 --clear-groups \
            --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw --bounding-set=-all,+net_raw \
            "$T/root/bin/xray" run -config "$T/root/etc/config.json" -config "$1" > "$T/core.log" 2>&1 &
    else
        info "setpriv missing: the core runs as root"
        XRAY_LOCATION_ASSET="$T/root/bin" "$T/root/bin/xray" run \
            -config "$T/root/etc/config.json" -config "$1" > "$T/core.log" 2>&1 &
    fi
    echo $! > "$T/state/core.pid"; PIDS="$PIDS $!"
}
stop_core() {
    kill "$(cat "$T/state/core.pid")" 2>/dev/null || true
    wait "$(cat "$T/state/core.pid")" 2>/dev/null || true
    rm -f "$T/state/core.pid"
}
wait_listen() {  # <ss flags> <address:port>
    _i=0
    until ss "$1" | grep -q "$2 "; do
        _i=$((_i + 1)); [ "$_i" -lt 100 ] || return 1
        sleep 0.05
    done
}
client_tcp() {  # bytes fetched through the tunnel within 3 s
    ip netns exec "$CLIENT" curl -s -o /dev/null --noproxy '*' --max-time 3 \
        -w '%{size_download} %{speed_download}' "http://$TARGET:$BULK/" 2>/dev/null || true
}
client_udp() {  # <port>: "ok" when the echo comes back through the tunnel
    ip netns exec "$CLIENT" python3 - "$TARGET" "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
for _ in range(3):
    s.sendto(b"through-the-tunnel", (sys.argv[1], int(sys.argv[2])))
    try:
        if s.recv(64) == b"through-the-tunnel":
            print("ok"); break
    except socket.timeout:
        pass
else:
    print("timeout")
PY
}
mbit() { awk '{ printf "%.0f", $2 * 8 / 1e6 }'; }

info "mode: $MODE"
cli _ingress-down >/dev/null 2>&1 || true   # leftovers of an interrupted run
ip netns del "$CLIENT" 2>/dev/null || true
ip netns add "$CLIENT"
ip -n "$CLIENT" link set lo up

# 1. Kernel path up.
cli _ingress-up > "$T/up.log" 2>&1 && _up=0 || _up=$?
cat "$T/up.log" | sed 's/^/INFO   /'
check "ingress-up succeeds" [ "$_up" = 0 ]
check "kernel path marked active" [ -f "$T/run/kernel-ingress" ]
check "overlay replaces the WireGuard inbound by tag" python3 - "$T/run/ingress.json" "$HOST_IP" "$PORT" <<'PY'
import json, sys
inbound, = json.load(open(sys.argv[1]))["inbounds"]
assert inbound["tag"] == "wg-in" and inbound["protocol"] == "dokodemo-door"
assert inbound["listen"] == sys.argv[2] and inbound["port"] == int(sys.argv[3])
assert inbound["settings"] == {"network": "tcp,udp", "followRedirect": True}
assert inbound["streamSettings"]["sockopt"]["tproxy"] == "tproxy"
assert inbound["sniffing"]["routeOnly"] is True
PY
check "overlay is readable by the core" [ "$(stat -c %a "$T/run/ingress.json")" = 644 ]
check "WireGuard port guarded before use" iptables -C PU_LAB_WG -p udp --dport "$WG_PORT" ! -i lo -j DROP
check "tunnel MTU on the veth" [ "$(cat /sys/class/net/$VETH/mtu)" = 1340 ]

if [ "$MODE" = wireguard ]; then
    check "kernel WireGuard holds the port" sh -c "ss -lun | grep -q ':$WG_PORT '"
    # The UniFi side: created in the root namespace, so its socket can reach loopback.
    ip link add "$CDEV" type wireguard
    wg set "$CDEV" private-key "$T/unifi_private.key" \
        peer "$(cat "$T/root/etc/wg/wg_public.key")" endpoint "127.0.0.1:$WG_PORT" allowed-ips 0.0.0.0/0
    ip link set "$CDEV" netns "$CLIENT"
    ip -n "$CLIENT" addr add 10.7.0.2/32 dev "$CDEV"
    ip -n "$CLIENT" link set "$CDEV" mtu 1340 up
    ip -n "$CLIENT" route add default dev "$CDEV"
else
    ip -n "$CLIENT" addr add 10.7.0.2/32 dev "$CDEV"
    ip -n "$CLIENT" link set "$CDEV" mtu 1340 up
    ip -n "$CLIENT" route add 10.7.0.1/32 dev "$CDEV"
    ip -n "$CLIENT" route add default via 10.7.0.1 dev "$CDEV"
fi

start_core "$T/run/ingress.json"
check "unprivileged core binds the transparent listener" wait_listen -ltn "$HOST_IP:$PORT"
_tcp="$(client_tcp)"
check "TCP through the kernel path" [ "${_tcp%% *}" -gt 0 ] 2>/dev/null
info "kernel path: $(printf '%s\n' "$_tcp" | mbit) Mbit/s in this lab"
check "UDP through the kernel path" [ "$(client_udp "$ECHO")" = ok ]
check "UDP reply on a port the host shares (SO_REUSEADDR)" [ "$(client_udp "$SHARED")" = ok ]
check "UDP reply on a port the host holds is lost" [ "$(client_udp "$CLASH")" = timeout ]
if [ "$MODE" = wireguard ]; then
    check "UniFi-side handshake" sh -c "ip netns exec $NS wg show $WGDEV latest-handshakes | awk '{ exit !(\$2 > 0) }'"
fi

cli status > "$T/status.out" 2>&1 || true
check "status reports the kernel path" grep -q '^ingress:   kernel WireGuard' "$T/status.out"
check "status reports the guarded port" grep -q "^wg listen: 0.0.0.0:$WG_PORT (loopback only" "$T/status.out"
check "status names the clashing UDP port" grep -q "^udp note: .*\\b$CLASH/" "$T/status.out"
if grep -q "^udp note: .*\\b$SHARED/" "$T/status.out"; then fail "status skips a shared UDP port"
else pass "status skips a shared UDP port"; fi

# 2. The guard timer restores rules a firewall reload removed.
iptables -t mangle -D PREROUTING -i "$VETH" -j PU_LAB_TP
iptables -D INPUT -j PU_LAB_IN
ip rule del pref 11 iif "$VETH" lookup 7708
check "traffic stops without the rules" [ "$(client_tcp | cut -d' ' -f1)" = 0 ]
cli _fw-reconcile > "$T/reconcile.log" 2>&1 || true
_tcp="$(client_tcp)"
check "reconcile restores the kernel path" [ "${_tcp%% *}" -gt 0 ] 2>/dev/null
LAB_STATE=activating cli _fw-reconcile >/dev/null 2>&1 || true
check "reconcile leaves a starting core alone" [ -f "$T/run/kernel-ingress" ]

# 3. Teardown leaves nothing behind; a core that failed is counted.
stop_core
SERVICE_RESULT=exit-code cli _ingress-down >/dev/null 2>&1
check "a failed core is counted" [ "$(cat "$T/run/kernel-ingress.failures" 2>/dev/null)" = 1 ]
check "teardown removes the namespace and links" \
    sh -c "! ip netns list | cut -d' ' -f1 | grep -qx $NS && ! ip link show $VETH >/dev/null 2>&1"
check "teardown removes rules, route and guard" sh -c "
    ! iptables -t mangle -S | grep -q PU_LAB_TP && ! iptables -S | grep -q 'PU_LAB_IN\|PU_LAB_WG\|$VETH' \
    && ! ip rule show | grep -q 'lookup 7708' && [ -z \"\$(ip route show table 7708 2>/dev/null)\" ]"
check "teardown removes the marker and overlay" sh -c "[ ! -e '$T/run/kernel-ingress' ] && [ ! -e '$T/run/ingress.json' ]"
if [ "$MODE" = wireguard ]; then
    check "teardown frees the WireGuard port" sh -c "! ss -lun | grep -q ':$WG_PORT '"
else
    ip netns del "$CLIENT"; ip netns add "$CLIENT"; ip -n "$CLIENT" link set lo up
fi

# 4. A refused step falls back to Xray's WireGuard and cleans up.
LAB_FAIL=1 cli _ingress-up > "$T/fallback.log" 2>&1 && _up=0 || _up=$?
check "fallback still starts the core" [ "$_up" = 0 ]
check "fallback overlay keeps the WireGuard inbound" [ "$(cat "$T/run/ingress.json" 2>/dev/null)" = "{}" ]
check "fallback records why" grep -q 'injected failure' "$T/run/kernel-ingress.error"
check "fallback leaves no kernel path" sh -c "
    [ ! -e '$T/run/kernel-ingress' ] && ! ip netns list | cut -d' ' -f1 | grep -qx $NS \
    && ! iptables -t mangle -S | grep -q PU_LAB_TP && ! iptables -S | grep -q PU_LAB_WG"

rm -f "$T/run/kernel-ingress.failures"
cli _ingress-down >/dev/null 2>&1

# 5. A core that keeps failing on the kernel path gets Xray's WireGuard.
echo 3 > "$T/run/kernel-ingress.failures"
cli _ingress-up > "$T/fallback.log" 2>&1 || true
check "repeated core failures fall back" sh -c "
    [ \"\$(cat '$T/run/ingress.json')\" = '{}' ] && [ ! -e '$T/run/kernel-ingress' ] \
    && grep -q 'failed 3 times' '$T/run/kernel-ingress.error' && ! ip netns list | cut -d' ' -f1 | grep -qx $NS"
SERVICE_RESULT=exit-code cli _ingress-down >/dev/null 2>&1
check "a userspace core failure is not counted" [ "$(cat "$T/run/kernel-ingress.failures")" = 3 ]
rm -f "$T/run/kernel-ingress.failures"

if [ "$MODE" = wireguard ]; then
    LAB_FAIL=1 cli _ingress-up >/dev/null 2>&1   # Xray's WireGuard again
    # The same UniFi-side client now handshakes with Xray's own WireGuard
    # (a fresh peer handshakes at once instead of after its session times out).
    _server="$(cat "$T/root/etc/wg/wg_public.key")"
    ip netns exec "$CLIENT" wg set "$CDEV" peer "$_server" remove
    ip netns exec "$CLIENT" wg set "$CDEV" peer "$_server" endpoint "127.0.0.1:$WG_PORT" allowed-ips 0.0.0.0/0
    start_core "$T/run/ingress.json"
    check "fallback core holds the WireGuard port" wait_listen -lun "127.0.0.1:$WG_PORT"
    _tcp="$(client_tcp)"
    [ "${_tcp%% *}" -gt 0 ] 2>/dev/null || _tcp="$(client_tcp)"   # first try may race the handshake
    check "TCP through Xray's WireGuard" [ "${_tcp%% *}" -gt 0 ] 2>/dev/null
    info "userspace path: $(printf '%s\n' "$_tcp" | mbit) Mbit/s in this lab"
    stop_core
fi
cli _ingress-down >/dev/null 2>&1
[ "$FAILED" = 0 ] || { sed 's/^/INFO core: /' "$T/core.log" 2>/dev/null | tail -20; exit 1; }
