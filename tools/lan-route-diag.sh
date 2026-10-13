#!/bin/sh
# LAN route diagnostics for a UniFi gateway. Read-only: it changes no setting,
# rule or route. Run as root with LAN route on:
#   sh lan-route-diag.sh [PC-IP]
# With a PC address it also watches 30 s of that PC's traffic; browse or run a
# speed test on the PC while it does.
PC="${1:-}"
URL="https://speed.cloudflare.com/__down?bytes=10000000"
say() { printf '\n== %s\n' "$*"; }

say "system"
uname -r
proxy status 2>&1 | grep -E '^(ingress|lan route):'
TABLE="$(proxy status 2>/dev/null | sed -n 's/^lan route: on via table \([^ ]*\).*/\1/p')"
[ -n "$TABLE" ] || { echo "LAN route is not active; run: proxy set lan-route on"; exit 1; }
ip route show table "$TABLE"

say "offloads (pair, then LAN)"
LANDEV=br0
[ -z "$PC" ] || LANDEV="$(ip route get "$PC" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
for d in pu-lr0 "$LANDEV"; do
    printf '%s: ' "$d"; ethtool -k "$d" 2>/dev/null \
        | awk -F': ' '/^(tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload):/ { printf "%s=%s ", $1, $2 } END { print "" }'
done
printf 'pu-lr1: '; ip netns exec proxy-unifi ethtool -k pu-lr1 2>/dev/null \
    | awk -F': ' '/^(tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload):/ { printf "%s=%s ", $1, $2 } END { print "" }'
say "fast-path / offload modules"
lsmod 2>/dev/null | awk 'NR > 1 && tolower($1) ~ /sfe|ecm|nss|flow|hnat|ppe|fastpath|offload/ { print $1 }'

say "gateway's own downloads, 10 MB each (Mbit/s)"
MARK="$(ip rule show | awk -v t="$TABLE" '$NF == t && /fwmark/ { for (i = 1; i <= NF; i++) if ($i == "fwmark") { split($(i + 1), a, "/"); print a[1]; exit } }')"
printf 'WAN directly:       '; curl -4so /dev/null --max-time 30 -w '%{speed_download}\n' "$URL" | awk '{ printf "%.0f\n", $1 * 8 / 1e6 }'
printf 'WireGuard (wgclt):  '; curl -4so /dev/null --max-time 30 -w '%{speed_download}\n' \
    --interface "$(ip route show table "$TABLE" | awk '/^default dev/ { print $3; exit }')" "$URL" | awk '{ printf "%.0f\n", $1 * 8 / 1e6 }'
printf 'LAN route pair:     '; [ -n "$MARK" ] || MARK="none"; python3 - "$URL" "$MARK" <<'PY'
import socket, ssl, sys, time, urllib.parse
url = urllib.parse.urlsplit(sys.argv[1])
try:
    raw = socket.socket(); raw.setsockopt(socket.SOL_SOCKET, 36, int(sys.argv[2], 16)); raw.settimeout(30)  # SO_MARK
    raw.connect((url.hostname, 443))
    s = ssl.create_default_context().wrap_socket(raw, server_hostname=url.hostname)
    s.sendall(("GET %s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (url.path, url.query, url.hostname)).encode())
    start, total = time.time(), 0
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        total += len(chunk)
    print("%.0f" % (total * 8 / 1e6 / (time.time() - start)))
except (OSError, ValueError) as error:
    print("FAILED: %s" % error)
PY

[ -n "$PC" ] || { echo; echo "(pass the PC's IP address to also watch its traffic)"; exit 0; }
snap() {
    iptables -L FORWARD -v -x -n | awk '/pu-lr0/ { printf "forward %s %s; ", ($0 ~ /ctdir/ ? "replies" : "dropped"), $1 }'
    nstat -az TcpRetransSegs TcpExtTCPTimeouts 2>/dev/null | awk 'NR > 1 { printf "%s %s; ", $1, $2 }'; echo
}
say "watching $PC for 30 s: browse or run a speed test on the PC NOW"
snap > /tmp/lrd.before
sizes() { timeout 30 tcpdump -ni "$1" -Q "$2" -q "dst host $PC and not port 53" 2>/dev/null \
    | awk '{ n++; l = $NF + 0; if (l > m) m = l } END { printf "%d packets, largest %d bytes\n", n, m }'; }
sizes pu-lr0 in > /tmp/lrd.in & sizes "$LANDEV" out > /tmp/lrd.out &
timeout 30 tcpdump -nvi "$LANDEV" -c 12 "host $PC and tcp[tcpflags] & tcp-syn != 0" 2>/dev/null \
    | grep -oE '[0-9.]+ > [0-9.]+|mss [0-9]+' | paste - - > /tmp/lrd.syn
wait
snap > /tmp/lrd.after
echo "to the PC from the pair (pu-lr0 in):  $(cat /tmp/lrd.in)"
echo "to the PC on the LAN ($LANDEV out):      $(cat /tmp/lrd.out)"
echo "connection setups (address > address, MSS):"; sed 's/^/  /' /tmp/lrd.syn
echo "before: $(cat /tmp/lrd.before)"; echo "after:  $(cat /tmp/lrd.after)"
