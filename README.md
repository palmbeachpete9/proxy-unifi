# Xray-core on UniFi OS

Run an [Xray-core](https://github.com/XTLS/Xray-core) proxy client
(**VLESS**, **VMess**, **Trojan**, **Shadowsocks**) directly on your UniFi Cloud Gateway — and
steer traffic into it from the native UniFi UI (via **Policy Engine**).

UniFi gateways have no built-in proxy support and can't dial a `vless://` /
`trojan://` / `ss://` server.
`xray-unifi` bridges that gap **without** patching UniFi OS or adding a custom WAN:
it presents the proxy to UniFi as an ordinary **WireGuard VPN Client**, which the
controller already knows how to route. It is headless, SSH-only (no LAN port, no web
UI), and persists across reboots and firmware upgrades via
[unifi-common](https://github.com/unifi-utilities/unifi-common).

## Getting started

SSH into your gateway as `root` and run:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/xray-unifi/main/install.sh | sh
```

Then run `xray` for the management menu:

1. **Import / replace proxy link** — paste your `vless://` / `trojan://` / `ss://` link.
2. **Show UniFi WireGuard VPN Client config** — copy the printed settings into
   `unifi.ui.com → Settings → VPN → VPN Client → Create New → WireGuard`
   (or upload the printed `.conf`).
3. In **Policy Engine → Policy Table**, create a Traffic Route that sends your
   chosen VLAN/clients through that VPN Client.

That's it — the tunnel now appears as a VPN profile and is fully usable for
policy-based routing, kill switch, and per-client selection in the UniFi UI.

## How it works

```
  ┌─────────────────────────── UniFi Cloud Gateway ───────────────────────────┐
  │  VLAN client ─▶ Policy Table route ─▶ WireGuard VPN Client (native UniFi)   │
  │                              │ encrypted WireGuard over loopback            │
  │                              ▼  udp 127.0.0.1:51821                          │
  │                        xray-core  (WireGuard inbound)                       │
  │                              │  terminates the tunnel, then routes          │
  │                              ▼  proxy outbound (vless/trojan/ss link)       │
  └──────────────────────────────┼─────────────────────────────────────────────┘
                                  ▼  out the normal WAN
                            your proxy / VPN server ──▶ Internet
```

The gateway's own WireGuard VPN Client completes a real WireGuard handshake with
xray-core over the loopback interface. xray terminates the tunnel and forwards
everything out through the proxy server from your link. No remote WireGuard server
is required — it works with any plain `vless://` / `trojan://` / `ss://` provider.

## Requirements

- A UniFi gateway on **UniFi OS 4.x** or newer (tested on 5.1.12): UCG-Ultra / Max / Fiber, UDM / Pro / SE,
  UXG, UDR, …, with SSH enabled and `root` access.
- `unifi-common` for boot persistence — the installer sets it up automatically if
  it isn't already present.

## Usage

Run `xray` with no arguments for the interactive menu, or use the direct commands:

| Command | Description |
|---|---|
| `xray` | Interactive management menu |
| `xray status` | Service, configured server, and listener status |
| `xray ping [proto]` | Test the proxy link — `proto` = `get`·`head`·`tcp`·`icmp` (default `get`) |
| `xray start` · `stop` · `restart` | Control the service |
| `xray logs [args]` | Tail service logs (passed to `journalctl`) |
| `xray help` | Show help |

The menu additionally covers: import/replace link, show the UniFi WireGuard config,
regenerate keys, change port/MTU/DNS, enable/disable autostart, update xray-core,
and uninstall.

### Testing the link (`xray ping`)

`xray ping` checks the server with a 5 s timeout and prints the latency (or
`timeout`). The protocol is selectable from the menu or as an argument, and the
default is configurable with `xray set ping <proto>`:

| Protocol | What it measures |
|---|---|
| `get` (default) | HTTP **GET** to `https://www.gstatic.com/generate_204` **through the proxy tunnel** — true end-to-end delay |
| `head` | Same, via **HEAD** |
| `tcp` | TCP handshake latency directly to the proxy server |
| `icmp` | ICMP echo to the proxy server host |

The proxied tests spin up a throwaway SOCKS→proxy xray instance on loopback, so
they validate the actual link without disturbing the running tunnel.

## Supported links

- **VLESS** (`vless://`) — UUID, `encryption`, `flow` (e.g. `xtls-rprx-vision`).
- **VMess** (`vmess://`) — standard base64-JSON share link (`add`/`port`/`id`/`aid`/`scy`/`net`/`tls`/…).
- **Trojan** (`trojan://`) — password auth, TLS by default.
- **Shadowsocks** (`ss://`) — SIP002 (`base64(method:password)@host:port`) and the
  legacy fully-base64 form; AEAD and 2022 ciphers. **SIP003 plugins:**
  `obfs-local`/`simple-obfs` and `v2ray-plugin` run **natively via sing-box** (no
  external binary). Any *other* plugin works through xray once its binary is placed
  in `/data/xray-unifi/plugins/`.
- **Hysteria2** (`hysteria2://` / `hy2://`) and **TUIC** (`tuic://`) — via sing-box.

For VLESS, VMess and Trojan: security `none` / `tls` / `reality` (`sni`, `fp`, `alpn`,
`pbk`, `sid`, `spx`, `allowInsecure`) and transports `tcp` (incl.
`headerType=http`), `ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp`, `kcp`,
`quic`.

## Engines (xray-core + sing-box)

xray-unifi ships **two cores** and picks one automatically per imported link:

- **xray-core** — VLESS, VMess, Trojan, plain Shadowsocks (default for everything
  it supports; strong REALITY / XTLS-Vision).
- **sing-box** — Shadowsocks **+ obfs/v2ray-plugin (in-process, no build)**,
  **Hysteria2**, **TUIC**.

Both terminate the **same** WireGuard tunnel (identical keys/port), so there is
always a single UniFi VPN Client entry regardless of which core is active. Only
one core runs at a time; `xray status` shows which. Note: xray binds the WireGuard
port on loopback (`127.0.0.1`); sing-box binds it on all interfaces (it has no
listen-address option) — harmless, since WireGuard only ever answers the one
configured peer key.

## Notes & caveats

- **SSH-only:** xray listens only on `127.0.0.1`. There is no LAN-facing port and no
  web UI — manage it exclusively over SSH.
- **Loopback endpoint:** the UniFi WireGuard VPN Client points at `127.0.0.1:51821`.
  If the UI rejects a loopback endpoint, set `WG_LISTEN` in
  `/data/xray-unifi/etc/settings.env` to a routable local address and re-import.
- **MTU:** defaults to `1340`. Lower it (`xray set mtu 1280`) if large transfers
  stall.
- **Routing granularity:** xray sees decrypted IP packets, so do your per-client /
  per-VLAN selection in the UniFi Policy Table (the whole point); xray just forwards
  everything out the proxy outbound. The WireGuard inbound runs in userspace
  (gVisor), not kernel mode.

## Persistence

Everything lives under **`/data/xray-unifi`**, which UniFi OS preserves across
reboots and firmware upgrades. A boot hook at `/data/on_boot.d/15-xray-unifi.sh`
re-creates the `xray` command and the systemd service on every boot, so a firmware
upgrade (which wipes the root filesystem) does not break the install.

## Uninstall

```sh
xray            # menu → 18. Uninstall
# or:
rm -rf /data/xray-unifi   # also wipe keys/config
```

Then delete the WireGuard VPN Client in the UniFi UI.

## Credits

Persistence model inspired by
[SierraSoftworks/tailscale-unifi](https://github.com/SierraSoftworks/tailscale-unifi)
and built on [unifi-utilities/unifi-common](https://github.com/unifi-utilities/unifi-common).
Powered by [XTLS/Xray-core](https://github.com/XTLS/Xray-core).

## License

MIT
