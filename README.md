# proxy-unifi

Run a headless proxy client on your UniFi Cloud Gateway and steer traffic into it
from the native UniFi UI (**Policy Engine → Policy Table**).

proxy-unifi ships **two cores** — [xray-core](https://github.com/XTLS/Xray-core) and
[sing-box](https://github.com/SagerNet/sing-box) — and automatically picks the right
one for each link you import. Both terminate the **same** WireGuard tunnel, so the
UniFi UI only ever needs **one** VPN Client entry.

UniFi gateways have no built-in outbound proxy support and can't dial any proxy protocol server's links (`vless://` /
`trojan://` / `ss://` / `hysteria2://` / `tuic://`). proxy-unifi bridges that
gap **without** altering UniFi OS packages: it presents the proxy to
UniFi as an ordinary, natively supported **WireGuard VPN Client**, which the controller already knows
how to route. It is headless, SSH-only (no web UI), and persists across reboots and
firmware upgrades via [unifi-common](https://github.com/unifi-utilities/unifi-common).

## Getting started

SSH into your gateway as `root` and run:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/main/install.sh | sh
```

Then run `proxy` for the management menu:

1. **Import / replace proxy link** — paste your `vless://` / `vmess://` /
   `trojan://` / `ss://` / `hysteria2://` / `tuic://` link.
2. **Show UniFi WireGuard VPN Client config** — copy the printed settings into a
   `.conf` file and upload it at
   `unifi.ui.com → Settings → VPN → VPN Client → Create New → WireGuard`
   (or enter the fields manually).
3. In **Policy Engine → Policy Table**, create a Traffic Route that sends your
   chosen VLAN/clients through that VPN Client.

You apply the WireGuard config in UniFi **once** — it stays valid even when you
switch between links/engines later.

## How it works

```
  ┌─────────────────────────── UniFi Cloud Gateway ───────────────────────────┐
  │  VLAN client ─▶ Policy Table route ─▶ WireGuard VPN Client (native UniFi)   │
  │                              │ encrypted WireGuard over loopback            │
  │                              ▼  udp 127.0.0.1:51821                          │
  │                  xray-core  OR  sing-box  (WireGuard inbound)               │
  │                              │  terminates the tunnel, then routes          │
  │                              ▼  proxy outbound (your imported link)          │
  └──────────────────────────────┼─────────────────────────────────────────────┘
                                  ▼  out the normal WAN
                            your proxy / VPN server ──▶ Internet
```

The gateway's own WireGuard VPN Client does a real WireGuard handshake with the
active core over loopback. The core terminates the tunnel and forwards everything
out through the proxy server from your link. No remote WireGuard server is required.

## Engines & protocol selection

The engine is chosen automatically from the imported link:

| Link | Engine |
|---|---|
| `vless://`, `vmess://`, `trojan://`, plain `ss://` | **xray-core** |
| `ss://` with `obfs-local`/`simple-obfs`/`v2ray-plugin` | **sing-box** (plugin in-process — no external binary) |
| `hysteria2://` / `hy2://`, `tuic://` | **sing-box** |
| `ss://` with any *other* SIP003 plugin | **xray-core** (external plugin binary, see below) |

Only one core runs at a time. Both use the **same** WireGuard keys/port, so the
single UniFi VPN Client entry works no matter which core is active — switching links
never requires re-pasting anything in UniFi.

> **Bind note:** xray binds the WireGuard port on loopback (`127.0.0.1:51821`);
> sing-box binds it on all interfaces (it has no listen-address option). This is
> harmless — WireGuard only ever answers the one configured peer key — but it is a
> difference worth knowing.

## Supported links

- **VLESS** (`vless://`) — UUID, `encryption`, `flow` (e.g. `xtls-rprx-vision`).
- **VMess** (`vmess://`) — standard base64-JSON share link.
- **Trojan** (`trojan://`) — password auth, TLS by default.
- **Shadowsocks** (`ss://`) — SIP002 and legacy base64; AEAD and 2022 ciphers.
  SIP003 `obfs-local`/`simple-obfs`/`v2ray-plugin` run natively via sing-box.
- **Hysteria2** (`hysteria2://` / `hy2://`) and **TUIC** (`tuic://`) — via sing-box.

For VLESS / VMess / Trojan: security `none` / `tls` / `reality` (`sni`, `fp`,
`alpn`, `pbk`, `sid`, `spx`, `allowInsecure`) and transports `tcp` (incl.
`headerType=http`), `ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp`, `kcp`, `quic`.

## Usage

Run `proxy` for the interactive menu, or use the direct commands:

| Command | Description |
|---|---|
| `proxy` | Interactive management menu |
| `proxy status` | Engine, configured server, and listener status |
| `proxy ping [proto]` | Test the link — `proto` = `get`·`head`·`tcp`·`icmp` (default `get`) |
| `proxy start` · `stop` · `restart` | Control the service |
| `proxy logs [args]` | Tail service logs (passed to `journalctl`) |
| `proxy help` | Show help |

The menu also covers: import/replace link, show the UniFi WireGuard config,
regenerate keys, change port/MTU/DNS, ping test + protocol, enable/disable
autostart, update cores, update geo files, and uninstall.

### Testing the link (`proxy ping`)

`proxy ping` checks the server with a 5 s timeout and prints latency (or `timeout`).
`get`/`head` measure the real round trip **through the tunnel** (via a throwaway
loopback SOCKS instance on the active engine); `tcp`/`icmp` hit the server directly.

## Notes & caveats

- **SSH-only management:** there is no web UI and no LAN-facing management port —
  manage it over SSH with `proxy`.
- **Loopback endpoint:** the UniFi WireGuard VPN Client points at `127.0.0.1:51821`.
  If the UI rejects a loopback endpoint, set `WG_LISTEN` in
  `/data/proxy-unifi/etc/settings.env` to a routable local address and re-import.
- **MTU** defaults to `1340` (`proxy set mtu 1280` if large transfers stall);
  **DNS** defaults to `8.8.8.8`.
- **Routing granularity:** the core sees decrypted IP packets, so do per-client /
  per-VLAN selection in the UniFi Policy Table; the core just forwards everything
  out the proxy outbound.
- **SS + exotic SIP003 plugin** (not obfs/v2ray-plugin): handled by xray with a
  supervised external plugin process. The binary must be placed in
  `/data/proxy-unifi/plugins/` (e.g. a self-built `obfs-local` for arm64).

## Persistence

Everything lives under **`/data/proxy-unifi`**, which UniFi OS preserves across
reboots and firmware upgrades. A boot hook at `/data/on_boot.d/15-proxy-unifi.sh`
re-creates the `proxy` command and the systemd service (with the correct engine) on
every boot, so a firmware upgrade does not break the install.

## Uninstall

```sh
proxy            # menu → Uninstall
# or:
rm -rf /data/proxy-unifi   # also wipe keys/config
```
Then delete the WireGuard VPN Client in the UniFi UI.

## Credits

Persistence model inspired by
[SierraSoftworks/tailscale-unifi](https://github.com/SierraSoftworks/tailscale-unifi)
and built on [unifi-utilities/unifi-common](https://github.com/unifi-utilities/unifi-common).
Powered by [XTLS/Xray-core](https://github.com/XTLS/Xray-core) and
[SagerNet/sing-box](https://github.com/SagerNet/sing-box).

## License

MIT
