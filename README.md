# proxy-unifi

Run a headless proxy client on your UniFi Cloud Gateway and steer traffic into it
from the native UniFi UI (**Policy Engine → Policy Table**).

proxy-unifi ships **two cores** — [xray-core](https://github.com/XTLS/Xray-core) and
[sing-box](https://github.com/SagerNet/sing-box) — and automatically picks the right
one for each link you import. Both terminate the **same** WireGuard tunnel, so the
UniFi UI only ever needs **one** VPN Client entry.

UniFi gateways have no built-in outbound proxy support and can't dial any proxy protocol server's links (`vless://`, `hysteria2://`, ...).
proxy-unifi bridges that gap **without** altering UniFi OS packages: it presents the proxy to
UniFi as a natively supported **WireGuard VPN Client**, which the controller already knows
how to route. It is headless, SSH-only (no web UI), and persists across reboots and
firmware upgrades via [unifi-common](https://github.com/unifi-utilities/unifi-common).

## Getting started

SSH into your gateway as `root` and run:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/main/install.sh | sh
```

After the script finishes the installation, run `proxy` for the management menu:

1. **Import / replace proxy link** — paste your link (i.e.: `vless://`). Currently, only single-server links are supported! Subscription links are unsupported, planned to be in the future.

2. **Copy the shown WireGuard VPN Client config** — create a `.conf` file locally on your computer and upload it at:

   `unifi.ui.com → Your gateway -> Settings → VPN → VPN Client → Create New → WireGuard`

3. Finally, use **Policy Engine** to create any traffic routes you desire, utilising native Ubiquiti functionality - VLAN / Device / IP / Domain / Region routing.

The created `.conf` file & Ubiquiti WireGuard config is persistent for the entire script's life. Swapping proxy links or protocols from one to another does **not** change it, making it easier to maintain.

## How it works

```
  ┌─────────────────────────── UniFi Cloud Gateway ────────────────────────────┐
  │  VLAN client ─▶ Policy Table route ─▶ WireGuard VPN Client (native UniFi)  │
  │                              │ encrypted WireGuard over loopback           │
  │                              ▼  udp 127.0.0.1:51821                        │
  │                  xray-core  OR  sing-box  (WireGuard inbound)              │
  │                              │  terminates the tunnel, then routes         │
  │                              ▼  proxy outbound (your imported link)        │
  └──────────────────────────────┼─────────────────────────────────────────────┘
                                 ▼  out the normal WAN
                            your proxy / VPN server ──▶ Internet
```

The gateway's own WireGuard VPN Client does a real WireGuard handshake with the
active core over loopback. The core terminates the tunnel and forwards everything
out through the proxy server from your link. No remote WireGuard server is required.

## Compatibility

This package is compatible with UniFi OS 4.x or newer and is known to work on the following UniFi devices:
| Model | Code |
|---|---|
| UniFi Cloud Gateway Ultra | `UCG-Ultra` |
| UniFi Cloud Gateway Max | `UCG-Max` |
| UniFi Cloud Gateway Fiber | `UCG-Fiber` |
| UniFi Dream Router | `UDR` |
| UniFi Dream Router 7 | `UDR7` |
| UniFi Dream Machine | `UDM` |
| UniFi Dream Machine Pro | `UDM-Pro` |
| UniFi Dream Machine SE | `UDM-SE` |
| UniFi Dream Machine Pro Max | `UDM-Pro-Max` |
| UniFi Express | `UX` |
| UniFi Express 7 | `UX7` |
| UniFi Enterprise Fortress Gateway | `EFG` |

> **Note:** Some UniFi OS updates (i.e. UniFi OS 5.1.12 that introduced several CVE patches) may completely wipe the script & its data from onboard memory. 
> Keep your proxy link saved for cases like that, and reinstall proxy-unifi.

The proxy engine is chosen automatically based on the imported link:

| Protocol | Engine |
|---|---|
| VLESS | xray-core |
| VMess | xray-core |
| Trojan | xray-core |
| Shadowsocks — plain, AEAD + 2022 ciphers | xray-core |
| Shadowsocks + obfs-local / simple-obfs | sing-box |
| Shadowsocks + v2ray-plugin | sing-box |
| Hysteria2 | sing-box |
| TUIC | sing-box |

Only one core runs at a time. Both use the **same** WireGuard keys/port, so the
single UniFi VPN Client entry works no matter which core is active.

> **Note:** xray binds the WireGuard port on loopback (`127.0.0.1:51821`);
> sing-box binds it on all interfaces (it has no listen-address option). This is
> still secure — WireGuard only ever answers the one configured peer key.

## Usage

Run `proxy` for the interactive menu, or use the direct commands:

| Command | Description |
|---|---|
| `proxy` | Main menu |
| `proxy status` | Engine, configured server, and listener status |
| `proxy ping [...]` | Test the link — `...` = `get`·`head`·`tcp`·`icmp` (default `get`) |
| `proxy start` · `stop` · `restart` | Service controls |
| `proxy logs [args]` | Service logs (passed to `journalctl`) |
| `proxy help` | Show help |
| `proxy update` | Updates engine binaries (xray + sing-box) and geo files |

The menu covers: import/replace link, UniFi WireGuard config,
regenerate keys, change port/MTU/DNS, ping test + protocol, enable/disable
autostart, update cores, update geo files, and uninstall.

## Notes

- **SSH-only management:** there is no web UI and no LAN-facing management port —
  manage it over SSH with `proxy`.
- **Loopback endpoint:** the UniFi WireGuard VPN Client points at `127.0.0.1:51821`.
  If the UI rejects a loopback endpoint, set `WG_LISTEN` in
  `/data/proxy-unifi/etc/settings.env` to a routable local address and re-import.
- **MTU** defaults to `1340` (Change via main menu if large transfers stall);
  **DNS** defaults to `8.8.8.8`.

## Persistence

Everything lives under **`/data/proxy-unifi`**, which UniFi OS preserves across
reboots and most firmware upgrades. A boot hook at `/data/on_boot.d/15-proxy-unifi.sh`
re-creates the `proxy` command and the systemd service (with the correct engine) on
every boot.

## Update

To update client functionality (pull files from GitHub), simply run the script again:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/main/install.sh | sh
```

Re-running the installer only overwrites `bin/` (script + binaries) and the `systemd` unit. Your WireGuard keys, added proxy link and client settings (DNS, MTU) persist — the UniFi WireGuard client keeps working without any changes required.

## Uninstall

```sh
proxy            # menu → Uninstall
# or:
rm -rf /data/proxy-unifi   # also wipe keys/config
```
Then delete the WireGuard VPN Client in the UniFi UI.

## Credits

Persistence model built on [unifi-utilities/unifi-common](https://github.com/unifi-utilities/unifi-common).
Powered by [XTLS/Xray-core](https://github.com/XTLS/Xray-core) and
[SagerNet/sing-box](https://github.com/SagerNet/sing-box).

## License

MIT
