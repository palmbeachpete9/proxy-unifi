<div align="right">

**🇬🇧 English** · [🇷🇺 Русский](README.ru.md)

</div>

# proxy-unifi

Run a headless proxy client on your UniFi Cloud Gateway and steer traffic into it
from the native UniFi UI (**Policy Engine → Policy Table**).

proxy-unifi ships **three cores** — [xray-core](https://github.com/XTLS/Xray-core),
[sing-box](https://github.com/SagerNet/sing-box), and a pinned userspace
[AmneziaWG-enabled core](https://github.com/amnezia-vpn/amnezia-box). It selects the
right core for imported links and saved AWG profiles. All three terminate the
**same** WireGuard tunnel, so the UniFi UI only ever needs **one** VPN Client entry.

UniFi gateways have no built-in outbound proxy support and can't dial any proxy protocol server's links (`vless://`, `hysteria2://`, ...).
proxy-unifi bridges that gap **without** altering UniFi OS packages: it presents the proxy to
UniFi as a natively supported **WireGuard VPN Client**, which the controller already knows
how to route. It is headless, SSH-only (no web UI), and persists across reboots and
firmware upgrades via [unifi-common](https://github.com/unifi-utilities/unifi-common).

## Getting started

SSH into your gateway as `root` and run:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/experimental/install.sh | sh
```

After the script finishes the installation, run `proxy` for the management menu:

1. **Import a connection** — choose a single-server share link (`vless://`,
   `vmess://`, `trojan://`, `ss://`, `hysteria2://`, or `tuic://`), an HTTPS
   subscription, an Xray JSON profile, or an AmneziaWG profile from the
   corresponding menu action.

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
  │        xray-core  OR  sing-box  OR  AmneziaWG core (WireGuard inbound)     │
  │                              │  terminates the tunnel, then routes         │
  │                              ▼  selected proxy / AWG outbound              │
  └──────────────────────────────┼─────────────────────────────────────────────┘
                                 ▼  out via WAN
                            your proxy server ──▶ Internet
```

The gateway's own WireGuard VPN Client does a real WireGuard handshake with the
active core over loopback. The core terminates that inner tunnel and forwards
everything through the selected proxy or AWG outbound. Proxy-link modes need no
remote WireGuard server; AWG mode connects to the remote AmneziaWG peer in the
selected profile.

## Kernel WireGuard ingress (Xray and sing-box)

For Xray and sing-box links and Xray JSON profiles, the gateway's kernel
terminates the UniFi VPN Client's WireGuard by default; the core no longer does it. Xray's own WireGuard
decrypts in userspace, one packet at a time: on a UCG-Ultra that held the tunnel
near 35 Mbit/s while the proxy outbound alone reached ~350 Mbit/s. On the same
gateway, the kernel path measured ~180 Mbit/s at half the CPU.

The kernel WireGuard device uses the same port, keys and MTU, so nothing changes
in the UniFi VPN Client. It lives in a private network namespace; decrypted
traffic leaves through a veth pair, and TPROXY hands every TCP and UDP connection
to the core, which routes it exactly as before (same inbound tag; Xray keeps its
sniffing). sing-box runs a copy of its config with a `tproxy` inbound in place of
its WireGuard endpoint. AmneziaWG profiles keep their own WireGuard.

- **Fallback:** if any setup step fails, or the core does not come up on this
  path (a failed health check after a restart, or three failures in a row), the
  service runs the core's own WireGuard instead. **Check status** shows the path in use
  and why; **Restart** tries the kernel path again.
- **Switch:** `proxy` → WireGuard settings → Ingress (`kernel` or `userspace`).
- **Firewall rewrites:** if the UniFi controller rewrites the firewall or routing
  rules, the guard timer restores them within 30 seconds.
- **UDP replies from ports the gateway listens on:** the core answers transparent UDP
  from the remote address and port, which fails for ports the gateway itself holds
  (UniFi's STUN on 3478, for example). Those replies are lost; **Check status**
  lists the ports. TCP is unaffected.
- **Privilege:** only in this mode, the core gets `CAP_NET_RAW`, which
  transparent sockets require, and `CAP_NET_BIND_SERVICE`, so it can answer UDP
  from remote ports below 1024 (DNS, QUIC).
- **Private addresses:** as with Xray's WireGuard inbound, direct (freedom) routes
  refuse private and loopback targets for tunnel clients. sing-box configs have
  no direct route: everything goes to the proxy.
- **LAN route (on by default):** in the menu under WireGuard settings. LAN traffic that a Policy Table route sends to this
  VPN Client is routed into a second proxy-unifi veth pair instead of being
  encrypted, and
  reaches the core without both WireGuard passes, in full-size packets. UniFi still processes it first: its
  marking, NAT (DNS interception, hotspot), its other routing tables, and its
  FORWARD firewall. The firewall sees `pu-lr0` instead of `wgclt` as the egress
  interface, so rules written for the VPN zone's interface do not match; rules by
  address or by LAN interface still do. Only replies to connections the gateway
  forwarded into the pair come back from it, and UniFi's FORWARD chain (its
  threat blocklists included) decides on them as on replies from `wgclt`. Traffic the gateway itself sends
  through the VPN client (such as UniFi's DNS forwarder for it) takes the pair
  too, and only its replies reach the gateway. **Check status** shows `lan route` with how many TCP connections
  UniFi's firewall let through; it reports `blocked` if strict reverse-path
  filtering (`rp_filter=1`) rules the mode out.
- **Measure:** the third line of the **Speed test** tests the full tunnel through the
  gateway's own VPN Client.
- **Installing an older version:** versions without this mode cannot remove it,
  and it would keep the WireGuard port. Run `systemctl stop proxy-unifi` first
  (or reboot after installing).

## Compatibility

This package is compatible with UniFi OS 4.x or newer and requires the gateway's
system Python 3.9 or newer. The minimum was verified against the signed UDM-Pro
4.0.6 and 5.1.19 firmware images; installation fails before making changes if an
older interpreter is found. It is known to work on the following UniFi devices:

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
| Shadowsocks — plain / classic AEAD | xray-core |
| Shadowsocks 2022 — standards-compliant fixed keys | sing-box |
| Shadowsocks 2022 AES-128 — Xray-compatible 32-byte key | xray-core |
| Shadowsocks + obfs-local / simple-obfs | sing-box |
| Shadowsocks + v2ray-plugin | sing-box |
| Hysteria2 | sing-box |
| TUIC | sing-box |
| AmneziaWG 1.5 / 2.0 / 3.0 / 3.1 configuration | AmneziaWG core |

Only one core runs at a time. All three use the **same** WireGuard keys/port, so the
single UniFi VPN Client entry works no matter which core is active.

> **Note:** xray binds the WireGuard port on loopback (`127.0.0.1:51821`).
> sing-box and the AmneziaWG core have no listen-address option for their inner
> WireGuard endpoint, so they bind all interfaces — but
> proxy-unifi adds an `iptables`/`ip6tables` rule that drops every non-loopback
> packet to that port, making it unreachable from the LAN/WAN. Defence in depth:
> the port is firewalled to loopback **and** WireGuard only ever answers the one
> configured peer key.

Common share-link extras are honoured where the core supports them: `tfo` /
`fastopen` (TCP Fast Open; not used by QUIC-based Hysteria2 and TUIC), Hysteria2
port hopping (`mport`, `hop-interval`, or a port list such as `host:443,20000-30000`),
`upmbps` / `downmbps`, `obfs=none`, TUIC `disable_sni` and Shadowsocks `uot`.
A `fp` fingerprint on Hysteria2 or TUIC is ignored: sing-box cannot apply it over
QUIC. Options that would change security (for example `insecure=1` or Hysteria2
`pinSHA256`) are still refused, and the subscription list marks such nodes
unsupported with the reason instead of offering them.

## Shadowsocks 2022

SS2022 is imported through the existing single-link and subscription workflows;
there is no separate profile menu or second UniFi VPN Client entry. The catalog
labels these rows as `ss2022`, and **Status** reports `Shadowsocks 2022` when one
is active.

Supported standardized methods:

- `2022-blake3-aes-128-gcm` — 16-byte base64 PSK
- `2022-blake3-aes-256-gcm` — 32-byte base64 PSK
- `2022-blake3-chacha20-poly1305` — 32-byte base64 PSK

Single-user keys are accepted for all three methods. Colon-delimited extensible
identity chains (`relay-key:server-key:user-key`, up to 16 keys) are accepted for
the two AES-GCM methods; this multi-user construction does not support ChaCha20.
Key syntax and decoded length are checked before a core is downloaded or the
active tunnel is changed. Standards-compliant links run through sing-box. The
older Xray-specific 32-byte AES-128 key form remains supported through xray-core
so existing links do not regress; subscription rows show a compatibility warning
for that form.

SS2022 replay protection requires reasonably synchronized client/server clocks.
Multiplexing and UDP-over-TCP are not silently enabled because the provider server
must explicitly support them; forcing either option would break ordinary SS2022
servers. Native TCP and UDP forwarding remain enabled by the core defaults.

## Subscriptions and JSON pools

The Subscriptions menu keeps up to 20 HTTPS subscriptions at once, each with its
own number, name (the provider's title, or the URL's host; you can rename it)
and, if a provider needs one, its own User-Agent. To choose the active node you
pick the subscription first, then the node (with a single subscription the first
step is skipped). Subscriptions contain plain-text or base64-encoded share links,
plus Xray JSON client profiles with routing balancers.
Node names remain Unicode, including Cyrillic and emoji. Selecting a node applies
it through the same validated import path as a single share link.
Clash YAML, SIP008, sing-box JSON, WireGuard, AnyTLS, Naive, and SSH subscription
formats are not currently parsed.

Each installation creates a random persistent device UUID and sends it as
`x-hwid` to the subscription origin. The header is not forwarded across a
cross-origin redirect. The default User-Agent is `Happ/2.0` and can be
changed from the Subscriptions menu, for all subscriptions or for one. A
persistent systemd timer refreshes every subscription in the background at the
configured interval; one failing provider keeps its nodes and does not stop the
others, and downloads never block the menu or the fallback watchdog. After a
refresh the selected node is found again by its exact content; if that changed,
by its name, protocol and server. When the provider moved it to a new server, a
node with the same name and protocol takes its place, and among several such
nodes the one at the same list position wins. If none fits, the active tunnel is
kept unchanged.

Provider JSON is not executed byte-for-byte. proxy-unifi validates target
addresses, routing references, balancers, observatories, DNS, and resource
limits; removes provider listeners and control surfaces; and inserts its own
WireGuard inbound. Provider outbounds, routing rules, balancer strategies,
health probes, and failover tags otherwise remain intact. Profiles that cannot
be projected safely are rejected before xray-core is started.

Routing rules that depend on source/user identity or the provider's local entry
address or port are rejected when they apply to the retained inbound. This
includes `source`, `sourceIP`, `sourcePort`, `user`, `localIP` and `localPort`.
Rules restricted to removed inbounds are discarded. Routing webhooks are not
supported: they can send connection metadata through a separate HTTP client,
outside the profile's configured outbounds.

## Fallback pool

Main menu 3 sets up a pool of 2-10 nodes, from any of your subscriptions, in
priority order. While fallback is on, a watchdog checks the active node through
the tunnel at a set interval. When it fails a set number of checks in a row it
counts as offline, and the tunnel moves to the next node in priority order that
answers right now. With "return to higher priority" on, the tunnel goes back to a
better node once it has passed a set number of checks in a row. If no pool node
answers (for example while the internet connection is down), it checks one node
per interval instead of all of them, to spare the gateway's CPU.

The wizard asks for the number of nodes, each node (subscription, then node),
their order, and the timing:

| Preset | Check every | Offline after | Back online after |
|---|---|---|---|
| Fast | 10 s | 3 failed checks (~30 s) | 3 good checks |
| Balanced (default) | 20 s | 3 failed checks (~1 min) | 5 good checks |
| Relaxed | 60 s | 3 failed checks (~3 min) | 5 good checks |

Custom timing sets each value (and the seconds per check) yourself. A switch
applies the node like choosing it by hand, so open connections are reset; with
nodes on kernel ingress that takes about 1-3 s, while a node on its core's own
WireGuard makes the UniFi VPN Client reconnect, up to ~15 s. Choosing a
node yourself (a link, a subscription node, a JSON or AmneziaWG profile) asks
first and then turns fallback off; the pool is kept. If the problem is between
UniFi and the core rather than the node, the watchdog does not switch and
**Check status** says so. Every switch is logged (**View logs**) and shown as "Last
switch" in the menu.

## AmneziaWG profiles

The second menu block manages standalone AmneziaWG 1.5, 2.0, 3.0, and 3.1 client
configurations. Choose **Create a new profile**, enter a display name, paste the
configuration into the editor, and save (in `nano`: `Ctrl+X`, `Y`, `Enter`). Saved profiles
can be listed, selected and activated, edited, renamed, or deleted; `*` marks the
active profile. Cyrillic, CJK text, and emoji are preserved, with a display-only
fallback for limited UniFi SSH terminals. The editor is `nano` when the gateway
has it, otherwise `vi`, which UniFi OS ships; the menu says how to save in it.

AWG runs entirely in userspace. It does not create a kernel interface, change
gateway policy routes, require `/dev/net/tun`, or replace the persistent UniFi
WireGuard client. Selecting an AWG profile therefore needs no change in the UniFi
UI. The AWG core is downloaded on first activation and is pinned to the project
release and an architecture-specific SHA-256 digest embedded in proxy-unifi.

The importer accepts AWG obfuscation fields `Jc`, `Jmin`, `Jmax`, `S1-S4`,
`H1-H4`, and `I1-I5`, including AWG 2.0 header ranges and CPS packet templates,
plus the AWG 3.0 fields `HeaderProtectionKey`, `ContentPaddingAddition`,
`RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, and
`MaxHandshakeAttempts`, and the AWG 3.1 flags `RandomTrailers` and `DisableCookies`.
AWG 3.x settings must match the server. A server with `HeaderProtectionKey` accepts
only AWG 3.x clients, and header protection requires `S1-S4` to be at least 12.
A `PersistentKeepalive` range such as `20-30` uses its lower bound, and the
kernel-module peer switch `AdvancedSecurity = on` is accepted.
Multiple peers, IPv4/IPv6 addresses, preshared keys, and keepalives are supported.
Unsafe `wg-quick` hooks and routing commands are rejected. A profile's client-side
`ListenPort` is retained in its saved source but omitted from the outbound runtime
to avoid opening an unnecessary UDP listener. Profile DNS is shown for reference;
the DNS advertised to UniFi remains the global value under **WireGuard settings**.

## Usage

Run `proxy`: everything is in its menu.

- **Connections:** a single link, subscriptions, the fallback pool, AmneziaWG
  profiles, and Xray JSON profiles; the current server and config.
- **UniFi side:** the WireGuard VPN Client config, new keys, and the WireGuard
  settings (port, MTU, DNS, ingress, LAN route, keepalive, log level).
- **Tests:** the ping test and its protocol, and the **Speed test**: the WAN
  alone, the active outbound alone (no WireGuard), and the full tunnel through
  the gateway's VPN Client, with gateway and core CPU use.
- **Service:** start, stop, restart, status, logs, and autostart.
- **Updates:** proxy-unifi, the proxy cores, the geo files, automatic updates,
  and version info (see [Update](#update)). Then **Uninstall**.

## Notes

- **SSH-only management:** there is no web UI and no LAN-facing management port —
  manage it over SSH with `proxy`.
- **Loopback endpoint:** the UniFi WireGuard VPN Client points at `127.0.0.1:51821`.
  A custom `WG_LISTEN` address is supported for xray-core links and JSON pools.
  sing-box and the AmneziaWG core cannot bind this inbound to a chosen address,
  so proxy-unifi requires loopback configuration for those cores and fails closed if its firewall guard
  cannot be installed.
- **MTU** defaults to `1340` (Change via main menu if large transfers stall);
  **DNS** defaults to `8.8.8.8`.
- **Routes by domain:** UniFi matches a domain through the gateway's own DNS, so
  such a route only catches devices that use the gateway as their DNS server
  (not a hard-coded `8.8.8.8`) with the browser's Secure DNS / DNS over HTTPS off.
  After changing a route, test in a fresh private window, as cached DNS answers
  and open connections keep their old path.
- **Privilege separation:** proxy cores run as the dedicated `proxy-unifi` user
  in a hardened systemd service. Imports and updates are validated before an
  atomic state change; failed starts restore the prior working state.
- **Core integrity:** xray-core is never installed below the upstream security
  fix in `v26.7.11`; that release and the project-owned AWG core use embedded
  per-architecture hashes. Newer Xray releases must match GitHub's asset digest
  and Xray's sidecar checksum. sing-box is pinned to `v1.13.21` (1.14.3 does not
  open its WireGuard port on a Dream Router 7) and must match GitHub's digest.

## Persistence

Everything lives under **`/data/proxy-unifi`**, which UniFi OS preserves across
reboots and most firmware upgrades. A boot hook at `/data/on_boot.d/15-proxy-unifi.sh`
re-creates the `proxy` command and the systemd service (with the correct engine) on
every boot.

## Update

The menu's **Updates** entry updates proxy-unifi, the proxy cores (Xray,
sing-box, AmneziaWG), and the geo files. **Update proxy-unifi now** installs the
newest version of the branch you installed (`main` or `experimental`) whose
GitHub tests passed; each update does nothing when you already have it.

**Automatic updates** are off until you turn them on there. Once on, the gateway
checks daily around 04:00: it installs a new proxy-unifi version 24 hours after
its tests passed (time to catch a bad version before it reaches routers), then
updates the cores. An update restarts the tunnel once, for a few seconds; a day
with nothing new restarts nothing. **Check status** shows the version you run
and how the last automatic update ended; **View logs** has the details.

Every update runs the installer of the version it installs: it checks the
gateway, backs up the scripts, cores and services, and restores them all if any
step, the tunnel's health check included, fails. Running the install command
again does the same by hand:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/proxy-unifi/experimental/install.sh | sh
```

Remote installer files are pinned to one immutable GitHub commit for each run.
Core archives and geo assets must pass their published SHA-256 checks before
activation, and failed core/service updates restore the previous files.

Re-running the installer only overwrites `bin/` (script + binaries) and the `systemd` unit. Your WireGuard keys, added proxy link, subscriptions, fallback pool, AmneziaWG profiles, and client settings (DNS, MTU) persist — the UniFi WireGuard client keeps working without any changes required.

## Uninstall

```sh
proxy uninstall   # stop services, remove units/guards, keep data
rm -rf /data/proxy-unifi   # optional: purge keys and configuration afterward
```
Then delete the WireGuard VPN Client in the UniFi UI.

## Credits

Persistence model built on [unifi-utilities/unifi-common](https://github.com/unifi-utilities/unifi-common).
Powered by [XTLS/Xray-core](https://github.com/XTLS/Xray-core),
[SagerNet/sing-box](https://github.com/SagerNet/sing-box),
[AmneziaVPN/amnezia-box](https://github.com/amnezia-vpn/amnezia-box), and
[AmneziaVPN/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go).

## License

MIT
