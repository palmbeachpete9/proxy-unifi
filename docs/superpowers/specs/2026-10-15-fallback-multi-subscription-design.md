# Multiple subscriptions and a fallback pool

Date: 2026-10-15. Branch: `experimental` (it carries the live-tunnel check the
watchdog uses; `main` gets this when experimental is merged into it).

## Goal

1. Keep several subscriptions at once, all refreshed in the background, and
   pick the active node by choosing a subscription first, then a node.
2. A fallback pool: an ordered list of nodes, from any of the subscriptions.
   When the active node goes offline, the tunnel moves to the next node in
   priority order instead of going down, and (optionally) returns to a
   higher-priority node once it is back.

Decided with the user:

- Switching is done by a proxy-unifi watchdog that re-applies a node (a core
  restart), not by Xray's own balancer. It works for every node type and keeps
  an exact priority order; a switch resets open connections.
- Pool nodes come from subscriptions only (not hand-pasted links, JSON files
  or AmneziaWG profiles).
- Each subscription may have its own User-Agent; the HWID stays one per gateway.
- Choosing a node by hand while fallback is on turns fallback off (after a
  prompt in the menu); the pool is kept.

Out of scope: per-subscription refresh intervals, notifications, seamless
(restart-free) switching, load balancing across pool nodes.

## 1. Multiple subscriptions

### Storage

```
$SUB_DIR/                      (700)
  hwid                         unchanged, shared by all subscriptions
  selected                     id of the active node (unchanged meaning)
  selected.json                selection metadata + "sub": "<subscription id>"
  <id>/                        (700) one per subscription; id = 1, 2, 3 ...
    url.txt                    (600) the URL
    catalog.json               (600) parsed nodes (unchanged format)
    name                       (600) display name
    ua                         (600) optional User-Agent override
    status                     (600) "ok <epoch>" or "fail <epoch> <reason>"
```

- A subscription id is a positive integer, stable for its lifetime: a new
  subscription gets the highest existing id + 1, and removing one never
  renumbers the others. Menus and the CLI show and accept this id.
- At most 20 subscriptions.
- The name defaults to the provider's `profile-title` header when it sends
  one (plain or `base64:`-encoded), else the URL's host. Names are sanitized like every other provider string before
  display, and limited to 36 display characters.
- `SUB_USER_AGENT` in settings becomes the default for subscriptions without
  `ua`.

### Migration

Any command that reads subscriptions first migrates the old layout, once:
if `$SUB_DIR/url.txt` exists, `url.txt` and `catalog.json` move into
`$SUB_DIR/1/`, the name is derived as above, and `selected.json` (if present)
gains `"sub": "1"`. The move runs inside a transaction like other state
changes. The active node and tunnel are untouched.

### Refresh

- The refresh timer runs `sub-refresh-auto`, which refreshes every
  subscription in id order. A failing subscription records `fail` in its
  `status`, keeps its old catalog, and does not stop the others.
- Downloads run without the CLI lock (today the whole refresh holds it, up to
  30 s per provider). The lock is taken only to install each new catalog and
  re-match, so a slow provider never delays the watchdog or the menu.
- After a subscription's catalog is replaced:
  - if the active selection belongs to it, it is re-matched exactly as today
    (`mksub match`), including re-applying a changed node;
  - every fallback pool entry from it is re-matched the same way; an entry
    with no match is marked `missing`, one that matches again is un-marked.
  - Re-applying a changed active node here does not turn fallback off.
- The timer unit's condition becomes "any `$SUB_DIR/*/url.txt` exists".
- One global refresh interval (`SUB_REFRESH_HOURS`, unchanged).

### Choosing the active node

Choose a subscription, then a node from its list. With only one subscription
the subscription step is skipped. Selecting records `selected` and
`selected.json` (with `sub`) after a successful import, as today.

Node lists mark the active node `*`, unsupported nodes `x`, and pool members
with their priority (`1`..`10`) in an extra column.

### Subscriptions menu (main menu 2)

```
Subscriptions:
  1. Provider A     24 nodes   refreshed 12:00
  2. overgrow       18 nodes   refresh failed 11:58 (timeout)
Active node: [Provider A] 🇩🇪 Germany (vless)

 1. Choose active node
 2. Show a subscription's nodes
 3. Add a subscription
 4. Remove a subscription
 5. Rename a subscription
 6. Refresh all now
 7. Refresh interval
 8. User-Agent
 0. Back
```

- "User-Agent" asks for a subscription id or `d` for the default, then the
  value; an empty value for a subscription clears its override.
- Removing a subscription asks for confirmation. If the active node came from
  it, the tunnel keeps running on that node but it is no longer tied to a
  subscription (as with a manual import). Its pool entries are removed.

### CLI

```
proxy sub add URL [NAME]
proxy sub list [SUB]          no SUB: subscriptions; SUB: its nodes
proxy sub select SUB NODE
proxy sub select NODE         only while exactly one subscription exists
proxy sub refresh [SUB]       no SUB: all
proxy sub remove SUB
proxy sub rename SUB NAME
proxy sub ua SUB|default UA   empty UA with SUB clears the override
proxy sub interval HOURS
```

## 2. The fallback pool

### Storage and settings

`$ETC_DIR/fallback.json` (600):

```json
{"schema": 1, "nodes": [
  {"sub": "1", "meta": {...selection metadata...}, "missing": false}
]}
```

- 2 to 10 entries; list order is priority (first = 1). No duplicate
  (sub, node id) pairs; only nodes the catalog marks supported.
- The file is validated on every load (schema, numeric sub ids, metadata
  shape); a malformed file is reported and fallback stays off.

Settings (`settings.env`), each validated on load like existing keys:

| Key           | Values   | Default | Meaning                                         |
|---------------|----------|---------|-------------------------------------------------|
| `FALLBACK`    | on, off  | off     | watchdog active                                 |
| `FB_INTERVAL` | 5-600    | 20      | seconds between checks                          |
| `FB_DOWN`     | 1-20     | 3       | failed checks in a row before a node is offline |
| `FB_UP`       | 1-50     | 5       | good checks in a row before a node is online    |
| `FB_TIMEOUT`  | 2-30     | 5       | seconds per check                               |
| `FB_RETURN`   | on, off  | on      | return to a higher-priority node when online    |

The check URL is the existing `PING_URL`.

Timing presets:

| Preset   | Interval | Offline after | Online after |
|----------|----------|---------------|--------------|
| Fast     | 10 s     | 3             | 3            |
| Balanced | 20 s     | 3             | 5            |
| Relaxed  | 60 s     | 3             | 5            |

### Wizard (fallback menu 1)

1. "How many nodes in the pool? (2-10)"
2. For each priority 1..N: choose a subscription (skipped if only one), then a
   node. Lists show nodes already picked with their priority; picking a
   duplicate or unsupported node is refused and asked again.
3. Show the pool. "New order (e.g. 1 3 2), Enter to keep:" accepts a
   permutation of 1..N.
4. Timing: Fast, Balanced (default), Relaxed, or Custom (asks interval,
   offline-after, online-after and timeout, each with its range).
5. "Return to a higher-priority node when it is back online? [Y/n]"
6. "Turn fallback on now? [Y/n]" (see "Turning fallback on").

Nothing is saved until step 6 is answered; Ctrl-C or an empty answer at
step 1 leaves the old pool and settings as they were.

### Fallback menu (main menu 3)

```
Fallback: ON — balanced (every 20 s, offline after 3 fails, online after 5 OK), returns to higher priority
  1. [Provider A] 🇩🇪 Germany   vless     online   132 ms   <- active
  2. [overgrow]   🇳🇱 NL-2      json      online    88 ms
  3. [Provider A] 🇫🇮 Finland   trojan    offline since 12:03 (timeout)
Last switch: 12:04  #3 -> #1 (back online)

 1. Set up a new pool (wizard)
 2. Add a node
 3. Remove a node
 4. Change priority order
 5. Timing
 6. Return to higher priority: on/off
 7. Test all pool nodes now
 8. Turn fallback on/off
 0. Back
```

- Per-node state comes from the watchdog's state file; before any check it
  shows "not checked yet". Missing entries show "missing from subscription".
- "Add a node" asks subscription, node, then position (Enter = last).
- Any change while fallback is on takes effect at the next check.

### Main menu

A new item 3 "Fallback pool"; the items after it move down by one:

```
 0. Exit menu
 1. Manage a single-server proxy link
 2. Subscriptions
 3. Fallback pool
 4. Manage AmneziaWG profiles
 5. Import an Xray JSON profile (from a file)
 6. Show current server & config
 7. Show UniFi WireGuard VPN Client config
 8. Regenerate WireGuard keys
 9. Change WireGuard settings
10. Ping test
11. Change test algorithm
12. Start
13. Stop
14. Restart
15. Check status
16. View logs
17. Enable autostart
18. Disable autostart
19. Update proxy cores
20. Update geo files
21. Version info
22. Uninstall
```

The section separators stay as today; the selection prompt becomes `[0-22]`.
The status block under the menu gains a line
`Fallback:   on, #1 of 3 active` (or `off`).

### CLI

```
proxy fallback status
proxy fallback on | off
proxy fallback add SUB NODE [POSITION]
proxy fallback remove POSITION
proxy fallback order P1 P2 ...            a permutation of the current positions
proxy fallback timing INTERVAL DOWN UP [TIMEOUT]
proxy fallback return on | off
proxy fallback test
```

`proxy status` gains `fallback: on, active #2 of 3 ([overgrow] NL-2), last
switch 12:04` (or `fallback: off`).

### Manual choices while fallback is on

Choosing a node by hand, importing a link, a JSON profile or an AmneziaWG
profile, in the menu, first asks: "Fallback is on; choosing a node yourself
turns it off. Continue? [y/N]". On the CLI it turns fallback off and says so.
The pool is kept. Switches made by the watchdog do not turn it off.

Removing pool entries until fewer than 2 remain, or removing a subscription
that leaves fewer than 2, turns fallback off and says so.

## 3. The watchdog

### Unit

`proxy-unifi-fallback.timer` (`OnBootSec=60s`, `OnUnitActiveSec=<FB_INTERVAL>s`,
`AccuracySec=1s`) starts the oneshot `proxy-unifi-fallback.service`, which runs
`proxy-unifi fallback-check` as root with `Nice=10`. The timer is enabled
while `FALLBACK=on` and disabled otherwise; changing `FB_INTERVAL` rewrites it.
Uninstall removes both units; an update keeps the pool, settings and timer.

The service sets `LogLevelMax=notice`, so the journal does not get a
"started/finished" pair every interval; switches and "no pool node online"
are logged at notice level and stay visible.

A run does nothing when:

- fallback is off or the pool has fewer than 2 usable entries;
- the main service is stopped (`inactive`: the user stopped it). A service
  that is failing or restarting is still watched; without a healthy core the
  test core decides (see "A check");
- the CLI lock is held by someone else: the run tries it once and skips
  instead of waiting.

### State

`/run/proxy-unifi/fallback.state` (600, JSON, in RAM like the kernel ingress
state), rewritten atomically by each run, so the gateway's flash is not
written every interval:

- per node id: consecutive fails, consecutive successes, last result time,
  last latency in ms, last error text;
- the rotation position for return checks (see "A run");
- whether the live tunnel check is failing while the node answers.

The last switch (time, from-position, to-position, reason) is written to
`$ROOT/fallback.last` only when a switch happens, so it survives a reboot.
A missing or malformed state file starts from empty counters after a reboot
or corruption.

The decisions (update counters, pick a switch target) are a pure function in
a new `mkfallback.py`: state plus check results in, new state plus at most
one action out. The shell runs the checks and applies the action. This keeps
the logic testable without a network or a gateway.

### A check

An HTTP request to `PING_URL` through the node, limited to `FB_TIMEOUT`. Any
HTTP response counts as success (it came back through the node); no response
is a failure, with curl's error recorded.

- Active node: through the live tunnel (the UniFi VPN client interface, the
  same path as `proxy ping`) when the service is healthy and that interface
  exists. If that fails, the node is checked once more through a test core;
  only when both fail does the check count as failed. Without the interface,
  or while the core is not healthy, the test core alone decides.
  When the live check fails but the node answers through the test core, the
  problem is between UniFi and the core (not the node), so nothing switches;
  the state records it and the fallback menu and `proxy status` show "tunnel
  check failing, node answers" so it is not silent.
- Any other node: through a test core built from that node's catalog entry
  (the `proxy ping` test core, generalized to take a node instead of the
  active configuration).

### A run

1. If the active node is not a pool entry (for example right after turning
   fallback on), switch to the highest-priority entry that passes one check
   now. Done.
2. Check the active node and update its counters.
3. If the active node has `FB_DOWN` failures in a row, it is offline: check
   the other entries in priority order (skipping missing ones) and switch to
   the first that passes one check. If none passes, stay, record "no pool node
   online", and keep checking on later runs.
4. Else, if `FB_RETURN=on` and the active node is not priority 1, check ONE
   higher-priority entry, rotating through them from the highest. Each entry
   keeps its own streak of good checks. Switch to an entry once its streak
   reaches `FB_UP`, unless a higher-priority entry has a streak of at least 1
   (it is recovering too); then wait for that one, so a provider-wide outage
   that ends does not cause two switches in a row.

Cost bound: in steady state a run is one request through the live tunnel.
Return checks add at most one test core per run. Only an outage (step 3) or
turning fallback on checks several entries in one run. A return to an entry
`k` places above the active one takes about `FB_UP` x `k` runs.

A switch applies the node through the same validated path as choosing it by
hand (build, `-test` with the real core, apply, record `selected`), with the
fallback flag so it does not turn fallback off. If applying fails, that entry
counts as offline for this run and step 3 continues with the next one. Each
switch is logged to the journal with its reason (`proxy logs` shows it) and
stored as the last switch.

### Turning fallback on

Checks every pool entry once through a test core and prints the results.
Then it saves `FALLBACK=on`, enables the timer, and runs one watchdog run
immediately (step 1 applies the highest-priority online node). If no entry
passes, it still turns on, keeps the current node, and says so.

"Test all pool nodes now" is the same check without the switch; it updates
each entry's last result and latency but not the streak counters. It needs
no lock.

## Error handling and security

- All new files are root-only (600 files, 700 directories) under the existing
  trees; URLs never appear in argv (mksub keeps reading them from files).
- Provider-controlled names and labels are sanitized before display.
- Subscription ids, positions and settings are validated as integers in range
  before use; `fallback.json` and `fallback.state` are parsed by Python with
  shape checks.
- Test cores keep running under the service account with safeexec's limits.
  No new listeners on the gateway.
- Every state change goes through the existing transaction and lock, so an
  interrupted switch or menu action rolls back.

## Testing

Unit tests (parser tier) of `mkfallback.py`'s decision function with
scripted results: offline after `FB_DOWN` failures, first passing candidate
chosen, staying when all fail, return only after `FB_UP`, waiting for a
recovering higher entry, rotation, `FB_RETURN=off`, live-fails-node-answers
not switching, and a malformed state starting clean.

Sandboxed lifecycle tests (mock systemctl, as today):

- migration of the single-subscription layout into `1/`, with the selection
  kept;
- add, list, select, rename and remove subscriptions; nodes from two
  subscriptions; one-argument `sub select` with a single subscription;
- refresh of all subscriptions with one failing; pool entries marked missing
  and un-marked;
- the wizard driven by piped menu input, including reordering and
  cancellation;
- the shell wiring of the watchdog with a stubbed check: a switch after
  `FB_DOWN` failures applies the node and records the last switch, a run is
  skipped while the lock is held, nothing runs while the service is stopped,
  and fallback turns off on a manual select but not on a refresh re-apply;
- a refresh does not hold the lock while downloading.

Real-core test: a test core built for a pool node that is not active answers
a check.

Every new check gets a negative control: it must fail without the change it
covers.
