# Multiple Subscriptions and Fallback Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep several subscriptions (refreshed in the background, chosen subscription → node) and a 2–10 node fallback pool that a watchdog fails over in priority order.

**Architecture:** Subscriptions move from one `$SUB_DIR` to `$SUB_DIR/<id>/` folders managed by the POSIX-sh CLI. A new stdlib-only `src/mkfallback.py` owns the pool file and the watchdog's decisions; its `run` drives one watchdog run, calling back into the CLI for checks (`_fallback-probe`, no lock) and switches (`_fallback-apply`, under the CLI lock). A systemd timer fires `fallback-check` every `FB_INTERVAL` seconds.

**Tech Stack:** POSIX sh (dash/busybox-compatible), Python 3.9+ stdlib, systemd timers, Xray/sing-box test cores via `safeexec.py`.

**Spec:** `docs/superpowers/specs/2026-10-15-fallback-multi-subscription-design.md`

## Global Constraints

- Branch: `experimental`. Shell stays POSIX sh and passes `shellcheck -x`; Python runs on 3.9 (CI job "Python 3.9").
- Files under `$ETC_DIR` and `$SUB_DIR`: 600 files, 700 directories; URLs never in argv.
- Every persisted state change runs inside `txn_begin`/`txn_commit` under the CLI lock.
- Subscription ids: integers 1..999, at most 20 subscriptions; pool 2–10 entries.
- Settings: `FALLBACK` on|off (off), `FB_INTERVAL` 5–600 (20), `FB_DOWN` 1–20 (3), `FB_UP` 1–50 (5), `FB_TIMEOUT` 2–30 (5), `FB_RETURN` on|off (on).
- Presets: Fast 10/3/3, Balanced 20/3/5, Relaxed 60/3/5 (interval/offline-after/online-after), timeout 5.
- Runtime state `/run/proxy-unifi/fallback.state` (RAM); last switch `$ROOT/fallback.last` (written only on a switch).
- Menus: one item per line; main menu gains "3. Fallback pool" and becomes `[0-22]`.
- Decision vs. spec: the spec's `proxy sub ...` / `proxy fallback ...` direct commands are dropped. The CLI keeps the menu as the single full interface (as the usage text already says); `proxy status` gains the fallback line. Fewer entry points to keep correct; nothing in the user's request needs scripting.

## Review Focus

1. A pool entry whose subscription catalog is from an older schema or unreadable: the watchdog must treat it as unusable (skip), not crash the run.
2. The user stops the service while fallback is on: no run may start it again (restart_service would) — `fallback-check` exits before any check when the unit is `inactive`.
3. The user changes the pool or turns fallback off while a run is checking: `_fallback-apply` re-checks `FALLBACK=on` and the expected active node under the lock and refuses a stale switch.
4. A refresh changes the active node's id: the selection and the pool entry must stay linked (both re-matched by the same matcher), so the next run does not think the active node left the pool.
5. Menu input that is empty, non-numeric or out of range anywhere in the wizard: re-ask or cancel cleanly, never save a half-built pool.

Each line is pinned by a test in the owning task (Tasks 3, 6, 6, 4, 7 respectively).

---

### Task 1: mksub groundwork (title, pure matcher, extract by id, marks, summary)

**Files:**
- Modify: `src/mksub.py` (`_meta_from_headers`, `cmd_match`, `cmd_extract`, `cmd_render`, `main`; new `match_node`, `cmd_subs`)
- Test: `tests/run.sh` (parser tier, new `py_case`)

**Interfaces:**
- Produces: `mksub.match_node(cat, old_meta) -> (node, score) | None`; `extract --id ID` (alternative to `--index`); `render --pool FILE --sub ID` marks pool entries with their priority; `subs --dir SUB_DIR [--selected-file F]` prints one line per subscription: `ID<TAB>display line`.
- Catalog meta gains `"title"` (sanitized, ≤36 display chars) from the `profile-title` header (`base64:` prefix decoded).

- [ ] **Step 1: Write the failing test** (append to `parser_tests` in `tests/run.sh`, after the existing mksub cases)

```sh
    py_case "mksub: title, matcher, extract by id, pool marks, summary" "$SRC" <<'PY'
import base64, contextlib, io, json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
import mksub
links = "\n".join([
    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?security=tls&type=tcp#DE",
    "trojan://secret@b.example.com:443?security=tls#NL"]).encode()
title = "base64:" + base64.b64encode("Провайдер A".encode()).decode()
cat = mksub.process_body(links, {"profile-title": title})
assert cat["meta"]["title"] == "Провайдер A", cat["meta"]
assert mksub.process_body(links, {"profile-title": "Plain"})["meta"]["title"] == "Plain"
de, nl = cat["nodes"]
assert mksub.match_node(cat, mksub._selection_meta(nl))[0]["id"] == nl["id"]
moved = dict(mksub._selection_meta(de), id="0" * 64)
assert mksub.match_node(cat, moved)[0]["id"] == de["id"]
assert mksub.match_node(cat, dict(moved, label="gone", server="x:1")) is None
with tempfile.TemporaryDirectory() as tmp:
    sub = os.path.join(tmp, "1"); os.makedirs(sub)
    path = os.path.join(sub, "catalog.json"); json.dump(cat, open(path, "w"))
    meta, payload = os.path.join(tmp, "m"), os.path.join(tmp, "p")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        mksub.cmd_extract(type("A", (), dict(file=path, index=0, id=nl["id"],
                                              meta_file=meta, payload_file=payload))())
    assert out.getvalue().split("\t")[0] == nl["id"] and open(payload).read().startswith("trojan://")
    pool = os.path.join(tmp, "fallback.json")
    json.dump({"schema": 1, "nodes": [
        {"sub": "2", "meta": mksub._selection_meta(de), "missing": False},
        {"sub": "1", "meta": mksub._selection_meta(nl), "missing": False}]}, open(pool, "w"))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        mksub.cmd_render(type("A", (), dict(file=path, selected=de["id"], pool=pool, sub="1"))())
    rows = out.getvalue().splitlines()
    assert "[*]" in rows[0] and " 2 " not in rows[0][:12], rows   # DE active, pool entry is sub 2's
    assert rows[1].startswith("  2. [ ] 2"), rows                  # NL is pool priority 2
    open(os.path.join(sub, "url.txt"), "w").write("https://x.example/s")
    open(os.path.join(sub, "name"), "w").write("Provider A")
    open(os.path.join(sub, "status"), "w").write("fail 1760000000 timeout")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        mksub.cmd_subs(type("A", (), dict(dir=tmp))())
    line = out.getvalue().strip()
    assert line.startswith("1\t") and "Provider A" in line and "2 nodes" in line and "refresh failed" in line, line
PY
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash tests/run.sh 2>&1 | grep -A3 'mksub: title'`
Expected: `FAIL mksub: title, matcher, ...` with `KeyError: 'title'`.

- [ ] **Step 3: Implement**

In `_meta_from_headers`, after the `subscription-userinfo` block:

```python
        title = headers.get("profile-title")
        if title:
            title = str(title).strip()
            if title.lower().startswith("base64:"):
                try:
                    title = base64.b64decode(title[7:] + "=" * (-len(title[7:]) % 4)).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    title = ""
            title = clean(title, LABEL_MAX)
            if title:
                meta["title"] = title
```

Replace the scoring loop of `cmd_match` with a pure function and call it:

```python
def match_node(cat, old):
    """The catalog node a stored selection now refers to, as (node, score), or None.

    Exact content identity always wins. Otherwise require a unique strong match;
    ambiguity returns None so the caller leaves the tunnel unchanged."""
    best_score, best_node, best_count = -1, None, 0
    for nd in cat.get("nodes", []):
        if not nd.get("recognized"):
            continue
        if nd.get("id") == old.get("id"):
            return nd, 100
        meta = _selection_meta(nd)
        if meta["kind"] != old.get("kind") or meta["scheme"] != old.get("scheme"):
            continue
        score = 30
        if meta["label"] and meta["label"] == old.get("label"):
            score += 40
        if meta["server"] and meta["server"] == old.get("server"):
            score += 30
        if meta["n"] == old.get("n"):
            score += 5
        if score > best_score:
            best_score, best_node, best_count = score, nd, 1
        elif score == best_score:
            best_count += 1
    if best_score < 70 or best_count != 1:
        return None
    return best_node, best_score


def cmd_match(args):
    cat = _load(args.file)
    try:
        with open(args.selection_file, "r", encoding="utf-8") as fh:
            old = json.load(fh)
    except Exception as e:
        die("could not read selection metadata: %s" % e)
    if not isinstance(old, dict):
        die("selection metadata is malformed")
    old = _migrate_selection_scheme(old, getattr(args, "active_link_file", ""))
    found = match_node(cat, old)
    if found is None:
        sys.exit(1)
    nd, score = found
    if args.meta_file:
        _write_selection_meta(nd, args.meta_file)
    sys.stdout.write("%s\t%s\t%s\n" % (nd["n"], nd["id"], score))
```

In `cmd_extract`, find by id when given:

```python
    if getattr(args, "id", ""):
        nd = next((node for node in cat.get("nodes", []) if node.get("id") == args.id), None)
    else:
        nd = next((node for node in cat.get("nodes", []) if node.get("n") == args.index), None)
    if nd is None:
        die("no such node in subscription")
```

In `cmd_render`, add the pool column (priority or blank) after the mark:

```python
    marks = {}
    if getattr(args, "pool", "") and os.path.exists(args.pool):
        try:
            with open(args.pool, "r", encoding="utf-8") as fh:
                entries = json.load(fh).get("nodes", [])
            for pos, entry in enumerate(entries, 1):
                if entry.get("sub") == args.sub:
                    marks[entry["meta"]["id"]] = str(pos)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            marks = {}
    ...
        line = "%3d. [%s] %2s %-9s %-24s %s" % (
            nd.get("n", 0), mark, marks.get(nd.get("id"), ""), scheme, server, label)
```

New `cmd_subs` (local time via `time.strftime("%H:%M" if today else "%d %b")`):

```python
def cmd_subs(args):
    """One line per subscription folder: id<TAB>display line (sanitized)."""
    import time
    ids = sorted(int(d) for d in os.listdir(args.dir) if d.isdigit() and 1 <= int(d) <= 999
                 and os.path.isfile(os.path.join(args.dir, d, "url.txt")))
    def read(sid, name):
        try:
            with open(os.path.join(args.dir, str(sid), name), "r", encoding="utf-8") as fh:
                return fh.read(512).strip()
        except OSError:
            return ""
    def when(epoch):
        t = time.localtime(epoch)
        return time.strftime("%H:%M" if t[:3] == time.localtime()[:3] else "%d %b %H:%M", t)
    for sid in ids:
        name = clean(read(sid, "name"), LABEL_MAX) or "(unnamed)"
        try:
            nodes = len(_load(os.path.join(args.dir, str(sid), "catalog.json"))["nodes"])
            count = "%d nodes" % nodes
        except SystemExit:
            count = "not fetched"
        status = read(sid, "status").split(" ", 2)
        if status[0] == "ok" and len(status) > 1 and status[1].isdigit():
            state = "refreshed %s" % when(int(status[1]))
        elif status[0] == "fail" and len(status) > 1 and status[1].isdigit():
            state = "refresh failed %s (%s)" % (when(int(status[1])), clean(status[2] if len(status) > 2 else "", 40))
        else:
            state = ""
        sys.stdout.write("%d\t%3d. %-*s %-11s %s\n" % (sid, sid, LABEL_MAX, name, count, state))
```

`main()`: `extract.add_argument("--index", type=int, default=0)`, `extract.add_argument("--id", default="")`; `render` gains `--pool` and `--sub` (defaults `""`); register `subs` with `--dir` required. `_load` failures inside `cmd_subs` raise `SystemExit` from `die()`; catching it is intended. `die()` prints to stderr — redirect stderr in the shell caller.

- [ ] **Step 4: Run tests**

Run: `bash tests/run.sh 2>&1 | grep -E 'mksub|summary'`
Expected: the new case passes; all existing mksub cases still pass.

- [ ] **Step 5: Commit**

```bash
git add src/mksub.py tests/run.sh
git commit -m "mksub: provider title, reusable matcher, extract by id, pool marks, summary"
```

### Task 2: mkfallback.py pool file

**Files:**
- Create: `src/mkfallback.py`
- Modify: `install.sh` (5 file lists), `tests/run.sh` (py_compile list line 141, bundle lists 321/390), `tests/lifecycle.sh:22`
- Test: `tests/run.sh` parser tier

**Interfaces:**
- Consumes: `mksub._load`, `mksub._selection_meta`, `mksub.match_node`, `proxylib.die`.
- Produces (CLI, all take `--pool FILE`; writes are atomic, mode 600):
  - `add --sub ID --catalog F --index N [--position P]` → appends/inserts; dies with `node #N is already in the pool`, `node #N is not supported`, `no node #N`, `the pool holds at most 10 nodes`.
  - `remove --position P`, `order P1 P2 ...` (permutation), `count` (prints usable/total), `drop-sub --sub ID` (prints remaining count), `rematch --sub ID --catalog F` (marks/unmarks `missing`, updates meta).
  - Python API: `load_pool(path) -> list[dict]`, `save_pool(path, nodes)`.

- [ ] **Step 1: Write the failing test**

```sh
    py_case "mkfallback: pool add/order/remove/rematch/drop" "$SRC" <<'PY'
import json, os, subprocess, sys, tempfile
src = sys.argv[1]; sys.path.insert(0, src)
import mksub
def cli(*args):
    return subprocess.run([sys.executable, os.path.join(src, "mkfallback.py")] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
links = "\n".join(["vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?security=tls&type=tcp#DE",
                   "trojan://secret@b.example.com:443?security=tls#NL",
                   "vless://b831381d-6324-4d53-ad4f-8cda48b30811@0.0.0.0:443?security=tls&type=tcp#bad"]).encode()
with tempfile.TemporaryDirectory() as tmp:
    catf, pool = os.path.join(tmp, "catalog.json"), os.path.join(tmp, "fallback.json")
    cat = mksub.process_body(links); json.dump(cat, open(catf, "w"))
    assert cli("add", "--pool", pool, "--sub", "1", "--catalog", catf, "--index", "2").returncode == 0
    assert cli("add", "--pool", pool, "--sub", "1", "--catalog", catf, "--index", "1", "--position", "1").returncode == 0
    dup = cli("add", "--pool", pool, "--sub", "1", "--catalog", catf, "--index", "1")
    assert dup.returncode != 0 and "already in the pool" in dup.stderr, dup.stderr
    bad = cli("add", "--pool", pool, "--sub", "1", "--catalog", catf, "--index", "3")
    assert bad.returncode != 0 and "not supported" in bad.stderr, bad.stderr
    assert cli("add", "--pool", pool, "--sub", "1", "--catalog", catf, "--index", "9").returncode != 0
    assert oct(os.stat(pool).st_mode & 0o777) == "0o600"
    assert [n["meta"]["label"] for n in json.load(open(pool))["nodes"]] == ["DE", "NL"]
    assert cli("order", "--pool", pool, "2", "1").returncode == 0
    assert [n["meta"]["label"] for n in json.load(open(pool))["nodes"]] == ["NL", "DE"]
    assert cli("order", "--pool", pool, "1", "1").returncode != 0
    # NL disappears from the catalog -> missing; comes back with a new id -> matched again
    json.dump(dict(cat, nodes=[cat["nodes"][0]]), open(catf, "w"))
    assert cli("rematch", "--pool", pool, "--sub", "1", "--catalog", catf).returncode == 0
    assert [n["missing"] for n in json.load(open(pool))["nodes"]] == [True, False]
    assert cli("count", "--pool", pool).stdout.split() == ["1", "2"]
    json.dump(cat, open(catf, "w"))
    assert cli("rematch", "--pool", pool, "--sub", "1", "--catalog", catf).returncode == 0
    assert [n["missing"] for n in json.load(open(pool))["nodes"]] == [False, False]
    assert cli("remove", "--pool", pool, "--position", "1").stdout == ""
    assert cli("drop-sub", "--pool", pool, "--sub", "1").stdout.strip() == "0"
    json.dump({"schema": 1, "nodes": [{"sub": "x", "meta": {}}]}, open(pool, "w"))
    assert cli("count", "--pool", pool).returncode != 0          # malformed file is refused
PY
```

- [ ] **Step 2: Run to verify it fails** — `bash tests/run.sh 2>&1 | grep -A2 mkfallback` → FAIL (`No such file ... mkfallback.py`).

- [ ] **Step 3: Implement** `src/mkfallback.py` (pool half):

```python
#!/usr/bin/env python3
"""
mkfallback.py - the fallback pool and its watchdog's decisions for proxy-unifi.

The pool is an ordered list (first = priority 1) of subscription nodes kept in
fallback.json. The shell CLI does the I/O a check or a switch needs; this module
validates and edits the pool and decides, for one watchdog run, what to check
and where to switch (run_once), calling back into the CLI for both.

Stdlib only (Python 3.9+).
"""

import argparse
import json
import os
import re
import sys
import tempfile
import time

from proxylib import die, dispatch_subcommand

SCHEMA = 1
MAX_POOL = 10
_SUB_RE = re.compile(r"^[1-9][0-9]{0,2}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _write_json(path, value, mode=0o600):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".write.", dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            json.dump(value, fh, ensure_ascii=False, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _valid_entry(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("meta"), dict):
        return False
    meta = entry["meta"]
    return (isinstance(entry.get("sub"), str) and _SUB_RE.match(entry["sub"]) is not None
            and isinstance(meta.get("id"), str) and _ID_RE.match(meta["id"]) is not None
            and isinstance(entry.get("missing", False), bool)
            and all(isinstance(meta.get(k, ""), str) for k in ("kind", "scheme", "label", "server")))


def load_pool(path):
    """The pool's entries; an absent file is an empty pool, a malformed one dies."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        die("could not read the fallback pool: %s" % e)
    nodes = data.get("nodes") if isinstance(data, dict) else None
    if data.get("schema") != SCHEMA or not isinstance(nodes, list) or len(nodes) > MAX_POOL \
            or not all(_valid_entry(n) for n in nodes):
        die("the fallback pool file is malformed")
    keys = [(n["sub"], n["meta"]["id"]) for n in nodes]
    if len(set(keys)) != len(keys):
        die("the fallback pool file is malformed")
    return nodes


def save_pool(path, nodes):
    _write_json(path, {"schema": SCHEMA, "nodes": nodes})


def _catalog(path):
    import mksub
    return mksub._load(path)


def cmd_add(args):
    import mksub
    if not _SUB_RE.match(args.sub):
        die("invalid subscription id")
    nodes = load_pool(args.pool)
    if len(nodes) >= MAX_POOL:
        die("the pool holds at most %d nodes" % MAX_POOL)
    nd = next((n for n in _catalog(args.catalog)["nodes"] if n["n"] == args.index), None)
    if nd is None:
        die("no node #%d in this subscription" % args.index)
    if not nd.get("recognized"):
        die("node #%d is not supported" % args.index)
    if any(e["sub"] == args.sub and e["meta"]["id"] == nd["id"] for e in nodes):
        die("node #%d is already in the pool" % args.index)
    entry = {"sub": args.sub, "meta": mksub._selection_meta(nd), "missing": False}
    position = args.position or len(nodes) + 1
    if not 1 <= position <= len(nodes) + 1:
        die("position must be 1-%d" % (len(nodes) + 1))
    nodes.insert(position - 1, entry)
    save_pool(args.pool, nodes)


def cmd_remove(args):
    nodes = load_pool(args.pool)
    if not 1 <= args.position <= len(nodes):
        die("no position %d in the pool" % args.position)
    del nodes[args.position - 1]
    save_pool(args.pool, nodes)


def cmd_order(args):
    nodes = load_pool(args.pool)
    if sorted(args.positions) != list(range(1, len(nodes) + 1)):
        die("enter each position 1-%d exactly once" % len(nodes))
    save_pool(args.pool, [nodes[p - 1] for p in args.positions])


def cmd_count(args):
    nodes = load_pool(args.pool)
    sys.stdout.write("%d %d\n" % (sum(not n.get("missing") for n in nodes), len(nodes)))


def cmd_drop_sub(args):
    nodes = [n for n in load_pool(args.pool) if n["sub"] != args.sub]
    save_pool(args.pool, nodes)
    sys.stdout.write("%d\n" % len(nodes))


def rematch(nodes, sub, cat):
    """Re-point the pool entries of one refreshed subscription; returns nodes."""
    import mksub
    for entry in nodes:
        if entry["sub"] != sub:
            continue
        found = mksub.match_node(cat, entry["meta"])
        if found is None:
            entry["missing"] = True
        else:
            entry["meta"], entry["missing"] = mksub._selection_meta(found[0]), False
    return nodes


def cmd_rematch(args):
    if not os.path.exists(args.pool):
        return
    save_pool(args.pool, rematch(load_pool(args.pool), args.sub, _catalog(args.catalog)))
```

`main()` registers the subcommands with `argparse` exactly as named in Interfaces (`--position` int default 0 for `add`, required int for `remove`; `order` takes `positions` as `nargs="+"`, `type=int`) and calls `dispatch_subcommand(ap)`. Add `mkfallback.py` to: `install.sh` lines 75, 248 (`needed`), 387, 397, 406; `tests/run.sh` line 141 (py_compile) and the file lists at 321/390; `tests/lifecycle.sh:22`.

- [ ] **Step 4: Run tests** — `bash tests/run.sh 2>&1 | grep -E 'mkfallback|static|summary'` → new case ok, static tier still ok.
- [ ] **Step 5: Commit** — `git add src/mkfallback.py install.sh tests/run.sh tests/lifecycle.sh && git commit -m "mkfallback: the fallback pool file"`

### Task 3: mkfallback.py watchdog decisions (`run_once`) and its CLI

**Files:**
- Modify: `src/mkfallback.py`
- Test: `tests/run.sh` parser tier

**Interfaces:**
- Produces: `run_once(pool, state, active, cfg, probe, apply, now) -> list[str]` (log lines; mutates `state`), where
  - `pool`: entries from `load_pool`; `active`: `(sub, id)` or `None`; `cfg`: `{"down": int, "up": int, "ret": bool}`;
  - `probe(index, kind) -> (ok: bool, ms: int, err: str)`, `kind` in `"live"`, `"core"`; a live probe that cannot run returns `(False, 0, "nolive")`;
  - `apply(index, reason) -> (ok: bool, err: str)`.
- State JSON: `{"schema":1,"nodes":{"<sub>:<id>":{"fails":n,"oks":n,"at":epoch,"ms":n,"err":""}},"rot":n,"tunnel":"ok"|"failing","note":""}`; `load_state(path)` returns a fresh state for a missing/malformed file.
- CLI: `run --pool F --state F --last F --selected F --cli PATH --down N --up N --return on|off --timeout N`; `test --pool F --state F --cli PATH --timeout N`; `show --pool F --state F --last F --selected F --subs-dir D`; `status --pool F --state F --last F --selected F --subs-dir D`.
- The CLI callbacks: `PATH _fallback-probe SUB ID live|core` prints `ok MS` or `fail ERR`; `PATH _fallback-apply SUB ID EXPECTED_ACTIVE_ID REASON` exits 0 on a switch.

- [ ] **Step 1: Write the failing test**

```sh
    py_case "mkfallback: watchdog decisions" "$SRC" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import mkfallback as fb
def entry(i):
    return {"sub": "1", "meta": {"id": ("%x" % i) * 64, "label": "n%d" % i, "kind": "link",
                                 "scheme": "vless", "server": "s"}, "missing": False}
pool = [entry(i) for i in (1, 2, 3)]
def key(i): return "1:" + ("%x" % (i + 1)) * 64
def world(up, applied):
    def probe(i, kind):
        return (True, 50, "") if up[i] else (False, 0, "timeout")
    def apply(i, reason):
        applied.append((i, reason)); return (True, "")
    return probe, apply
cfg = {"down": 3, "up": 2, "ret": True}
active = ("1", pool[0]["meta"]["id"])
# offline only after 3 failed runs, then the first passing candidate (#3, #2 is down too)
state, applied = fb.load_state("/nonexistent"), []
probe, apply = world([False, False, True], applied)
for _ in range(2):
    fb.run_once(pool, state, active, cfg, probe, apply, 0)
assert applied == [] and state["nodes"][key(0)]["fails"] == 2
fb.run_once(pool, state, active, cfg, probe, apply, 0)
assert [a[0] for a in applied] == [2] and "#1" in applied[0][1], applied
# everything down: stay, note it
state, applied = fb.load_state("/nonexistent"), []
probe, apply = world([False, False, False], applied)
for _ in range(3):
    fb.run_once(pool, state, active, cfg, probe, apply, 0)
assert applied == [] and "no pool node online" in state["note"]
# return: on #3, #1 back -> rotation checks #1 then #2; switch after 2 good checks of #1
state, applied = fb.load_state("/nonexistent"), []
probe, apply = world([True, False, True], applied)
on3 = ("1", pool[2]["meta"]["id"])
for _ in range(3):
    fb.run_once(pool, state, on3, cfg, probe, apply, 0)
assert [a[0] for a in applied] == [0], (applied, state)
# a recovering higher entry holds back a lower one that is already online
state, applied = fb.load_state("/nonexistent"), []
state["nodes"][key(0)] = {"fails": 0, "oks": 1, "at": 0, "ms": 0, "err": ""}
state["nodes"][key(1)] = {"fails": 0, "oks": 5, "at": 0, "ms": 0, "err": ""}
state["rot"] = 1                                  # next return check is #2
probe, apply = world([True, True, True], applied)
fb.run_once(pool, state, on3, cfg, probe, apply, 0)
assert applied == [], applied
# no return when FB_RETURN is off
state, applied = fb.load_state("/nonexistent"), []
probe, apply = world([True, True, True], applied)
for _ in range(5):
    fb.run_once(pool, state, on3, dict(cfg, ret=False), probe, apply, 0)
assert applied == []
# live check fails, node answers through a test core: no failure, tunnel flagged
state, applied = fb.load_state("/nonexistent"), []
calls = []
def probe2(i, kind):
    calls.append(kind); return (kind == "core", 9, "" if kind == "core" else "timeout")
for _ in range(4):
    fb.run_once(pool, state, active, cfg, probe2, lambda i, r: (applied.append(i), (True, ""))[1], 0)
assert applied == [] and state["tunnel"] == "failing" and state["nodes"][key(0)]["fails"] == 0
# active not in the pool -> highest-priority online entry right away
state, applied = fb.load_state("/nonexistent"), []
probe, apply = world([False, True, True], applied)
fb.run_once(pool, state, ("9", "f" * 64), cfg, probe, apply, 0)
assert [a[0] for a in applied] == [1]
# a failed apply counts as offline and the next candidate is tried
state, applied = fb.load_state("/nonexistent"), []
def apply_fail_first(i, reason):
    applied.append(i); return (i != 1, "test failed")
probe, _ = world([False, True, True], [])
for _ in range(3):
    fb.run_once(pool, state, active, cfg, probe, apply_fail_first, 0)
assert applied == [1, 2], applied
# a missing entry is skipped; fewer than 2 usable entries -> no run
state, applied = fb.load_state("/nonexistent"), []
gone = [entry(1), dict(entry(2), missing=True)]
probe, apply = world([False, True], applied)
for _ in range(3):
    fb.run_once(gone, state, ("1", gone[0]["meta"]["id"]), cfg, probe, apply, 0)
assert applied == []
import os, tempfile
with tempfile.TemporaryDirectory() as tmp:
    bad = os.path.join(tmp, "s"); open(bad, "w").write("{oops")
    assert fb.load_state(bad)["nodes"] == {}
PY
```

- [ ] **Step 2: Run to verify it fails** → FAIL `AttributeError: module 'mkfallback' has no attribute 'load_state'`.

- [ ] **Step 3: Implement** (append to `src/mkfallback.py`):

```python
def _key(entry):
    return "%s:%s" % (entry["sub"], entry["meta"]["id"])


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if isinstance(state, dict) and state.get("schema") == SCHEMA \
                and isinstance(state.get("nodes"), dict) and isinstance(state.get("rot"), int):
            state.setdefault("tunnel", "ok")
            state.setdefault("note", "")
            return state
    except (OSError, ValueError):
        pass
    return {"schema": SCHEMA, "nodes": {}, "rot": 0, "tunnel": "ok", "note": ""}


def _record(state, entry, ok, ms, err, now, streaks=True):
    node = state["nodes"].setdefault(_key(entry), {"fails": 0, "oks": 0, "at": 0, "ms": 0, "err": ""})
    node.update(at=now, ms=ms if ok else 0, err="" if ok else err)
    if streaks:
        if ok:
            node["oks"], node["fails"] = node["oks"] + 1, 0
        else:
            node["fails"], node["oks"] = node["fails"] + 1, 0
    return node


def _switch_to_first_online(pool, state, order, probe, apply, now, reason, log):
    for i in order:
        ok, ms, err = probe(i, "core")
        _record(state, pool[i], ok, ms, err, now)
        if not ok:
            continue
        done, why = apply(i, reason)
        if done:
            state["note"], state["tunnel"] = "", "ok"
            log.append("switched to #%d: %s" % (i + 1, reason))
            return True
        _record(state, pool[i], False, 0, "could not apply: %s" % why, now)
    state["note"] = "no pool node online"
    log.append("no pool node online")
    return False


def run_once(pool, state, active, cfg, probe, apply, now):
    """One watchdog run (see the spec's "A run"). Mutates state; returns log lines."""
    log = []
    usable = [i for i, e in enumerate(pool) if not e.get("missing")]
    if len(usable) < 2:
        return log
    apos = next((i for i in usable if active and (pool[i]["sub"], pool[i]["meta"]["id"]) == active), None)
    if apos is None:
        _switch_to_first_online(pool, state, usable, probe, apply, now,
                                "the active node is not in the pool", log)
        return log
    ok, ms, err = probe(apos, "live")
    if not ok:
        live_err = err
        ok, ms, err = probe(apos, "core")
        state["tunnel"] = "failing" if ok and live_err != "nolive" else "ok"
    else:
        state["tunnel"] = "ok"
    node = _record(state, pool[apos], ok, ms, err, now)
    if node["fails"] >= cfg["down"]:
        others = [i for i in usable if i != apos]
        _switch_to_first_online(pool, state, others, probe, apply, now,
                                "#%d offline after %d failed checks: %s" % (apos + 1, node["fails"], err), log)
        return log
    state["note"] = ""
    higher = [i for i in usable if i < apos]
    if not cfg["ret"] or not higher:
        return log
    i = higher[state["rot"] % len(higher)]
    state["rot"] += 1
    ok, ms, err = probe(i, "core")
    _record(state, pool[i], ok, ms, err, now)
    streak = {j: state["nodes"].get(_key(pool[j]), {}).get("oks", 0) for j in higher}
    ready = [j for j in higher if streak[j] >= cfg["up"]]
    if not ready:
        return log
    target = ready[0]
    if any(streak[j] >= 1 for j in higher if j < target):
        return log                     # a higher entry is recovering too: wait for it
    done, why = apply(target, "#%d back online" % (target + 1))
    if done:
        log.append("switched to #%d: back online" % (target + 1))
    else:
        _record(state, pool[target], False, 0, "could not apply: %s" % why, now)
    return log
```

CLI wiring (append): `_cli_probe(cli, entry, kind, timeout)` runs `subprocess.run([cli, "_fallback-probe", sub, id, kind], timeout=timeout*3+30, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)` and parses `ok MS` / `fail ERR` (anything else or a timeout → `(False, 0, "check did not finish")`). `_cli_apply(cli, entry, expected, reason)` runs `[cli, "_fallback-apply", sub, id, expected or "-", reason]` with `timeout=600`; returns `(rc == 0, last stderr line)`. `_active(selected_file)` reads `selected.json` → `(sub, id)` or `None` (missing `sub` key → `None`).

`cmd_run`: `pool = load_pool(...)`; `state = load_state(...)`; `cfg` from args; `run_once(...)` with the CLI callbacks; `_write_json(args.state, state)`; for a switch line, `_write_json(args.last, {"at": now, "line": line})`; print each log line prefixed `<5>` so journald records it at notice level (the unit sets `SyslogLevelPrefix` default yes).

`cmd_test`: probes every usable entry with `"core"`, records with `streaks=False`, writes state, prints `  N. <label>  online 123 ms` / `offline (err)` / `missing from subscription`.

`cmd_show`: prints the pool table of the spec (`  1. [<sub name>] <label>  <scheme>  online 132 ms   <- active`, `offline since HH:MM (err)`, `not checked yet`, `missing from subscription`), the tunnel line when `state["tunnel"] == "failing"` (`  tunnel check failing, node answers through a test core`), the note, and `Last switch: HH:MM  <line>`. Sub names come from `<subs-dir>/<sub>/name` passed through `mksub.clean`.

`cmd_status`: one line `active #K of N ([name] label), last switch HH:MM` (or `active node not in the pool`), plus `, tunnel check failing` when flagged.

- [ ] **Step 4: Run tests** → new case ok.
- [ ] **Step 5: Commit** — `git commit -am "mkfallback: watchdog decisions and run/test/show/status"`

### Task 4: Multiple subscriptions in the CLI

**Files:**
- Modify: `src/proxy-unifi` (constants block lines 38–43; `restore_runtime_state` ~481; `write_refresh_timer`/`enable_refresh_timer` ~1320–1360; `install_service` ~1995; `sub_*` and `menu_sub` ~3600–3850; dispatch `sub-refresh-auto` and the no-lock list)
- Test: `tests/lifecycle.sh` (existing subscription block ~213–245; new block)

**Interfaces:**
- Produces shell functions: `sub_migrate`, `sub_ids` (ascending ids, one per line), `sub_any` (0 if any), `sub_valid_id ID`, `sub_path ID`, `sub_ua ID`, `sub_add URL [NAME]`, `sub_fetch_one ID DEST` (lock-free), `sub_install ID CANDIDATE` (locked), `sub_refresh_all` (lock-free fetch + locked install per sub), `sub_select ID N`, `sub_rename ID NAME`, `sub_set_ua ID UA`, `sub_remove ID`, `sub_choose` (menu prompt; echoes an id), `sub_summary`.
- `SUB_SELECTED_META` (`selected.json`) carries `"sub"`. Variables `SUB_URL_FILE`/`SUB_CATALOG` are removed; use `$(sub_path ID)/url.txt` etc.
- `FB_POOL="$ETC_DIR/fallback.json"` constant defined here (used by rematch/drop-sub), `MKFALLBACK="$BIN_DIR/mkfallback.py"`.

- [ ] **Step 1: Write the failing tests** — replace the old-layout subscription block in `tests/lifecycle.sh` (it already writes `subscription/url.txt` + `catalog.json`) so it now asserts migration, and add multi-subscription checks after it:

```sh
printf '2\n1\n1\n\n0\n' | menu_input > "$T/sub-select.out" 2>&1
grep -q 'refreshed\|nodes' "$T/sub-select.out"
if grep -q 'unsupported' "$T/sub-select.out"; then exit 1; fi
[ "$(cat "$T/root/etc/engine")" = xraypool ]
# migrated: the old files moved into subscription 1, the selection names it
[ -s "$T/root/etc/subscription/1/url.txt" ] && [ ! -e "$T/root/etc/subscription/url.txt" ]
[ -s "$T/root/etc/subscription/1/catalog.json" ] && [ -s "$T/root/etc/subscription/1/name" ]
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "1"' \
    "$T/root/etc/subscription/selected.json"
# a second subscription (catalog placed by hand: the sandbox has no network)
mkdir -p "$T/root/etc/subscription/2"; chmod 700 "$T/root/etc/subscription/2"
printf 'https://two.example/s' > "$T/root/etc/subscription/2/url.txt"
printf 'Second' > "$T/root/etc/subscription/2/name"
python3 - "$REPO/src" "$T/root/etc/subscription/2/catalog.json" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1]); import mksub
links = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.1.1.1:443?security=none&type=tcp#two-a\n" \
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.0.0.1:443?security=none&type=tcp#two-b"
json.dump(mksub.process_body(links.encode()), open(sys.argv[2], "w"))
PY
# choose subscription 2, node 2
printf '2\n1\n2\n2\n\n0\n' | menu_input > "$T/sub2.out" 2>&1
grep -q 'Second' "$T/sub2.out"
[ "$(cat "$T/root/etc/engine")" = xray ]
grep -q '1.0.0.1' "$T/root/etc/link.txt"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["sub"] == "2"' \
    "$T/root/etc/subscription/selected.json"
# rename, then remove subscription 1 (asks y/N); 2 keeps its number
printf '2\n5\n2\nRenamed\n\n0\n' | menu_input >/dev/null 2>&1
[ "$(cat "$T/root/etc/subscription/2/name")" = Renamed ]
printf '2\n4\n1\ny\n\n0\n' | menu_input >/dev/null 2>&1
[ ! -e "$T/root/etc/subscription/1" ] && [ -d "$T/root/etc/subscription/2" ]
# refresh-all with no network: each failure is recorded, the catalog is kept
run_cli sub-refresh-auto >/dev/null 2>&1 || true
grep -q '^fail ' "$T/root/etc/subscription/2/status"
[ -s "$T/root/etc/subscription/2/catalog.json" ]
[ ! -e "$T/root/.lock" ] || exit 1
```

And a lock-free download check (Review Focus is about the watchdog never waiting minutes): run `sub-refresh-auto` with a `mksub.py` replaced by a stub whose `fetch` sleeps 3 s and writes `$T/fetching` first; while it sleeps, assert `[ ! -d "$T/root/.lock" ]`:

```sh
cp "$T/root/bin/mksub.py" "$T/mksub.real"
cat > "$T/root/bin/mksub.py" <<PY
import os, sys, time, runpy
if len(sys.argv) > 1 and sys.argv[1] == "fetch":
    open("$T/fetching", "w").close(); time.sleep(3); sys.exit(1)
sys.argv[0] = "$T/mksub.real"; runpy.run_path("$T/mksub.real", run_name="__main__")
PY
run_cli sub-refresh-auto >/dev/null 2>&1 &
_rp=$!; _i=0
while [ ! -e "$T/fetching" ] && [ "$_i" -lt 100 ]; do _i=$((_i + 1)); sleep 0.05; done
[ ! -d "$T/root/.lock" ]
wait "$_rp" || true
cp "$T/mksub.real" "$T/root/bin/mksub.py"
```

- [ ] **Step 2: Run** `sh tests/lifecycle.sh tests/.cache/xray` → fails at the first new assertion (menu 2 → 1 is still "Add or replace").

- [ ] **Step 3: Implement** (shell; key functions shown, the rest follow the same patterns):

```sh
SUB_DIR="$ETC_DIR/subscription"
SUB_HWID_FILE="$SUB_DIR/hwid"               # stable per-install device id
SUB_SELECTED="$SUB_DIR/selected"            # id of the node currently activated
SUB_SELECTED_META="$SUB_DIR/selected.json"  # selection metadata (+ "sub") for refresh matching
SUB_MAX=20
FB_POOL="$ETC_DIR/fallback.json"            # the fallback pool (mkfallback.py)
MKFALLBACK="$BIN_DIR/mkfallback.py"

sub_valid_id() { _uint "$1" && [ "$1" -ge 1 ] && [ "$1" -le 999 ] && [ -s "$SUB_DIR/$1/url.txt" ]; }
sub_path() { printf '%s/%s' "$SUB_DIR" "$1"; }
sub_ids() {
    for _sd in "$SUB_DIR"/*/; do
        _sd="${_sd%/}"; _sd="${_sd##*/}"
        sub_valid_id "$_sd" && echo "$_sd"
    done | sort -n
}
sub_any() { [ -n "$(sub_ids)" ]; }
sub_ua() { cat "$SUB_DIR/$1/ua" 2>/dev/null || printf '%s' "$SUB_USER_AGENT"; }

# The single-subscription layout of earlier versions becomes subscription 1.
sub_migrate() {
    [ -s "$SUB_DIR/url.txt" ] || return 0
    txn_begin
    mkdir -p "$SUB_DIR/1" && chmod 700 "$SUB_DIR/1" || fatal "could not migrate the subscription"
    mv "$SUB_DIR/url.txt" "$SUB_DIR/1/url.txt" || fatal "could not migrate the subscription"
    [ ! -f "$SUB_DIR/catalog.json" ] || mv "$SUB_DIR/catalog.json" "$SUB_DIR/1/catalog.json" \
        || fatal "could not migrate the subscription"
    sub_name_default 1 | atomic_write "$SUB_DIR/1/name" 600 || fatal "could not migrate the subscription"
    if [ -s "$SUB_SELECTED_META" ]; then
        py - "$SUB_SELECTED_META" <<'PYEOF' | atomic_write "$SUB_SELECTED_META.new" 600 \
            && mv -f "$SUB_SELECTED_META.new" "$SUB_SELECTED_META" || fatal "could not migrate the selection"
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
meta["sub"] = "1"
print(json.dumps(meta, ensure_ascii=True, sort_keys=True))
PYEOF
    fi
    [ -n "$TXN_DIR" ] && txn_commit
}
```

`sub_name_default ID`: the catalog's `meta.title` if present (via `py -c` reading `catalog.json`), else the URL host (`sed 's|^https://\([^/:?#]*\).*|\1|'` of `url.txt`).

Migration runs at the top of `menu_sub`, `fallback_menu`, `sub_refresh_all`, `cmd_status` (read-only: status prints from the old layout if migration has not happened — call `( locked_call sub_migrate )` from the menu entry instead), and `install_service` (install/update/boot recovery run it once).

`sub_fetch_to URL DEST UA` gains the UA argument (`--ua "$3"`). `sub_add URL [NAME]`: refuse at `SUB_MAX`; new id = highest + 1; fetch to a candidate first; then `txn_begin`, `mkdir -m 700`, write `url.txt`, `catalog.json`, `name` (given or `sub_name_default`), `status` (`ok <epoch>`), `enable_refresh_timer`, `txn_commit`, print `Subscription <id> added.` and the node list.

`sub_install ID CANDIDATE` (called through `locked_call`): `txn_begin`; write the catalog and `status ok <epoch>`; `py "$MKFALLBACK" rematch --pool "$FB_POOL" --sub ID --catalog <catalog>`; if `selected.json`'s `sub` is ID, run the existing re-match logic of `sub_refresh` with `_KEEP_FALLBACK=1 _QUIET=1 sub_select ID N` on a changed node; `txn_commit`.

`sub_refresh_all`: for each id, `sub_fetch_to "$(cat url)" "$RUN_DIR/refresh-ID" "$(sub_ua ID)"` without the lock; on success `locked_call sub_install ID "$RUN_DIR/refresh-ID"`; on failure `locked_call sub_mark_failed ID "<reason>"` (writes `status fail <epoch> <reason>`). Print one line per subscription unless `_AUTO_REFRESH=1`. Dispatch: move `sub-refresh-auto` into the no-lock list and call `( sub_migrate_locked ); sub_refresh_all`.

`sub_select ID N`: as today, but with the catalog of ID, `selected.json` written with `sub` (use `py` to add `"sub": ID` to the meta written by `mksub extract`), and — unless `_KEEP_FALLBACK=1` — `fallback_detach` (Task 6 defines it; until then a no-op stub `fallback_detach() { :; }` keeps this task green).

`sub_remove ID`: `txn_begin`; `rm -rf "$SUB_DIR/ID"`; if `selected.json`'s `sub` is ID, remove `selected` and `selected.json` (tunnel unchanged); `py "$MKFALLBACK" drop-sub ...` and if fewer than 2 remain while `FALLBACK=on`, turn it off with a message (Task 6 helper `fallback_set off`; stubbed here); `sub_any || disable_refresh_timer`; `txn_commit`.

`sub_choose PROMPT` (menu helper, no lock): if exactly one id, echo it; else print `sub_summary`, read `Subscription number:`, validate with `sub_valid_id`, echo it (empty → return 1).

`menu_sub` (one item per line, exactly the spec's text): header from `sub_summary` plus `Active node: [<name>] <label> (<scheme>)` read from `selected.json`; items 1–8 and 0 as in the spec; `8. User-Agent` asks `Subscription number, or d for the default:`.

Timer: `write_refresh_timer` uses `ConditionPathExistsGlob=$SUB_DIR/*/url.txt`; `enable_refresh_timer` and `install_service` and `restore_runtime_state` test `sub_any` instead of `[ -s "$SUB_URL_FILE" ]`.

`sub_status` (used by `proxy status`) prints `subscriptions: N` and each `sub_summary` line.

- [ ] **Step 4: Run** `sh tests/lifecycle.sh tests/.cache/xray && echo lifecycle-ok` and `bash tests/run.sh` (shellcheck, static, lifecycle) → pass.
- [ ] **Step 5: Commit** — `git commit -am "Subscriptions: several at once, chosen subscription then node, lock-free refresh"`

### Task 5: Checks and switches for one node (`_fallback-probe`, `_fallback-apply`)

**Files:**
- Modify: `src/proxy-unifi` (`_probe_start`, `ping_proxy`, new `_http_probe`, `_fallback_probe`, `_fallback_apply`, dispatch)
- Test: `tests/run.sh` engine tier (the probe harness `lib.sh`)

**Interfaces:**
- `_probe_start BUDGET MEM [ENGINE SOURCE]`: with ENGINE (`xray`|`singbox`|`xraypool`) and SOURCE (a link file or profile file) builds the test core for that node instead of the active one.
- `_http_probe CURL_ARGS...` sets `_rc`, `_code`, `_ms`, `_why` (curl exit 28 → `_why="timeout (>${PING_TIMEOUT}s)"`).
- `_fallback-probe SUB ID live|core` → stdout `ok MS` | `fail ERR`, exit 0 either way; `live` prints `fail nolive` when there is no UniFi client interface or the service is not healthy. Uses `FB_TIMEOUT` as `PING_TIMEOUT`.
- `_fallback-apply SUB ID EXPECTED REASON` → under the lock: exits 3 (`stale`) unless `FALLBACK=on` and the active node id equals EXPECTED (`-` = none); else `_KEEP_FALLBACK=1 _QUIET=1 sub_select SUB N` for the node with that id (via `mksub extract --id`, then its `n`), prints `switched`.

- [ ] **Step 1: Failing test** — extend the engine-tier probe harness: add `MKJSON`/`MKSUB` and `_http_probe` to `lib.sh`, then:

```sh
    # A pool node that is not active gets its own test core.
    cat > "$_pd/node.json" <<'EOF'
{"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10808}],"outbounds":[{"protocol":"freedom","tag":"proxy"}]}
EOF
    # shellcheck disable=SC2016 # $1-$2 expand inside the child shell.
    _node="$(sh -c '. "$1"; _probe_start 30 256 xraypool "$2" || exit 1
_http_probe -X GET --proxy "${_proxy_scheme}://127.0.0.1:${_port}" "$PING_URL"; _ping_cleanup
echo "$_rc $_code"' sh "$_pd/lib.sh" "$_pd/node.json" 2>&1)"
```
with `[ "$_node" = "0 200" ]` added to the proxy-ping `ok` condition (and to its message).

- [ ] **Step 2: Run** → FAIL (`_http_probe: not found`).
- [ ] **Step 3: Implement**

```sh
# Run curl for a probe; sets _rc, _code, _ms and _why (curl's error, or timeout).
_http_probe() {
    _out="$(LC_ALL=C curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' --max-time "$PING_TIMEOUT" \
             "$@" 2>&1)" && _rc=0 || _rc=$?
    _code=""; _ms=""; _why=""
    if [ "$_rc" = 0 ]; then
        _out="$(printf '%s\n' "$_out" | tail -n 1)"
        _code="${_out%% *}"; _ms="$(_ms_from_seconds "${_out##* }")"
    elif [ "$_rc" = 28 ]; then
        _why="timeout (>${PING_TIMEOUT}s)"
    else
        _why="$(printf '%s\n' "$_out" | sed -n 's/^curl: ([0-9]*) //p' | head -n 1)"
        _why="${_why:-curl exit $_rc}"
    fi
}
```

`ping_proxy` uses it (its output lines stay exactly as now). `_probe_start`: `_e="${3:-$(current_engine)}"`, `_src="${4:-}"`, and the builders use `"${_src:-$POOL_SRC}"` / `"${_src:-$OUTBOUND_LINK}"`.

```sh
_fallback_probe() {   # <sub> <node id> <live|core>
    sub_valid_id "$1" || { echo "fail no such subscription"; return 0; }
    PING_TIMEOUT="$FB_TIMEOUT"
    if [ "$3" = live ]; then
        _wgif="$(unifi_client_if)"
        if [ -z "$_wgif" ] || ! service_healthy; then echo "fail nolive"; return 0; fi
        _http_probe -X GET -4 --noproxy '*' --interface "$_wgif" "$PING_URL"
    else
        ensure_run_dir
        _row="$(py "$MKSUB" extract --file "$SUB_DIR/$1/catalog.json" --id "$2" \
            --meta-file "$RUN_DIR/fb.meta" --payload-file "$RUN_DIR/fb.payload" 2>/dev/null)" \
            || { echo "fail missing from subscription"; return 0; }
        case "$_row" in *"${TAB}1${TAB}"*) : ;; *) echo "fail not supported"; return 0 ;; esac
        if [ "${_row##*"$TAB"}" = pool ]; then _fe=xraypool
        else _fe="$(engine_for_link_file "$RUN_DIR/fb.payload")"; fi
        _probe_start "$((FB_TIMEOUT + 15))" 256 "$_fe" "$RUN_DIR/fb.payload" \
            || { echo "fail test core did not start"; return 0; }
        _http_probe -X GET --proxy "${_proxy_scheme}://127.0.0.1:${_port}" "$PING_URL"
        _ping_cleanup
    fi
    if [ "$_rc" = 0 ]; then echo "ok $_ms"; else echo "fail $_why"; fi
}
```

`_fallback_apply` per Interfaces; sub/id validated (`sub_valid_id`, id matches `[0-9a-f]` × 64 via `case`), REASON printed with `logger`-free `echo "<5>proxy-unifi fallback: $4"`. Dispatch: `_fallback-probe` joins the no-lock list; `_fallback-apply` takes the lock like other mutating commands (default branch).

- [ ] **Step 4: Run** engine tier on the Mac with the `ss` stand-in and in CI → ok.
- [ ] **Step 5: Commit** — `git commit -am "Fallback: check and switch one pool node"`

### Task 6: The watchdog timer, settings, and fallback on/off

**Files:**
- Modify: `src/proxy-unifi` (defaults, `load_settings`, `save_settings`, timer writers, `txn_begin`/`restore_runtime_state`, `install_service`, `cmd_uninstall`, dispatch `fallback-check`, `cmd_status`, `cmd_import`, `cmd_import_json`, `awg_select`, `sub_select`)
- Modify: `install.sh` (unit lists lines 42 and 58 gain `proxy-unifi-fallback.service proxy-unifi-fallback.timer`)
- Test: `tests/lifecycle.sh` (mock unit files sed list gains `FB_SERVICE_FILE`/`FB_TIMER_FILE`), new block

**Interfaces:**
- Settings keys and validation per Global Constraints. Constants `FB_SERVICE_NAME="${SERVICE_NAME}-fallback"`, `FB_SERVICE_FILE`, `FB_TIMER_FILE`, `FB_STATE="$INGRESS_RUN/fallback.state"`, `FB_LAST="$ROOT/fallback.last"`.
- `fallback_set on|off` (inside a txn: save setting, write+enable or disable the timer), `fallback_detach` (if on: `fallback_set off` and print `Fallback turned off: you chose the node yourself (the pool is kept).`), `fallback_usable` (prints usable count), `fallback_check` (one run, no lock held by the caller), `lock_busy` (0 if a live process holds the CLI lock).

- [ ] **Step 1: Failing tests** (lifecycle; the probe is replaced by an injected function reading scripted results, the apply path is real):

```sh
# Inject before dispatch, like the identity helpers: scripted check results.
#   $MOCK_STATE/probe_<sub>_<id-prefix8>  holds "ok 50" or "fail timeout"
```
Add to the awk injection: `print "_fallback_probe() { _f=\"$MOCK_STATE/probe_${1}_$(printf %.8s \"$2\")\"; if [ -s \"$_f\" ]; then cat \"$_f\"; else echo \"fail unscripted\"; fi; }"`.

Then (after Task 4's block; subscription 2 has nodes two-a (1.1.1.1), two-b (1.0.0.1) and is
active on two-b). The pool is built with the module directly; the wizard comes in Task 7.

```sh
cat2="$T/root/etc/subscription/2/catalog.json"
idof() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nodes"][int(sys.argv[2])]["id"])' "$cat2" "$1"; }
ida="$(idof 0)"; idb="$(idof 1)"
python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub 2 --catalog "$cat2" --index 2
python3 "$T/root/bin/mkfallback.py" add --pool "$T/root/etc/fallback.json" --sub 2 --catalog "$cat2" --index 1
printf 'FALLBACK="on"\n' >> "$T/root/etc/settings.env"      # a later line wins in load_settings
echo "ok 40" > "$STATE/probe_2_$(printf %.8s "$ida")"
echo "fail timeout" > "$STATE/probe_2_$(printf %.8s "$idb")"
# #1 (two-b, active) is down: switch only on the 3rd run (balanced default FB_DOWN=3)
run_cli fallback-check; run_cli fallback-check
grep -q '1.0.0.1' "$T/root/etc/link.txt"
run_cli fallback-check
grep -q '1.1.1.1' "$T/root/etc/link.txt"
grep -q '#1 offline' "$T/root/fallback.last"
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"      # the watchdog's switch kept it on
run_cli status | grep -q '^fallback:  on, active #2 of 2'
# a held lock skips the run (nothing changes even though #1 is back)
echo "ok 40" > "$STATE/probe_2_$(printf %.8s "$idb")"
mkdir "$T/root/.lock"; sleep 300 & echo $! > "$T/root/.lock/pid"
for _r in 1 2 3 4 5 6 7 8 9 10 11; do run_cli fallback-check; done
grep -q '1.1.1.1' "$T/root/etc/link.txt"
kill "$(cat "$T/root/.lock/pid")"; rm -rf "$T/root/.lock"
# a stopped service is never started by a run
run_cli stop >/dev/null; run_cli fallback-check
if run_cli status 2>/dev/null | grep -q '^service:   active'; then exit 1; fi
run_cli start >/dev/null
# a stale switch is refused: the expected active node differs from the real one
if run_cli _fallback-apply 2 "$idb" "$(printf '0%.0s' $(seq 64))" test >/dev/null 2>&1; then exit 1; fi
grep -q '1.1.1.1' "$T/root/etc/link.txt"
# return to #1 after FB_UP=5 good checks (one return check per run, #1 is the only higher entry)
for _r in 1 2 3 4; do run_cli fallback-check; done
grep -q '1.1.1.1' "$T/root/etc/link.txt"
run_cli fallback-check
grep -q '1.0.0.1' "$T/root/etc/link.txt"
```

- [ ] **Step 2: Run** `sh tests/lifecycle.sh tests/.cache/xray` → FAIL at the first `run_cli fallback-check` (unknown command).

- [ ] **Step 3: Implement**

```sh
write_fallback_timer() {
    atomic_write "$FB_SERVICE_FILE" 644 <<EOF || return 1
[Unit]
Description=proxy-unifi fallback watchdog run
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN_DIR/proxy-unifi fallback-check
Nice=10
# Keep "started/finished" every interval out of the journal; switches log at notice.
LogLevelMax=notice
EOF
    atomic_write "$FB_TIMER_FILE" 644 <<EOF || return 1
[Unit]
Description=proxy-unifi fallback watchdog

[Timer]
OnBootSec=60s
OnUnitActiveSec=${FB_INTERVAL}s
AccuracySec=1s
Unit=$FB_SERVICE_NAME.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload 2>/dev/null || return 1
}

fallback_set() {   # on|off, inside a transaction
    FALLBACK="$1"; save_settings
    if [ "$1" = on ]; then
        write_fallback_timer || fatal "could not write the fallback timer"
        systemctl enable --now "$FB_SERVICE_NAME.timer" >/dev/null 2>&1 || fatal "could not start the fallback timer"
    else
        systemctl disable --now "$FB_SERVICE_NAME.timer" >/dev/null 2>&1 || true
    fi
}

lock_busy() {
    [ -d "$LOCK_DIR" ] || return 1
    _lb="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    case "$_lb" in ""|*[!0-9]*) return 0 ;; esac
    kill -0 "$_lb" 2>/dev/null
}

fallback_check() {
    [ "$FALLBACK" = on ] || return 0
    [ "$(_unit_state)" != inactive ] || return 0          # stopped by the user
    lock_busy && return 0                                  # someone is changing state
    [ -s "$FB_POOL" ] || return 0
    mkdir -p "$INGRESS_RUN" && chmod 700 "$INGRESS_RUN"
    py "$MKFALLBACK" run --pool "$FB_POOL" --state "$FB_STATE" --last "$FB_LAST" \
        --selected "$SUB_SELECTED_META" --cli "$BIN_DIR/proxy-unifi" \
        --down "$FB_DOWN" --up "$FB_UP" --return "$FB_RETURN" --timeout "$FB_TIMEOUT"
}
```

`txn_begin` records `fb-timer-enabled`/`fb-timer-active`; `restore_runtime_state` restores them (rewriting the unit when `FALLBACK=on`). `install_service`: when `FALLBACK=on`, `write_fallback_timer` and enable it; otherwise make sure it is disabled. `cmd_uninstall`: disable and remove both files. Dispatch: `fallback-check` joins the no-lock list. `cmd_import`, `cmd_import_json`: `[ "${_FROM_SUB:-0}" = "1" ] || { rm -f ...; fallback_detach; }`; `awg_select`: `fallback_detach`; `sub_select`: `[ "${_KEEP_FALLBACK:-0}" = 1 ] || fallback_detach`. `cmd_status`: `echo "fallback:  $( [ "$FALLBACK" = on ] && echo "on, $(py "$MKFALLBACK" status ...)" || echo off)"`. `FB_INTERVAL` changes rewrite the timer when on.

- [ ] **Step 4: Run** lifecycle → pass.
- [ ] **Step 5: Commit** — `git commit -am "Fallback: watchdog timer, settings, on/off, manual choices turn it off"`

### Task 7: Fallback menu, wizard, main menu renumbering

**Files:**
- Modify: `src/proxy-unifi` (`print_menu`, `cmd_menu`, new `menu_fallback`, `fallback_wizard`, `fallback_pick_node`, `fallback_confirm_manual`; menu actions 1, 2→1, 5 (JSON), 4 (AWG select) call `fallback_confirm_manual` first)
- Test: `tests/lifecycle.sh` (menu layout assertion; every existing `menu_input` line whose first number is ≥3 shifts by one: AWG `3`→`4`, JSON `4`→`5`, details `5`→`6`, regen `7`→`8`, WG settings `8`→`9`)

**Interfaces:**
- `fallback_pick_node DRAFT POS` loops: `sub_choose`, render nodes with `--pool DRAFT --sub ID`, read `Node number:` (empty → return 1), `py "$MKFALLBACK" add --pool DRAFT ... --position POS` (error → print and re-ask).
- `fallback_wizard`: works on `$RUN_DIR/fallback.draft` (copy nothing; a new pool); steps 1–6 of the spec; installs under `locked_call fallback_install DRAFT INTERVAL DOWN UP TIMEOUT RETURN ONOFF`; when turning on, after the lock is released, runs `fallback_turn_on_check` (prints `py "$MKFALLBACK" test`, then `fallback_check`).
- `fallback_confirm_manual`: when `FALLBACK=on`, `printf 'Fallback is on; choosing a node yourself turns it off. Continue? [y/N]: '`; returns 1 unless `y`.

- [ ] **Step 1: Failing tests** — the menu layout assertion becomes:

```python
positions=[plain.index(label) for label in
           ("Subscriptions", "Fallback pool", "Manage AmneziaWG profiles",
            "Import an Xray JSON profile")]
assert positions == sorted(positions), positions
numbers=[int(x) for x in re.findall(r"│\s+([0-9]+)\. ", plain)]
assert numbers[:23] == list(range(23)), numbers[:23]
```

plus the wizard input of Task 6's block (now runnable), plus cancellations (Review Focus 5):

```sh
# Empty/invalid answers never save a half-built pool.
cp "$T/root/etc/fallback.json" "$T/pool.before"
printf '3\n1\nx\n\n\n0\n' | menu_input >/dev/null 2>&1          # count not a number, then cancel
printf '3\n1\n2\n2\n9\n\n\n0\n' | menu_input >/dev/null 2>&1    # node 9 does not exist, then cancel
cmp "$T/pool.before" "$T/root/etc/fallback.json"
# turning on from the wizard enables the timer (Task 6 set FALLBACK by hand)
grep -q 'FALLBACK="on"' "$T/root/etc/settings.env"
# choosing a node by hand asks first; "n" keeps everything, "y" turns fallback off, pool kept
printf '2\n1\nn\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"      # (the switches rewrote settings.env)
printf '2\n1\ny\n1\n\n0\n' | menu_input >/dev/null 2>&1
grep -q '^FALLBACK="off"' "$T/root/etc/settings.env"
[ ! -f "$STATE/enabled_proxy-unifi-fallback_timer" ]
[ -s "$T/root/etc/fallback.json" ]
# the wizard: 2 nodes (two-b, two-a), keep order, Balanced, return yes, turn on yes
printf '3\n1\n2\n2\n1\n\n2\ny\ny\n\n0\n' | menu_input > "$T/fb-wizard.out" 2>&1
grep -q '^FALLBACK="on"' "$T/root/etc/settings.env"
[ -f "$STATE/enabled_proxy-unifi-fallback_timer" ]
# reorder and remove through the menu
printf '3\n4\n2 1\n\n0\n' | menu_input >/dev/null 2>&1
python3 -c 'import json,sys; n=json.load(open(sys.argv[1]))["nodes"]; assert n[0]["meta"]["label"]=="two-a", n' "$T/root/etc/fallback.json"
printf '3\n5\n1\n\n0\n' | menu_input >/dev/null 2>&1            # Timing -> Fast
grep -q 'FB_INTERVAL="10"' "$T/root/etc/settings.env"
printf '3\n0\n' | menu_input > "$T/fb-menu.out" 2>&1
grep -q '^Fallback: ' "$T/fb-menu.out" && grep -q '8. Turn fallback on/off' "$T/fb-menu.out"
```

- [ ] **Step 2: Run** → FAIL (no "Fallback pool" in the main menu).
- [ ] **Step 3: Implement** the menus exactly as the spec shows (one item per line); `menu_fallback` header: `Fallback: ON — <preset name or custom> (every Ns, offline after N fails, online after N OK), returns to higher priority` (or `Fallback: off`), then `py "$MKFALLBACK" show ...`. Timing submenu offers `1. Fast 2. Balanced 3. Relaxed 4. Custom` (one per line); Custom asks each value with its range and re-asks on invalid input. Main menu block gets ` 3. Fallback pool` after ` 2. Subscriptions` and renumbers the rest; prompt `[0-22]`; the status block gains `Fallback:   on, #K of N active` / `off`.
- [ ] **Step 4: Run** lifecycle and the full suite → pass.
- [ ] **Step 5: Commit** — `git commit -am "Fallback pool menu and wizard; main menu item 3"`

### Task 8: Docs, full verification, push

**Files:**
- Modify: `README.md`, `README.ru.md` (menu table numbers; new "Subscriptions" and "Fallback pool" sections: what the pool does, the timing presets, that a switch resets connections), the spec (record the dropped direct commands under "Decided").

- [ ] **Step 1:** Update both READMEs; grep for old menu numbers (`menu 2`, `option 9`, `[0-21]`) and fix each.
- [ ] **Step 2:** `bash tests/run.sh` locally (Mac: expect only the 3 known Mac-only fails), `shellcheck -x src/proxy-unifi tests/*.sh install.sh`.
- [ ] **Step 3:** Negative controls on a scratch copy: revert each of (lock-free fetch, stale-apply refusal, stopped-service gate, recovering-higher wait) and confirm its test fails.
- [ ] **Step 4:** Commit, push `experimental`, wait for CI (Python 3.14 + 3.9), then one whole-branch review by a fresh reviewer.
