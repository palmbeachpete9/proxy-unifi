#!/usr/bin/env python3
"""
mkfallback.py - the fallback pool and its watchdog's decisions for proxy-unifi.

The pool is an ordered list (first = priority 1) of subscription nodes kept in
fallback.json. The shell CLI does the I/O a check or a switch needs; this module
validates and edits the pool and decides, for one watchdog run, what to check
and where to switch, calling back into the CLI for both.

Subcommands (every one takes --pool FILE):
  add --sub ID --catalog F --index N [--position P]
  remove --position P          order P1 P2 ...          count
  drop-sub --sub ID            rematch --sub ID --catalog F
  run   --state F --last F --selected F --cli PATH --down N --up N --return on|off --timeout N
  test  --state F --subs-dir D --cli PATH --timeout N
  show | status [--short]  --state F --last F --selected F --subs-dir D

The CLI callbacks a run uses:
  PATH _fallback-probe SUB ID live|core          -> "ok MS" or "fail ERROR"
  PATH _fallback-apply SUB ID EXPECTED           -> exit 0 once switched

Stdlib only (Python 3.9+).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import mksub
from proxylib import die, dispatch_subcommand

SCHEMA = 1
MAX_POOL = 10
_SUB_RE = re.compile(r"^[1-9][0-9]{0,2}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _write_json(path, value):
    mksub._atomic_write_text(path, json.dumps(value, ensure_ascii=False, sort_keys=True))


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
    if not isinstance(nodes, list) or data.get("schema") != SCHEMA or len(nodes) > MAX_POOL \
            or not all(_valid_entry(n) for n in nodes):
        die("the fallback pool file is malformed")
    keys = [(n["sub"], n["meta"]["id"]) for n in nodes]
    if len(set(keys)) != len(keys):
        die("the fallback pool file is malformed")
    return nodes


def save_pool(path, nodes):
    keys = [(n["sub"], n["meta"]["id"]) for n in nodes]
    if len(set(keys)) != len(keys):                    # never write what load_pool rejects
        die("the fallback pool would list a node twice")
    _write_json(path, {"schema": SCHEMA, "nodes": nodes})


def cmd_add(args):
    if not _SUB_RE.match(args.sub):
        die("invalid subscription id")
    nodes = load_pool(args.pool)
    if len(nodes) >= MAX_POOL:
        die("the pool holds at most %d nodes" % MAX_POOL)
    nd = next((n for n in mksub._load(args.catalog)["nodes"] if n["n"] == args.index), None)
    if nd is None:
        die("no node #%d in this subscription" % args.index)
    if not nd.get("recognized"):
        die("node #%d is not supported" % args.index)
    if any(e["sub"] == args.sub and e["meta"]["id"] == nd["id"] for e in nodes):
        die("node #%d is already in the pool" % args.index)
    position = args.position or len(nodes) + 1
    if not 1 <= position <= len(nodes) + 1:
        die("position must be 1-%d" % (len(nodes) + 1))
    nodes.insert(position - 1, {"sub": args.sub, "meta": mksub._selection_meta(nd), "missing": False})
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
    """Re-point the pool entries of one refreshed subscription; returns nodes.

    Entries whose node is still there claim it first; then the others may take
    a look-alike, each new node at most once. An entry left without one is
    marked missing (and keeps its old id, which is no longer in the catalog)."""
    ids = {nd["id"] for nd in cat.get("nodes", []) if nd.get("recognized")}
    mine = [e for e in nodes if e["sub"] == sub]
    claimed = {e["meta"]["id"] for e in mine if e["meta"]["id"] in ids}
    for entry in mine:
        if entry["meta"]["id"] in ids:
            entry["missing"] = False
            continue
        found = mksub.match_node(cat, entry["meta"])
        if found is None or found[0]["id"] in claimed:
            entry["missing"] = True
        else:
            claimed.add(found[0]["id"])
            entry["meta"], entry["missing"] = mksub._selection_meta(found[0]), False
    return nodes


def cmd_rematch(args):
    if not os.path.exists(args.pool):
        return
    save_pool(args.pool, rematch(load_pool(args.pool), args.sub, mksub._load(args.catalog)))


# ---- the watchdog --------------------------------------------------------
def _key(entry):
    return "%s:%s" % (entry["sub"], entry["meta"]["id"])


def _read_json(path):
    """A small state file's JSON object; {} when it is missing or unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def load_state(path):
    """The watchdog's counters; missing or malformed means a fresh start."""
    state = _read_json(path)
    if state.get("schema") == SCHEMA and isinstance(state.get("nodes"), dict) \
            and isinstance(state.get("rot"), int):
        state.setdefault("tunnel", "ok")
        state.setdefault("note", "")
        return state
    return {"schema": SCHEMA, "nodes": {}, "rot": 0, "tunnel": "ok", "note": ""}


def _record(state, entry, ok, ms, err, now, streaks=True):
    node = state["nodes"].setdefault(_key(entry), {"fails": 0, "oks": 0, "at": 0, "ms": 0, "err": ""})
    if not ok and not node.get("err"):
        node["since"] = now
    node.update(at=now, ms=ms if ok else 0, err="" if ok else (err or "no answer"))
    if streaks:
        if ok:
            node["oks"], node["fails"] = node["oks"] + 1, 0
        else:
            node["fails"], node["oks"] = node["fails"] + 1, 0
    return node


def _switch_to_first_online(pool, state, order, frm, probe, apply, now, reason, log):
    if state["note"]:
        # ponytail: nothing answered last time (the WAN may be down), so check one
        # candidate per run, in turn, instead of starting a test core for each.
        order = [order[state["rot"] % len(order)]]
        state["rot"] += 1
    for i in order:
        ok, ms, err = probe(i, "core")
        _record(state, pool[i], ok, ms, err, now)
        if not ok:
            continue
        done, why = apply(i, reason)
        if done:
            state["note"], state["tunnel"] = "", "ok"
            log.append("switch %s#%d (%s)" % ("%s -> " % frm if frm else "to ", i + 1, reason))
            return True
        _record(state, pool[i], False, 0, "could not apply: %s" % why, now)
    if not state["note"]:
        log.append("no pool node online")
    state["note"] = "no pool node online"
    return False


def run_once(pool, state, active, cfg, probe, apply, now):
    """One watchdog run (the spec's "A run"). Mutates state; returns log lines.

    pool: load_pool() entries; active: (sub, node id) or None;
    cfg: {"down": n, "up": n, "ret": bool};
    probe(index, "live"|"core") -> (ok, ms, err), "nolive" when there is no live path;
    apply(index, reason) -> (ok, err).
    """
    log = []
    keys = {_key(e) for e in pool}
    state["nodes"] = {k: v for k, v in state["nodes"].items() if k in keys}
    usable = [i for i, e in enumerate(pool) if not e.get("missing")]
    if len(usable) < 2:
        return log
    apos = next((i for i in usable
                 if active and (pool[i]["sub"], pool[i]["meta"]["id"]) == tuple(active)), None)
    if apos is None:
        _switch_to_first_online(pool, state, usable, "", probe, apply, now,
                                "fallback took over: the active node was not in the pool", log)
        return log
    ok, ms, err = probe(apos, "live")
    if ok:
        state["tunnel"] = "ok"
    else:
        live_err = err
        ok, ms, err = probe(apos, "core")
        # The node answers but the tunnel does not: a UniFi/core problem, not the node's.
        state["tunnel"] = "failing" if ok and live_err != "nolive" else "ok"
    node = _record(state, pool[apos], ok, ms, err, now)
    if node["fails"] >= cfg["down"]:
        others = [i for i in usable if i != apos]
        _switch_to_first_online(pool, state, others, "#%d" % (apos + 1), probe, apply, now,
                                "#%d offline after %d failed checks: %s" % (apos + 1, node["fails"], err),
                                log)
        return log
    state["note"] = ""
    higher = [i for i in usable if i < apos]
    if not cfg["ret"] or not higher:
        return log
    # ponytail: one return check per run, in turn, bounds the cost to one test core per run.
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
    reason = "#%d back online" % (target + 1)
    done, why = apply(target, reason)
    if done:
        state["tunnel"] = "ok"         # judged on the core that was just replaced
        log.append("switch #%d -> #%d (%s)" % (apos + 1, target + 1, reason))
    else:
        _record(state, pool[target], False, 0, "could not apply: %s" % why, now)
    return log


# ---- CLI around the watchdog ---------------------------------------------
class Stale(Exception):
    """The CLI refused a switch: the user changed things while the run checked."""


def _active(path):
    meta = _read_json(path)
    sub, nid = meta.get("sub"), meta.get("id")
    if isinstance(sub, str) and _SUB_RE.match(sub) and isinstance(nid, str) and _ID_RE.match(nid):
        return (sub, nid)
    return None


def _cli(args, timeout):
    """(exit status, output) of a CLI callback. Output goes through a file, not a
    pipe: a process the callback leaves running must not hold this run open."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as out:
        done = subprocess.run(args, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
        out.seek(0)
        return done.returncode, out.read(65536)


def _cli_probe(cli, entry, kind, timeout):
    try:
        _, out = _cli([cli, "_fallback-probe", entry["sub"], entry["meta"]["id"], kind], timeout * 3 + 40)
    except (OSError, subprocess.SubprocessError):
        return False, 0, "check did not finish"
    word, _, rest = (out.strip().splitlines() or [""])[0].partition(" ")
    if word == "ok" and rest.isdigit():
        return True, int(rest), ""
    if word == "fail" and rest:
        return False, 0, rest[:80]
    return False, 0, "check did not finish"


def _cli_apply(cli, entry, expected):
    try:
        rc, out = _cli([cli, "_fallback-apply", entry["sub"], entry["meta"]["id"], expected or "-"], 600)
    except (OSError, subprocess.SubprocessError):
        return False, "switch did not finish"
    lines = [line for line in out.splitlines() if line.strip()]
    why = lines[-1][:80] if lines else "exit %d" % rc
    if rc == 3:
        raise Stale(why)
    return rc == 0, why


def _label(entry):
    return mksub.clean(entry["meta"].get("label", ""), 24) or "(no label)"


def cmd_run(args):
    pool = load_pool(args.pool)
    state = load_state(args.state)
    active = _active(args.selected)
    cfg = {"down": args.down, "up": args.up, "ret": args.ret == "on"}
    now = int(time.time())
    try:
        log = run_once(pool, state, active, cfg,
                       lambda i, kind: _cli_probe(args.cli, pool[i], kind, args.timeout),
                       lambda i, _reason: _cli_apply(args.cli, pool[i], active[1] if active else ""),
                       now)
    except Stale as e:
        log = ["skipped: %s" % e]
    _write_json(args.state, state)
    for line in log:
        if line.startswith("switch "):
            _write_json(args.last, {"at": now, "line": line[len("switch "):]})
        # "<5>": journald records the line at notice level, past the unit's LogLevelMax.
        sys.stdout.write("<5>fallback: %s\n" % line)


def _status_text(entry, node):
    if entry.get("missing"):
        return "missing from subscription"
    if not node or not node.get("at"):
        return "not checked yet"
    if node.get("err"):
        return "offline since %s (%s)" % (mksub.when(node.get("since") or node["at"]), node["err"][:40])
    text = "online  %4d ms" % node.get("ms", 0)
    # Nodes below the active one are not checked while it works: say how old this is.
    if time.time() - node["at"] > 300:
        text += " (checked %s)" % mksub.when(node["at"])
    return text


TOO_FEW = "inactive: fewer than 2 pool nodes are available"


def _too_few(pool):
    return sum(not e.get("missing") for e in pool) < 2


def _row(subs_dir, pos, entry):
    return "  %d. %s %s %-8s" % (pos, mksub.pad("[%s]" % mksub.sub_name(subs_dir, entry["sub"], 16), 18),
                                  mksub.pad(_label(entry), 24),
                                  mksub.clean(entry["meta"].get("scheme", ""), 8))


def cmd_test(args):
    pool = load_pool(args.pool)
    state = load_state(args.state)
    now = int(time.time())
    for pos, entry in enumerate(pool, 1):
        if not entry.get("missing"):
            ok, ms, err = _cli_probe(args.cli, entry, "core", args.timeout)
            _record(state, entry, ok, ms, err, now, streaks=False)
        sys.stdout.write("%s %s\n" % (_row(args.subs_dir, pos, entry),
                                      _status_text(entry, state["nodes"].get(_key(entry)))))
        sys.stdout.flush()
    _write_json(args.state, state)


def _last(path):
    last = _read_json(path)
    return last if isinstance(last.get("at"), int) and isinstance(last.get("line"), str) else None


def cmd_show(args):
    pool = load_pool(args.pool)
    state = load_state(args.state)
    active = _active(args.selected)
    if not pool:
        sys.stdout.write("  (the pool is empty: set one up with 1)\n")
    for pos, entry in enumerate(pool, 1):
        mark = "   <- active" if active == (entry["sub"], entry["meta"]["id"]) else ""
        sys.stdout.write("%s %s%s\n" % (_row(args.subs_dir, pos, entry),
                                        _status_text(entry, state["nodes"].get(_key(entry))), mark))
    if state.get("tunnel") == "failing":
        sys.stdout.write("  tunnel check failing; the node answers through a test core\n")
    if state.get("note"):
        sys.stdout.write("  %s\n" % state["note"])
    if pool and _too_few(pool):
        sys.stdout.write("  fallback is %s\n" % TOO_FEW)
    last = _last(args.last)
    if last:
        sys.stdout.write("Last switch: %s  %s\n" % (mksub.when(last["at"]), last["line"][:100]))


def cmd_status(args):
    pool = load_pool(args.pool)
    state = load_state(args.state)
    active = _active(args.selected)
    pos = next((i for i, e in enumerate(pool, 1) if active == (e["sub"], e["meta"]["id"])), 0)
    if pos:
        text = "active #%d of %d" % (pos, len(pool))
        if not args.short:
            text += " ([%s] %s)" % (mksub.sub_name(args.subs_dir, pool[pos - 1]["sub"], 16), _label(pool[pos - 1]))
    else:
        text = "the active node is not in the pool (%d nodes)" % len(pool)
    if _too_few(pool):
        text += ", " + TOO_FEW
    last = _last(args.last)
    if last:
        text += ", last switch %s" % mksub.when(last["at"])
    if state.get("tunnel") == "failing":
        text += ", tunnel check failing"
    if state.get("note"):
        text += ", %s" % state["note"]
    sys.stdout.write(text + "\n")


def main():
    ap = argparse.ArgumentParser(description="proxy-unifi fallback pool")
    sub = ap.add_subparsers(dest="cmd")
    pool = argparse.ArgumentParser(add_help=False)
    pool.add_argument("--pool", required=True)

    a = sub.add_parser("add", parents=[pool])
    a.add_argument("--sub", required=True)
    a.add_argument("--catalog", required=True)
    a.add_argument("--index", type=int, required=True)
    a.add_argument("--position", type=int, default=0)
    a.set_defaults(fn=cmd_add)

    r = sub.add_parser("remove", parents=[pool])
    r.add_argument("--position", type=int, required=True)
    r.set_defaults(fn=cmd_remove)

    o = sub.add_parser("order", parents=[pool])
    o.add_argument("positions", type=int, nargs="+")
    o.set_defaults(fn=cmd_order)

    sub.add_parser("count", parents=[pool]).set_defaults(fn=cmd_count)

    d = sub.add_parser("drop-sub", parents=[pool])
    d.add_argument("--sub", required=True)
    d.set_defaults(fn=cmd_drop_sub)

    m = sub.add_parser("rematch", parents=[pool])
    m.add_argument("--sub", required=True)
    m.add_argument("--catalog", required=True)
    m.set_defaults(fn=cmd_rematch)

    r = sub.add_parser("run", parents=[pool])
    for name in ("--state", "--last", "--selected", "--cli"):
        r.add_argument(name, required=True)
    r.add_argument("--down", type=int, required=True)
    r.add_argument("--up", type=int, required=True)
    r.add_argument("--return", dest="ret", choices=("on", "off"), required=True)
    r.add_argument("--timeout", type=int, required=True)
    r.set_defaults(fn=cmd_run)

    t = sub.add_parser("test", parents=[pool])
    for name in ("--state", "--subs-dir", "--cli"):
        t.add_argument(name, required=True)
    t.add_argument("--timeout", type=int, required=True)
    t.set_defaults(fn=cmd_test)

    for name, fn in (("show", cmd_show), ("status", cmd_status)):
        v = sub.add_parser(name, parents=[pool])
        for opt in ("--state", "--last", "--selected", "--subs-dir"):
            v.add_argument(opt, required=True)
        v.set_defaults(fn=fn)
    sub.choices["status"].add_argument("--short", action="store_true")  # the main menu: no name

    dispatch_subcommand(ap)


if __name__ == "__main__":
    main()
