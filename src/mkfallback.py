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

Stdlib only (Python 3.9+).
"""

import argparse
import json
import os
import re
import sys
import tempfile

from proxylib import die, dispatch_subcommand

SCHEMA = 1
MAX_POOL = 10
_SUB_RE = re.compile(r"^[1-9][0-9]{0,2}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _write_json(path, value):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".write.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
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
    if not isinstance(nodes, list) or data.get("schema") != SCHEMA or len(nodes) > MAX_POOL \
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


def main():
    ap = argparse.ArgumentParser(description="proxy-unifi fallback pool")
    sub = ap.add_subparsers(dest="cmd")

    a = sub.add_parser("add")
    a.add_argument("--pool", required=True)
    a.add_argument("--sub", required=True)
    a.add_argument("--catalog", required=True)
    a.add_argument("--index", type=int, required=True)
    a.add_argument("--position", type=int, default=0)
    a.set_defaults(fn=cmd_add)

    r = sub.add_parser("remove")
    r.add_argument("--pool", required=True)
    r.add_argument("--position", type=int, required=True)
    r.set_defaults(fn=cmd_remove)

    o = sub.add_parser("order")
    o.add_argument("--pool", required=True)
    o.add_argument("positions", type=int, nargs="+")
    o.set_defaults(fn=cmd_order)

    c = sub.add_parser("count")
    c.add_argument("--pool", required=True)
    c.set_defaults(fn=cmd_count)

    d = sub.add_parser("drop-sub")
    d.add_argument("--pool", required=True)
    d.add_argument("--sub", required=True)
    d.set_defaults(fn=cmd_drop_sub)

    m = sub.add_parser("rematch")
    m.add_argument("--pool", required=True)
    m.add_argument("--sub", required=True)
    m.add_argument("--catalog", required=True)
    m.set_defaults(fn=cmd_rematch)

    dispatch_subcommand(ap)


if __name__ == "__main__":
    main()
