#!/usr/bin/env python3
"""Run a core validator with a hard timeout, resource limits, and dropped uid.

The proxy CLI is root because it manages systemd/firewall state. Provider JSON
must not make the root CLI execute Xray validation with unrestricted access.
This helper receives only non-secret paths/flags and execs the validator under
the same dedicated account used by the service.
"""

import argparse
import os
import pwd
import resource
import signal
import subprocess
import sys
import time


def fail(message):
    sys.stderr.write("safeexec: %s\n" % message)
    return 2


def _limit(kind, value):
    _soft, hard = resource.getrlimit(kind)
    target = value if hard == resource.RLIM_INFINITY else min(value, hard)
    # Some kernels reject lowering soft+hard in one call when the current soft
    # value is above the requested new hard. Lower soft first, then hard.
    resource.setrlimit(kind, (target, hard))
    resource.setrlimit(kind, (target, target))


def _group_rss_bytes(pgid):
    """Total Linux resident set for members of the validator process group."""
    if not sys.platform.startswith("linux"):
        return 0
    total = 0
    try:
        entries = os.listdir("/proc")
    except OSError:
        return 0
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry, "r", encoding="ascii") as stat_file:
                fields = stat_file.read().rsplit(")", 1)[1].split()
            if len(fields) < 3 or int(fields[2]) != pgid:
                continue
            with open("/proc/%s/status" % entry, "r", encoding="ascii") as status:
                for line in status:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1]) * 1024
                        break
        except (OSError, ValueError, IndexError):
            continue
    return total


def _kill_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--memory-mb", type=int, default=256)
    parser.add_argument("--fsize-mb", type=int, default=16)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return fail("no command supplied")
    if not 1 <= args.timeout <= 300:
        return fail("timeout is out of range")
    if not 64 <= args.memory_mb <= 4096:
        return fail("memory limit is out of range")
    if not 1 <= args.fsize_mb <= 1024:
        return fail("file-size limit is out of range")
    try:
        account = pwd.getpwnam(args.user)
    except KeyError:
        return fail("service account '%s' does not exist" % args.user)

    def prepare():
        os.setsid()
        os.umask(0o077)
        _limit(resource.RLIMIT_CORE, 0)
        _limit(resource.RLIMIT_NOFILE, 1024)
        _limit(resource.RLIMIT_FSIZE, args.fsize_mb * 1024 * 1024)
        if hasattr(resource, "RLIMIT_CPU"):
            _limit(resource.RLIMIT_CPU, max(1, int(args.timeout) + 1))
        if os.geteuid() == 0:
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        elif os.geteuid() != account.pw_uid:
            raise PermissionError("cannot switch to requested service account")

    try:
        proc = subprocess.Popen(command, preexec_fn=prepare)
    except (OSError, subprocess.SubprocessError) as exc:
        return fail("could not start validator: %s" % exc)

    def forward(signum, _frame):
        _kill_group(proc.pid, signum)
    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    deadline = time.monotonic() + args.timeout
    memory_limit = args.memory_mb * 1024 * 1024
    reason = ""
    while proc.poll() is None:
        if time.monotonic() >= deadline:
            reason = "validator exceeded %.1fs timeout" % args.timeout
            break
        if _group_rss_bytes(proc.pid) > memory_limit:
            reason = "validator exceeded %d MB resident-memory limit" % args.memory_mb
            break
        time.sleep(0.05)
    if not reason:
        return proc.returncode
    _kill_group(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    _kill_group(proc.pid, signal.SIGKILL)
    proc.wait()
    sys.stderr.write("safeexec: %s\n" % reason)
    return 124 if "timeout" in reason else 125


if __name__ == "__main__":
    sys.exit(main())
