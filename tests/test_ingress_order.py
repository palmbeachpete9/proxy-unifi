#!/usr/bin/env python3
"""Check ingress INPUT ordering with an isolated firewall inventory model."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "proxy-unifi").read_text(encoding="utf-8")
INGRESS = ["-j", "PROXY_UNIFI_IN"]
WG = ["-j", "PROXY_UNIFI_WG"]
FOREIGN = ["-p", "tcp", "--dport", "41820", "-j", "ACCEPT"]
FOREIGN_OTHER = ["-p", "tcp", "--dport", "22", "-j", "DROP"]


def function(name, optional=False):
    start = re.search(r"^" + re.escape(name) + r"\(\)\s*\{[^\n]*", SOURCE, re.M)
    if start is None:
        if optional:
            return ""
        raise AssertionError("missing production helper: " + name)
    if re.search(r"\}\s*(?:#.*)?$", start.group()):
        return start.group()
    end = re.search(r"^\}", SOURCE[start.end():], re.M)
    if end is None:
        raise AssertionError("unterminated production helper: " + name)
    return SOURCE[start.start():start.end() + end.end()]


MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

path = Path(os.environ["FW_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
table = "filter"
if args[:1] == ["-t"]:
    table, args = args[1], args[2:]
operation, chain, *rule = args
chains = state[table]
code = 0
changed = False
if operation == "-S":
    if chain not in chains:
        code = 1
    else:
        if chain in ("INPUT", "FORWARD", "PREROUTING"):
            print("-P " + chain + " ACCEPT")
        for entry in chains[chain]:
            print("-A " + chain + " " + " ".join(entry))
elif operation == "-C":
    code = 0 if rule in chains.get(chain, []) else 1
elif operation == "-N":
    if chain in chains:
        code = 1
    else:
        chains[chain] = []
        changed = True
elif operation == "-I":
    if rule[:1] != ["1"]:
        raise SystemExit("test only supports insertion at the head")
    if state.get("fail_input_insert") and chain == "INPUT":
        code = 1
    else:
        chains[chain].insert(0, rule[1:])
        changed = True
elif operation == "-A":
    chains[chain].append(rule)
    changed = True
elif operation == "-F":
    chains[chain] = []
    changed = True
else:
    raise SystemExit("unexpected firewall operation: " + repr(args))
state["commands"].append([table] + args)
if changed:
    state["mutations"].append([table] + args)
path.write_text(json.dumps(state))
raise SystemExit(code)
'''


def inventory(input_rules, fail=False):
    return {
        "filter": {
            "INPUT": input_rules,
            "FORWARD": [["-i", "pu-veth0", "-j", "DROP"]],
            "PROXY_UNIFI_WG": [["-p", "udp", "--dport", "51821", "!", "-i", "lo", "-j", "DROP"]],
            "PROXY_UNIFI_IN": [
                ["-i", "pu-veth0", "-m", "mark", "--mark", "0x4000/0x4000", "-j", "ACCEPT"],
                ["-i", "pu-veth0", "-p", "icmp", "-j", "ACCEPT"],
                ["-i", "pu-veth0", "-j", "DROP"],
                ["-p", "tcp", "--dport", "41820", "-j", "DROP"],
                ["-p", "udp", "--dport", "41820", "-j", "DROP"],
            ],
        },
        "mangle": {
            "PREROUTING": [["-i", "pu-veth0", "-j", "PROXY_UNIFI_TP"]],
            "PROXY_UNIFI_TP": [
                ["-p", protocol, "-j", "TPROXY", "--on-ip", "169.254.77.1", "--on-port", "41820", "--tproxy-mark", "0x4000/0x4000"]
                for protocol in ("tcp", "udp")
            ],
        },
        "commands": [],
        "mutations": [],
        "fail_input_insert": fail,
    }


class IngressOrderingTests(unittest.TestCase):
    shells = [shell for shell in ("dash", "bash") if shutil.which(shell)]

    def run_case(self, shell, initial, command, fail=False):
        with tempfile.TemporaryDirectory(prefix="proxy-ingress-order-") as tmp:
            work = Path(tmp)
            state_path = work / "firewall.json"
            state_path.write_text(json.dumps(inventory(initial, fail)))
            mock = work / "iptables"
            mock.write_text(MOCK)
            mock.chmod(0o755)
            script = work / "case.sh"
            helpers = "\n".join(function(name, optional=(name == "_ingress_input_first")) for name in (
                "_fw_rule", "_fw_jump_first", "_fw_lock_one", "fw_lock",
                "_ingress_input_first", "_ingress_step", "_ingress_rules_ok", "_ingress_rules_add",
            ))
            script.write_text("""set -eu
INGRESS_PREF=10 INGRESS_VETH=pu-veth0 INGRESS_TABLE=7707
INGRESS_HOST_IP=169.254.77.1 INGRESS_PORT=41820 INGRESS_MARK=0x4000/0x4000
INGRESS_TP_CHAIN=PROXY_UNIFI_TP INGRESS_IN_CHAIN=PROXY_UNIFI_IN
FW_CHAIN=PROXY_UNIFI_WG WG_PORT=51821
load_settings() { :; }
have() { command -v "$1" >/dev/null 2>&1; }
err() { printf '%s\\n' "$*" >&2; }
_ipv6_enabled() { return 1; }
_ingress_rt_ok() { return 0; }
_ingress_rt_add() { return 0; }
ip() {
    case "$*" in
        'rule show') echo '10: from all iif pu-veth0 lookup 7707' ;;
        'route show table 7707') echo 'local default dev lo' ;;
        'route replace local 0.0.0.0/0 dev lo table 7707') : ;;
        *) printf 'unexpected ip call: %s\\n' "$*" >&2; return 1 ;;
    esac
}
""" + helpers + "\n" + command + "\n")
            env = dict(os.environ, FW_STATE=str(state_path), PATH=str(work) + os.pathsep + os.environ["PATH"])
            result = subprocess.run([shutil.which(shell), str(script)], env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            return result, json.loads(state_path.read_text())

    def test_correct_ingress_order_is_left_alone(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                initial = [INGRESS, WG, FOREIGN, FOREIGN_OTHER]
                result, state = self.run_case(shell, initial, "fw_lock; _ingress_rules_ok || _ingress_rules_add")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state["filter"]["INPUT"], initial)
                self.assertEqual(state["mutations"], [])

    def test_owned_wireguard_guard_may_precede_ingress(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                initial = [WG, INGRESS, FOREIGN]
                result, state = self.run_case(shell, initial, "_ingress_rules_ok || _ingress_rules_add")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state["filter"]["INPUT"], initial)
                self.assertEqual(state["mutations"], [])

    def test_missing_jump_is_repaired(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, state = self.run_case(shell, [WG, FOREIGN, FOREIGN_OTHER], "_ingress_rules_ok || _ingress_rules_add")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state["filter"]["INPUT"], [INGRESS, WG, FOREIGN, FOREIGN_OTHER])

    def test_foreign_rule_before_ingress_is_not_reported_healthy(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, state = self.run_case(shell, [FOREIGN, INGRESS], "_ingress_rules_ok")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state["mutations"], [])

    def test_reconcile_repairs_order_and_preserves_foreign_rules(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, state = self.run_case(shell, [FOREIGN, INGRESS, FOREIGN_OTHER], "fw_lock; _ingress_rules_ok || _ingress_rules_add")
                self.assertEqual(result.returncode, 0, result.stderr)
                current = state["filter"]["INPUT"]
                self.assertEqual(current, [INGRESS, WG, FOREIGN, INGRESS, FOREIGN_OTHER])
                self.assertFalse(any(command[1] == "-D" for command in state["commands"]))

    def test_explicit_repair_checks_existing_jump_order(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, state = self.run_case(shell, [WG, FOREIGN, INGRESS], "_ingress_rules_add")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state["filter"]["INPUT"], [INGRESS, WG, FOREIGN, INGRESS])

    def test_wireguard_guard_repair_does_not_hide_stale_ingress_order(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, state = self.run_case(shell, [FOREIGN, INGRESS], "fw_lock; _ingress_rules_ok")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state["filter"]["INPUT"], [WG, FOREIGN, INGRESS])

    def test_failed_order_repair_returns_failure(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                initial = [WG, FOREIGN, INGRESS]
                result, state = self.run_case(shell, initial, "_ingress_rules_ok || _ingress_rules_add", fail=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state["filter"]["INPUT"], initial)


if __name__ == "__main__":
    unittest.main()
