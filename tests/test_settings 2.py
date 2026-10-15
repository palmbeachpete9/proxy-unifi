#!/usr/bin/env python3
"""Check that menu mutations merge their arguments into locked current state."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "src" / "proxy-unifi").read_text()


def function(name):
    lines = SOURCE.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(name + "() {"))
    if lines[start].rstrip().endswith("}"):
        return lines[start]
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "}" and lines[i].startswith("}"))
    return "".join(lines[start:end + 1])


FUNCTIONS = "".join(function(name) for name in (
    "settings_defaults", "_uint", "_in_range", "load_settings", "atomic_write",
    "save_settings", "locked_call", "_fallback_timing_ok", "fallback_set_timing",
    "fallback_install", "fallback_toggle_return", "fallback_switch", "fallback_set",
    "sub_set_interval", "_sub_check_ua", "sub_set_user_agent",
))

COMMITTED = {
    "WG_LISTEN": "127.0.0.2", "WG_PORT": "51822", "WG_MTU": "1400",
    "WG_KEEPALIVE": "30", "INGRESS": "userspace", "LAN_ROUTE": "off",
    "XRAY_ADDR": "10.8.0.1/32", "UNIFI_ADDR": "10.8.0.2/32",
    "INNER_DNS": "1.1.1.1", "LOGLEVEL": "error", "PING_MODE": "head",
    "PING_URL": "https://example.com/health", "PING_TIMEOUT": "9",
    "SUB_REFRESH_HOURS": "12", "SUB_USER_AGENT": "Current/1.0", "FALLBACK": "on",
    "FB_INTERVAL": "40", "FB_DOWN": "4", "FB_UP": "6", "FB_TIMEOUT": "8",
    "FB_RETURN": "off",
}


def settings(path):
    result = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value.strip('"')
    return result


class LockedSettingsTests(unittest.TestCase):
    def exercise(self, shell, action, arguments, changes, omitted=()):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            current = {key: value for key, value in COMMITTED.items() if key not in omitted}
            (root / "committed.env").write_text("".join('%s="%s"\n' % item for item in current.items()))
            (root / "settings.env").write_text('WG_PORT="51821"\nINNER_DNS="9.9.9.9"\n')
            (root / "draft").write_text('{"fixture": true}\n')
            script = r'''
set -eu
ETC_DIR="$WORK"; SETTINGS="$WORK/settings.env"; FB_POOL="$WORK/pool.json"
SUB_USER_AGENT_DEFAULT=Happ/2.0; SUB_USER_AGENT_LEGACY_DEFAULT=proxy-unifi/1.1
MKFALLBACK=/unused; FB_SERVICE_NAME=fixture; TXN_DIR=""
_FROM_SUB=1; _KEEP_FALLBACK=1; _QUIET=1; _AUTO_REFRESH=1
py() { if [ "${1:-}" = "$MKFALLBACK" ]; then return 0; fi; python3 "$@"; }
fatal() { echo "$*" >&2; exit 9; }; c_grn() { :; }; c_ylw() { :; }
fallback_timing_text() { :; }; systemctl() { :; }
enable_refresh_timer() { printf '%s' "$SUB_REFRESH_HOURS" > "$WORK/timer"; }
write_fallback_timer() { printf '%s' "$FB_INTERVAL" > "$WORK/timer"; }
acquire_lock() { cp "$WORK/committed.env" "$SETTINGS"; }
release_lock() { :; }; recover_transaction() { :; }; on_exit() { :; }
txn_begin() { TXN_DIR=fixture; }; txn_commit() { TXN_DIR=""; }; txn_rollback() { exit 8; }
sub_ids() { :; }; sub_refresh_invalidate() { :; }
'''
            script += FUNCTIONS
            script += r'''
settings_defaults
load_settings
locked_call "$@"
[ "$_FROM_SUB:$_KEEP_FALLBACK:$_QUIET:$_AUTO_REFRESH" = "1:1:1:1" ]
'''
            script_path = root / "action.sh"
            script_path.write_text(script)
            env = dict(os.environ, WORK=work)
            args = [str(root / "draft") if arg == "DRAFT" else arg for arg in arguments]
            result = subprocess.run([shell, str(script_path), action, *args], env=env,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = dict(COMMITTED)
            expected.update(changes)
            self.assertEqual(settings(root / "settings.env"), expected)

    def test_only_requested_fields_change_after_waiting_for_lock(self):
        cases = (
            ("sub_set_interval", ["24"], {"SUB_REFRESH_HOURS": "24"}),
            ("sub_set_user_agent", ["Requested/2.0"], {"SUB_USER_AGENT": "Requested/2.0"}),
            ("fallback_set_timing", ["50", "5", "7", "10"],
             {"FB_INTERVAL": "50", "FB_DOWN": "5", "FB_UP": "7", "FB_TIMEOUT": "10"}),
            ("fallback_toggle_return", [], {"FB_RETURN": "on"}),
            ("fallback_switch", ["off"], {"FALLBACK": "off"}),
            ("fallback_switch", ["on"], {"FALLBACK": "on"}),
            ("fallback_install", ["DRAFT", "50", "5", "7", "10", "on"],
             {"FB_INTERVAL": "50", "FB_DOWN": "5", "FB_UP": "7", "FB_TIMEOUT": "10", "FB_RETURN": "on"}),
        )
        for shell in dict.fromkeys(filter(None, (shutil.which("sh"), shutil.which("dash")))):
            for action, arguments, changes in cases:
                with self.subTest(shell=shell, action=action, arguments=arguments):
                    self.exercise(shell, action, arguments, changes)

    def test_absent_current_keys_use_defaults_instead_of_stale_globals(self):
        for shell in dict.fromkeys(filter(None, (shutil.which("sh"), shutil.which("dash")))):
            with self.subTest(shell=shell):
                self.exercise(shell, "sub_set_interval", ["24"],
                              {"SUB_REFRESH_HOURS": "24", "INNER_DNS": "8.8.8.8"},
                              omitted=("INNER_DNS",))


if __name__ == "__main__":
    unittest.main()
