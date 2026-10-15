#!/usr/bin/env python3
"""JSON imports validate and persist the same bounded private input bytes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / "src" / "proxy-unifi").read_text()


def function(name):
    lines = SOURCE.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(name + "() {"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}\n")
    return "".join(lines[start:end + 1])


FUNCTIONS = "".join(function(name) for name in ("atomic_write", "cmd_import_json", "sub_forget_manual"))
PROFILE = {"inbounds": [{"protocol": "socks", "tag": "entry", "port": 10808}],
           "outbounds": [{"protocol": "blackhole", "tag": "block"},
                         {"protocol": "freedom", "tag": "direct"}],
           "routing": {"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "block"}]}}
CHANGED = dict(PROFILE, routing={"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}]})
PRELUDE = r'''
set -eu
RUN_DIR="$WORK/run"; mkdir -m 700 "$RUN_DIR"
POOL_SRC="$WORK/stored.json"; OUTBOUND_LINK="$WORK/link"; AWG_SELECTED="$WORK/awg-selected"
SUB_SELECTED="$WORK/selected"; SUB_SELECTED_META="$WORK/selected.json"; TXN_DIR=""
_FROM_SUB=1; _QUIET=1; ORIGINAL_FILE="$WORK/input.json"; MKJSON="$SRC/mkjson.py"
py() { python3 "$@"; }; fatal() { echo "$*" >&2; exit 9; }; ensure_run_dir() { [ -d "$RUN_DIR" ]; }
load_settings() { :; }; save_settings() { :; }
txn_begin() { : > "$WORK/transaction"; TXN_DIR=fixture; }; txn_commit() { TXN_DIR=""; }
restart_service() { : > "$WORK/restarted"; }
_build_pool() {
    : > "$WORK/build-started"
    [ "$1" != "$ORIGINAL_FILE" ] || exit 7
    [ "$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$1")" = 0o600 ] || exit 7
    py "$MKJSON" socksconfig --profile "$1" --socks-port 10810 > "$WORK/rendered.json" || exit 7
    cp "$1" "$WORK/validated.json"
    case "${CHANGE:-replace}" in
        replace) cp "$WORK/changed.json" "$ORIGINAL_FILE";;
        invalid) printf invalid > "$ORIGINAL_FILE";;
        remove) rm "$ORIGINAL_FILE";;
        none) :;;
    esac
}
'''


class ImportSnapshotTests(unittest.TestCase):
    def shells(self):
        return tuple(dict.fromkeys(filter(None, (shutil.which("dash"), shutil.which("bash")))))

    def exercise(self, shell, script, size=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            text = json.dumps(PROFILE)
            if size is not None:
                text += " " * (size - len(text))
            (root / "input.json").write_text(text)
            (root / "changed.json").write_text(json.dumps(CHANGED))
            (root / "case.sh").write_text(PRELUDE + FUNCTIONS + "\n" + script)
            done = subprocess.run([shell, str(root / "case.sh")], capture_output=True, text=True,
                                  env=dict(os.environ, WORK=tmp, SRC=str(REPO / "src")))
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            return {p.name: p.read_text() for p in root.iterdir() if p.is_file()}

    def test_source_replacement_removal_or_invalid_edit_cannot_change_stored_input(self):
        for shell in self.shells():
            for change in ("replace", "remove", "invalid", "none"):
                with self.subTest(shell=shell, change=change):
                    files = self.exercise(shell, 'CHANGE=%s\ncmd_import_json "$ORIGINAL_FILE"\n' % change)
                    self.assertEqual(files["stored.json"], files["validated.json"])
                    self.assertEqual(json.loads(files["stored.json"]), PROFILE)
                    self.assertEqual(json.loads(files["rendered.json"])["routing"], PROFILE["routing"])
                    self.assertIn("restarted", files)

    def test_existing_saved_source_can_be_imported_through_its_own_path(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                files = self.exercise(shell, r'''
mv "$ORIGINAL_FILE" "$POOL_SRC"; ORIGINAL_FILE="$POOL_SRC"
cmd_import_json "$ORIGINAL_FILE"
''')
                self.assertEqual(files["stored.json"], files["validated.json"])

    def test_size_budget_is_checked_before_transaction_or_build(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                files = self.exercise(shell, r'''
if ( cmd_import_json "$ORIGINAL_FILE" ); then result=0; else result=$?; fi
[ "$result" = 9 ] && [ ! -e "$WORK/transaction" ] && [ ! -e "$WORK/build-started" ] && [ ! -e "$POOL_SRC" ]
''', size=2000001)
                self.assertNotIn("restarted", files)

    def test_exact_budget_input_remains_accepted(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                files = self.exercise(shell, 'CHANGE=none\ncmd_import_json "$ORIGINAL_FILE"\n', size=2000000)
                self.assertEqual(len(files["stored.json"]), 2000000)
                self.assertEqual(files["stored.json"], files["validated.json"])

    def test_missing_empty_or_unreadable_input_changes_no_active_state(self):
        for shell in self.shells():
            for prepare in ('rm "$ORIGINAL_FILE"', ': > "$ORIGINAL_FILE"',
                            'rm "$ORIGINAL_FILE"; mkdir "$ORIGINAL_FILE"'):
                with self.subTest(shell=shell, prepare=prepare):
                    self.exercise(shell, prepare + r'''
if ( cmd_import_json "$ORIGINAL_FILE" ); then result=0; else result=$?; fi
[ "$result" = 9 ] && [ ! -e "$WORK/transaction" ] && [ ! -e "$WORK/build-started" ] && [ ! -e "$POOL_SRC" ]
''')


if __name__ == "__main__":
    unittest.main()
