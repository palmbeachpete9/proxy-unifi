#!/usr/bin/env python3
"""Provider profiles cannot enable routing telemetry; parser-only fixtures."""

import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import mkjson
import mksub


def profile():
    return {
        "inbounds": [{"protocol": "socks", "tag": "socks", "port": 10808},
                     {"protocol": "http", "tag": "http", "port": 10809}],
        "outbounds": [{"protocol": "blackhole", "tag": "block"}],
        "routing": {"rules": [{"type": "field", "network": "tcp,udp",
                                "outboundTag": "block"}]},
    }


class ProfileWebhookTests(unittest.TestCase):
    def rejects(self, cfg):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                mkjson.validate_profile(cfg)
        self.assertEqual(error.exception.code, 2)

    def test_disabled_absent_null_and_empty_objects_are_preserved(self):
        mkjson.validate_profile(profile())
        for value in (None, {}):
            with self.subTest(value=value):
                cfg = profile()
                cfg["routing"]["rules"][0]["webhook"] = value
                original = copy.deepcopy(cfg)
                mkjson.validate_profile(cfg)
                self.assertEqual(mkjson.sanitize_provider(cfg)["routing"], cfg["routing"])
                self.assertEqual(cfg, original)

    def test_public_webhook_is_rejected_as_an_unsupported_feature(self):
        for value in ({"url": "https://telemetry.example/events"},
                      {"url": "https://telemetry.example/events", "deduplication": 60,
                       "headers": {"X-Client": "fixture"}},
                      {"url": ""}, {"headers": {}}, "", False, [], [None], 1):
            with self.subTest(value=value):
                cfg = profile()
                cfg["routing"]["rules"][0]["webhook"] = value
                self.rejects(cfg)

    def test_noncanonical_semantic_spellings_are_rejected(self):
        for field in ("Webhook", "WEBHOOK", "webHook", "webhoo\u212a"):
            with self.subTest(field=field):
                cfg = profile()
                cfg["routing"]["rules"][0][field] = {
                    "url": "https://telemetry.example/events"}
                self.rejects(cfg)

    def test_data_map_header_names_remain_data(self):
        cfg = profile()
        cfg["routing"]["rules"][0]["attrs"] = {"Webhook": "fixture", "WEBHOOK": "data"}
        cfg["outbounds"][0]["streamSettings"] = {
            "network": "ws", "wsSettings": {"headers": {
                "Webhook": "ordinary header", "webhook": "another header"}}}
        mkjson.validate_profile(cfg)
        self.assertEqual(mkjson.sanitize_provider(cfg)["outbounds"], cfg["outbounds"])

    def test_inactive_other_inbound_rule_is_removed(self):
        cfg = profile()
        cfg["routing"]["rules"].insert(0, {
            "type": "field", "inboundTag": ["http"], "outboundTag": "block",
            "webhook": {"url": "https://telemetry.example/events"}})
        mkjson.validate_profile(cfg)
        self.assertEqual(mkjson.sanitize_provider(cfg)["routing"]["rules"],
                         cfg["routing"]["rules"][1:])

    def test_bad_profile_is_isolated_and_saved_verdict_is_rechecked(self):
        bad, good = profile(), profile()
        bad["routing"]["rules"][0]["webhook"] = {
            "url": "https://telemetry.example/events"}
        catalog = mksub.process_body(json.dumps([bad, good]).encode())
        self.assertEqual([node["recognized"] for node in catalog["nodes"]], [False, True])
        self.assertIn("webhooks", catalog["nodes"][0]["reason"])
        catalog["nodes"][0]["recognized"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            loaded = mksub._load(str(path))
        self.assertEqual([node["recognized"] for node in loaded["nodes"]], [False, True])

    def test_socks_projection_checks_before_emitting(self):
        cfg = profile()
        cfg["routing"]["rules"][0]["webhook"] = {
            "url": "https://telemetry.example/events"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    mkjson.cmd_socksconfig(argparse.Namespace(profile=str(path), socks_port=10810))
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
