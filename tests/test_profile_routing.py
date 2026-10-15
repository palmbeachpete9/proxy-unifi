#!/usr/bin/env python3
"""Provider routing projection regressions; no core execution or networking."""

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


def profile():
    return {
        "inbounds": [{"protocol": "socks", "tag": "socks", "port": 10808},
                     {"protocol": "http", "tag": "http", "port": 10809}],
        "outbounds": [{"protocol": "blackhole", "tag": "block"},
                      {"protocol": "freedom", "tag": "proxy"}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": [],
             "domain": ["full:blocked.example"], "outboundTag": "block"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
        ]},
    }


class ProfileRoutingTests(unittest.TestCase):
    def rejects(self, cfg):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                mkjson.validate_profile(cfg)
        self.assertEqual(error.exception.code, 2)

    def test_empty_inbound_selector_preserves_rule_order_and_source(self):
        cfg = profile()
        original = copy.deepcopy(cfg)
        mkjson.validate_profile(cfg)
        projected = mkjson.sanitize_provider(cfg)
        self.assertEqual(projected["routing"]["rules"], cfg["routing"]["rules"])
        self.assertEqual(projected["routing"]["rules"][0]["outboundTag"], "block")
        self.assertEqual(cfg, original)

    def test_empty_absent_and_null_selectors_are_unrestricted(self):
        for selector in ([], None):
            with self.subTest(selector=selector):
                cfg = profile()
                cfg["routing"]["rules"][0]["inboundTag"] = selector
                mkjson.validate_profile(cfg)
                self.assertEqual(mkjson.sanitize_provider(cfg)["routing"]["rules"],
                                 cfg["routing"]["rules"])
        cfg = profile()
        del cfg["routing"]["rules"][0]["inboundTag"]
        mkjson.validate_profile(cfg)
        self.assertEqual(mkjson.sanitize_provider(cfg)["routing"]["rules"],
                         cfg["routing"]["rules"])

    def test_primary_and_shared_selectors_stay_other_inbound_rule_is_removed(self):
        for selector in ("socks", ["socks"], ["http", "socks"]):
            with self.subTest(selector=selector):
                cfg = profile()
                cfg["routing"]["rules"][0]["inboundTag"] = selector
                mkjson.validate_profile(cfg)
                self.assertEqual(mkjson.sanitize_provider(cfg)["routing"]["rules"],
                                 cfg["routing"]["rules"])
        cfg = profile()
        cfg["routing"]["rules"].insert(1, {
            "type": "field", "inboundTag": ["http"], "outboundTag": "block"})
        mkjson.validate_profile(cfg)
        self.assertEqual(mkjson.sanitize_provider(cfg)["routing"]["rules"],
                         [cfg["routing"]["rules"][0], cfg["routing"]["rules"][2]])

    def test_invalid_selector_shapes_are_rejected(self):
        for selector in ({}, 1, True, [None], [1], ["socks", {}]):
            with self.subTest(selector=selector):
                cfg = profile()
                cfg["routing"]["rules"][0]["inboundTag"] = selector
                self.rejects(cfg)

    def test_empty_selector_keeps_source_and_graph_validation(self):
        for field, value in (("source", ["192.0.2.0/24"]),
                             ("sourcePort", "12345"), ("user", ["user@example.com"]),
                             ("outboundTag", "missing"), ("balancerTag", "missing")):
            with self.subTest(field=field):
                cfg = profile()
                cfg["routing"]["rules"][0][field] = value
                self.rejects(cfg)

    def test_socks_test_projection_preserves_empty_selector(self):
        cfg = profile()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                mkjson.cmd_socksconfig(argparse.Namespace(profile=str(path), socks_port=10810))
        rendered = json.loads(output.getvalue())
        self.assertEqual(rendered["routing"]["rules"], cfg["routing"]["rules"])
        self.assertEqual(rendered["inbounds"][0]["tag"], "socks")


if __name__ == "__main__":
    unittest.main()
