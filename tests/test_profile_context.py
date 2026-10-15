#!/usr/bin/env python3
"""Reject provider entry-context rules that the WireGuard projection changes."""

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
        "inbounds": [{"protocol": "socks", "tag": "socks", "listen": "127.0.0.1",
                      "port": 10808},
                     {"protocol": "http", "tag": "http", "port": 10809}],
        "outbounds": [{"protocol": "blackhole", "tag": "block"},
                      {"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"type": "field", "network": "tcp,udp",
                                "outboundTag": "block"}]},
    }


class ProfileContextTests(unittest.TestCase):
    def rejects(self, cfg):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                mkjson.validate_profile(cfg)
        self.assertEqual(error.exception.code, 2)

    def test_nonempty_source_and_local_entry_selectors_are_rejected(self):
        for field, value in (("sourceIP", ["192.0.2.0/24"]),
                             ("localIP", ["127.0.0.1"]), ("localPort", "10808"),
                             ("source", ["192.0.2.0/24"]), ("sourcePort", "12345"),
                             ("user", ["user@example.com"])):
            with self.subTest(field=field):
                cfg = profile()
                cfg["routing"]["rules"][0][field] = value
                self.rejects(cfg)

    def test_semantic_spellings_are_rejected(self):
        for field in ("SourceIP", "sourceIp", "SOURCEIP", "\u017fourceIP",
                      "LocalIP", "localIp", "LOCALIP", "LocalPort", "localport"):
            with self.subTest(field=field):
                cfg = profile()
                cfg["routing"]["rules"][0][field] = "10808" if "port" in field.lower() \
                    else ["192.0.2.0/24"]
                self.rejects(cfg)

    def test_empty_context_selectors_have_no_matching_constraint(self):
        cfg = profile()
        cfg["routing"]["rules"][0].update({"sourceIP": [], "localIP": [],
                                           "localPort": None})
        original = copy.deepcopy(cfg)
        mkjson.validate_profile(cfg)
        self.assertEqual(mkjson.sanitize_provider(cfg)["routing"], cfg["routing"])
        self.assertEqual(cfg, original)

    def test_removed_inbound_rules_do_not_block_projection(self):
        for field, value in (("sourceIP", ["192.0.2.0/24"]),
                             ("localIP", ["127.0.0.1"]), ("localPort", "10809")):
            with self.subTest(field=field):
                cfg = profile()
                cfg["routing"]["rules"].insert(0, {
                    "type": "field", "inboundTag": ["http"], field: value,
                    "outboundTag": "direct"})
                mkjson.validate_profile(cfg)
                self.assertEqual(mkjson.sanitize_provider(cfg)["routing"]["rules"],
                                 cfg["routing"]["rules"][1:])

    def test_shared_and_unrestricted_rules_keep_context_checks(self):
        for selector in (None, [], ["http", "socks"]):
            cfg = profile()
            cfg["routing"]["rules"][0].update({"inboundTag": selector,
                                               "sourceIP": ["192.0.2.0/24"]})
            self.rejects(cfg)

    def test_destination_selectors_and_order_are_preserved(self):
        cfg = profile()
        cfg["routing"]["rules"][0].update({"domain": ["full:service.example"],
                                           "ip": ["192.0.2.0/24"], "port": "443",
                                           "attrs": {"SourceIP": "fixture", "localIp": "data"}})
        cfg["routing"]["rules"].append({"type": "field", "network": "tcp,udp",
                                        "outboundTag": "direct"})
        mkjson.validate_profile(cfg)
        self.assertEqual(mkjson.sanitize_provider(cfg)["routing"], cfg["routing"])

    def test_bad_context_profile_is_isolated_in_catalog(self):
        bad, good = profile(), profile()
        bad["routing"]["rules"][0]["sourceIP"] = ["192.0.2.0/24"]
        catalog = mksub.process_body(json.dumps([bad, good]).encode())
        self.assertEqual([node["recognized"] for node in catalog["nodes"]], [False, True])
        self.assertIn("local-entry", catalog["nodes"][0]["reason"])

    def test_socks_projection_checks_before_emitting(self):
        cfg = profile()
        cfg["routing"]["rules"][0]["localPort"] = "10808"
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
