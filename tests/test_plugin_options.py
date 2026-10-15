#!/usr/bin/env python3
"""SIP003 plugin query decoding preserves the plugin's own URI option text."""

import argparse
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import urlencode

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import mksingbox
import mksub
import mkxray


def link(plugin, credentials="aes-128-gcm:password"):
    encoded = base64.urlsafe_b64encode(credentials.encode()).decode().rstrip("=")
    return "ss://%s@proxy.example:443?%s#fixture" % (
        encoded, urlencode({"plugin": plugin}))


class PluginOptionsTests(unittest.TestCase):
    def test_percent_encoded_path_bytes_are_preserved(self):
        for path in ("/tenant%2Fblue", "/literal%25", "/item%3Bvalue", "/%E2%9C%93"):
            with self.subTest(path=path):
                options = "mode=websocket;host=front.example;path=" + path
                outbound, host, port = mksingbox.parse_ss(link("v2ray-plugin;" + options))
                self.assertEqual(outbound["plugin"], "v2ray-plugin")
                self.assertEqual(outbound["plugin_opts"], options)
                self.assertEqual((host, port), ("proxy.example", 443))

    def test_ordinary_reserved_query_characters_are_decoded_once(self):
        options = "mode=websocket;host=front.example;path=/query?name=a+b&note=50%"
        outbound, _, _ = mksingbox.parse_ss(link("v2ray-plugin;" + options))
        self.assertEqual(outbound["plugin_opts"], options)

    def test_supported_plugin_aliases_and_empty_options_are_preserved(self):
        for name, expected in (("v2ray-plugin", "v2ray-plugin"),
                               ("obfs-local", "obfs-local"),
                               ("simple-obfs", "obfs-local")):
            for options in ("", "obfs=http;obfs-host=front.example"):
                with self.subTest(name=name, options=options):
                    value = name + (";" + options if options else "")
                    outbound, _, _ = mksingbox.parse_ss(link(value))
                    self.assertEqual(outbound["plugin"], expected)
                    self.assertEqual(outbound["plugin_opts"], options)

    def test_classifier_and_generator_agree_without_changing_link_identity(self):
        share = link("v2ray-plugin;mode=websocket;path=/tenant%2Fblue")
        self.assertEqual(mkxray.ss_engine(share), "singbox")
        node = mksub.node_from_link(share)
        self.assertTrue(node["recognized"])
        self.assertEqual(node["engine"], "singbox")
        self.assertEqual(node["link"], share)
        catalog = mksub.process_body(share.encode())
        self.assertEqual(catalog["nodes"][0]["id"], node["id"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            loaded = mksub._load(str(path))
        self.assertEqual(loaded["nodes"][0]["link"], share)
        self.assertEqual(loaded["nodes"][0]["id"], node["id"])

    def test_test_and_bridge_configs_keep_the_same_plugin_options(self):
        options = "mode=websocket;host=front.example;path=/tenant%2Fblue"
        args = argparse.Namespace(link=link("v2ray-plugin;" + options),
                                  socks_port=10810, port=51820, secret_key="fixture",
                                  peer_pubkey="fixture", address="10.7.0.1/32",
                                  mtu=1340, peer_allowed="0.0.0.0/0,::/0", loglevel="warn")
        for config in (mksingbox.build_test_config(args), mksingbox.build_config(args)):
            self.assertEqual(config["outbounds"][0]["plugin_opts"], options)


if __name__ == "__main__":
    unittest.main()
