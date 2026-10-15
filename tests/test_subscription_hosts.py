#!/usr/bin/env python3
"""Subscription host normalization and isolation; no networking or core calls."""

import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import mksub


def vmess_link(host):
    payload = {"add": host, "port": 443, "id": "user", "ps": "example"}
    return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()


class SubscriptionHostTests(unittest.TestCase):
    def test_policy_receives_canonical_hostname_for_each_link_family(self):
        domain = "bücher.example"
        canonical = "xn--bcher-kva.example"
        links = ["%s://user@%s:443#example" % (scheme, domain)
                 for scheme in ("vless", "vmess", "trojan", "hysteria2", "hy2", "tuic")]
        links += ["ss://aes-128-gcm:password@%s:443#example" % domain, vmess_link(domain)]
        for link in links:
            with self.subTest(scheme=link.split(":", 1)[0]):
                with mock.patch.object(mksub, "is_non_public_host", return_value=False) as policy:
                    node = mksub.node_from_link(link)
                self.assertTrue(node["recognized"], node)
                policy.assert_called_once_with(canonical)

    def test_policy_verdict_controls_canonical_hostname(self):
        link = "vless://user@bücher.example:443#example"
        with mock.patch.object(mksub, "is_non_public_host", return_value=True) as policy:
            node = mksub.node_from_link(link)
        self.assertFalse(node["recognized"])
        self.assertIn("non-public provider destination", node["reason"])
        policy.assert_called_once_with("xn--bcher-kva.example")

    def test_invalid_hosts_are_quiet_and_do_not_displace_valid_neighbor(self):
        for invalid in ("-invalid.example", "bad..example", "bad_name.example"):
            with self.subTest(host=invalid):
                feed = ("vless://user@%s:443#unsupported\n"
                        "vless://user@proxy.example.com:443#supported\n") % invalid
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    catalog = mksub.process_body(feed.encode())
                self.assertEqual([node["recognized"] for node in catalog["nodes"]],
                                 [False, True])
                self.assertEqual(catalog["nodes"][0]["reason"], "invalid provider destination")
                self.assertEqual(catalog["meta"]["supported"], 1)
                self.assertEqual(errors.getvalue(), "")

    def test_canonical_literal_policy_is_preserved(self):
        for host in ("127.0.0.1", "192.168.1.1", "169.254.169.254", "[::1]",
                     "localhost", "service.local"):
            with self.subTest(host=host):
                node = mksub.node_from_link("vless://user@%s:443#example" % host)
                self.assertFalse(node["recognized"])
                self.assertIn("non-public provider destination", node["reason"])
        for host in ("1.1.1.1", "[2606:4700:4700::1111]", "proxy.example.com"):
            with self.subTest(host=host):
                node = mksub.node_from_link("vless://user@%s:443#example" % host)
                self.assertTrue(node["recognized"], node)


if __name__ == "__main__":
    unittest.main()
