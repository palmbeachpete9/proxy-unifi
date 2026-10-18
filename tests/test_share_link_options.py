#!/usr/bin/env python3
"""Share-link options providers commonly add (TCP Fast Open, port hopping,
bandwidth hints, uTLS fingerprints) become what the cores actually support."""

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import mksingbox
import mksub
import mkxray

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SS22 = base64.urlsafe_b64encode(
    b"2022-blake3-aes-128-gcm:" + base64.b64encode(b"k" * 16)).decode().rstrip("=")
SS_LEGACY = base64.b64encode(b"aes-256-gcm:pw").decode()


def outbound(module, link):
    with contextlib.redirect_stderr(io.StringIO()):
        return module.parse_link(link)[0]


def refused(module, link):
    error = io.StringIO()
    try:
        with contextlib.redirect_stderr(error):
            module.parse_link(link)
    except SystemExit:
        return error.getvalue()
    return ""


class SingBoxLinks(unittest.TestCase):
    def test_tfo_is_accepted_and_used_only_over_tcp(self):
        for flag in ("tfo=1", "fastopen=true"):
            hy2 = outbound(mksingbox, "hysteria2://pw@example.com:443?%s#n" % flag)
            self.assertNotIn("tcp_fast_open", hy2)
            tuic = outbound(mksingbox, "tuic://%s:pw@example.com:443?%s#n" % (UUID, flag))
            self.assertNotIn("tcp_fast_open", tuic)
            ss = outbound(mksingbox, "ss://%s@example.com:8388?%s#n" % (SS22, flag))
            self.assertIs(ss["tcp_fast_open"], True)
        self.assertIn("true/false", refused(mksingbox, "hysteria2://pw@example.com:443?tfo=maybe"))

    def test_quic_links_never_request_utls(self):
        # sing-box refuses uTLS on QUIC only when a connection opens.
        hy2 = outbound(mksingbox, "hysteria2://pw@example.com:443?fp=chrome")
        tuic = outbound(mksingbox, "tuic://%s:pw@example.com:443?fingerprint=chrome" % UUID)
        self.assertNotIn("utls", hy2["tls"])
        self.assertNotIn("utls", tuic["tls"])

    def test_port_hopping_in_query_or_authority(self):
        query = outbound(mksingbox, "hysteria2://pw@example.com:443?mport=443,20000-30000&hop-interval=45s")
        self.assertEqual(query["server_port"], 443)
        self.assertEqual(query["server_ports"], ["443:443", "20000:30000"])
        self.assertEqual(query["hop_interval"], "45s")
        listed = outbound(mksingbox, "hysteria2://pw@example.com:20000-30000,40000/?sni=example.com")
        self.assertEqual(listed["server_port"], 20000)
        self.assertEqual(listed["server_ports"], ["20000:30000", "40000:40000"])
        v6 = outbound(mksingbox, "hysteria2://pw@[2001:db8::1]:443,5000-6000")
        self.assertEqual((v6["server"], v6["server_ports"]), ("2001:db8::1", ["443:443", "5000:6000"]))
        for bad in ("hysteria2://pw@example.com:443,5000-6000?mport=7000-8000",
                    "hysteria2://pw@example.com:443?mport=6000-5000",
                    "hysteria2://pw@example.com:443?mport=1-70000",
                    "hysteria2://pw@example.com:443?hop-interval=30",
                    "hysteria2://pw@example.com:443?mport=5000-6000&hop-interval=2"):
            self.assertTrue(refused(mksingbox, bad), bad)

    def test_bandwidth_hints_and_disabled_obfs(self):
        hy2 = outbound(mksingbox, "hysteria2://pw@example.com:443?upmbps=50&downmbps=200%20Mbps&obfs=none")
        self.assertEqual((hy2["up_mbps"], hy2["down_mbps"]), (50, 200))
        self.assertNotIn("obfs", hy2)
        self.assertTrue(refused(mksingbox, "hysteria2://pw@example.com:443?upmbps=fast"))
        self.assertTrue(refused(mksingbox, "hysteria2://pw@example.com:443?obfs=none&obfs-password=x"))

    def test_tuic_disable_sni_and_shadowsocks_uot(self):
        tuic = outbound(mksingbox, "tuic://%s:pw@example.com:443?disable_sni=1" % UUID)
        self.assertIs(tuic["tls"]["disable_sni"], True)
        ss = outbound(mksingbox, "ss://%s@example.com:8388?uot=1" % SS22)
        self.assertIs(ss["udp_over_tcp"], True)


class XrayLinks(unittest.TestCase):
    def test_tfo_becomes_a_socket_option(self):
        vless = outbound(mkxray, "vless://%s@example.com:443?security=tls&tfo=1" % UUID)
        self.assertEqual(vless["streamSettings"]["sockopt"], {"tcpFastOpen": True})
        plain = outbound(mkxray, "vless://%s@example.com:443?security=tls&tfo=0" % UUID)
        self.assertNotIn("sockopt", plain["streamSettings"])
        ss = outbound(mkxray, "ss://%s@example.com:8388?tfo=1&uot=1" % SS_LEGACY)
        self.assertEqual(ss["streamSettings"], {"sockopt": {"tcpFastOpen": True}})
        self.assertIs(ss["settings"]["servers"][0]["uot"], True)

    def test_engine_choice_accepts_tfo(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mkxray.ss_info("ss://%s@example.com:8388?tfo=1" % SS22)[0], "singbox")
            self.assertEqual(mkxray.ss_info("ss://%s@example.com:8388?tfo=1" % SS_LEGACY)[0], "xray")


class SubscriptionVerdicts(unittest.TestCase):
    def test_list_matches_what_selecting_would_do(self):
        feed = "\n".join((
            "hysteria2://pw@example.com:443?tfo=1#tfo",
            "hysteria2://pw@example.com:20000-30000?sni=example.com#hopping",
            "hysteria2://pw@example.com:443?pinSHA256=ab#pinned",
            "vless://%s@example.com:443?security=tls&tfo=1#vless" % UUID,
            "ss://%s@example.com:8388?tfo=1&uot=1#ss22" % SS22,
            "ss://%s@example.com:8388?fastopen=1#legacy" % SS_LEGACY,
            "ss://%s@example.com:8388?tfo=maybe#bad-tfo" % SS22,
        )).encode()
        nodes = {n["label"]: n for n in mksub.process_body(feed)["nodes"]}
        self.assertTrue(nodes["tfo"]["recognized"], nodes["tfo"])
        self.assertTrue(nodes["hopping"]["recognized"], nodes["hopping"])
        self.assertTrue(nodes["vless"]["recognized"], nodes["vless"])
        self.assertTrue(nodes["ss22"]["recognized"], nodes["ss22"])
        self.assertTrue(nodes["legacy"]["recognized"], nodes["legacy"])
        self.assertIn("true/false", nodes["bad-tfo"]["reason"])
        self.assertFalse(nodes["pinned"]["recognized"])
        self.assertIn("pinSHA256", nodes["pinned"]["reason"])


class CoresAcceptTheConfigs(unittest.TestCase):
    """With the pinned cores in tests/.cache (run.sh --download), the generated
    configs must also pass the cores' own checks."""

    def run_check(self, args, config):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(config, fh)
            done = subprocess.run(args + [path], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_sing_box_check(self):
        core = ROOT / "tests" / ".cache" / "sing-box"
        if not core.exists():
            self.skipTest("no cached sing-box")
        for link in ("hysteria2://pw@example.com:443?tfo=1&fp=chrome&mport=443,20000-30000"
                     "&hop-interval=30&upmbps=50&downmbps=200",
                     "tuic://%s:pw@example.com:443?fastopen=1&disable_sni=1" % UUID,
                     "ss://%s@example.com:8388?tfo=1&uot=1" % SS22):
            config = {"outbounds": [outbound(mksingbox, link)]}
            self.run_check([str(core), "check", "-c"], config)

    def test_xray_check(self):
        core = ROOT / "tests" / ".cache" / "xray"
        if not core.exists() or not shutil.which(str(core)):
            self.skipTest("no cached xray")
        for link in ("vless://%s@example.com:443?security=tls&tfo=1" % UUID,
                     "ss://%s@example.com:8388?tfo=1&uot=1" % SS_LEGACY):
            config = {"outbounds": [outbound(mkxray, link)]}
            self.run_check([str(core), "run", "-test", "-config"], config)


if __name__ == "__main__":
    unittest.main()
