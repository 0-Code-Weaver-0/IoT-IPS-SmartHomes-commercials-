"""Tests for detector.py (Person 3). Run:  python test_detector.py   (or python -m pytest / unittest)"""
import os
import tempfile
import unittest

import yaml

import detector
from detector import RuleConfigError, detect, validate_config

HERE = os.path.dirname(os.path.abspath(__file__))
CAMERA = {"device_id": "cam-01", "device_type": "ip_camera", "expected_protocols": ["TCP", "UDP"],
          "expected_ports": [80, 554], "expected_outbound_ports": [53, 123, 443, 8883]}


def ev(**over):
    e = {"device_id": "cam-01", "timestamp": "2026-10-21T10:00:00Z", "src_ip": "192.168.1.20", "dst_ip": "192.168.1.50",
         "dst_port": 554, "protocol": "TCP", "failed_attempts": 0, "connection_attempts": 3,
         "Rate": 15.0, "syn_count": 1, "unique_dst_ports": 1, "unique_dst_ips": 1}
    e.update(over)
    return e


def good_config():
    with open(os.path.join(HERE, "rules.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestBenign(unittest.TestCase):
    def test_normal_traffic(self):
        d = detect(ev(), CAMERA)
        self.assertEqual((d["label"], d["attack_type"], d["mitre_technique"]), ("BENIGN", "None", None))

    def test_many_viewers_of_the_camera_stream_are_not_brute_force(self):
        d = detect(ev(dst_port=554, failed_attempts=0, connection_attempts=150), CAMERA)
        self.assertEqual(d["label"], "BENIGN")

    def test_bulk_transfer_is_not_a_flood(self):   # high rate, one connection (video upload)
        self.assertEqual(detect(ev(Rate=1040.0, connection_attempts=1), CAMERA)["label"], "BENIGN")
        self.assertEqual(detect(ev(Rate=4300.0, connection_attempts=3), CAMERA)["label"], "BENIGN")


class TestRules(unittest.TestCase):
    def test_port_scan(self):
        d = detect(ev(unique_dst_ports=150), CAMERA)
        self.assertEqual((d["attack_type"], d["mitre_technique"]), ("Port Scan", "T1046"))

    def test_brute_force_ssh(self):
        d = detect(ev(dst_port=22, failed_attempts=300, connection_attempts=320), None)
        self.assertEqual((d["attack_type"], d["mitre_technique"]), ("Brute Force", "T1110"))
        self.assertGreaterEqual(d["confidence"], 0.9)

    def test_brute_force_telnet_and_rtsp(self):
        for port in (23, 554):
            self.assertEqual(detect(ev(dst_port=port, failed_attempts=120), None)["attack_type"], "Brute Force")

    def test_brute_force_needs_failed_logins_not_connections(self):
        self.assertEqual(detect(ev(dst_port=22, failed_attempts=10, connection_attempts=5000), None)["label"], "BENIGN")

    def test_ssh_flag_without_port(self):
        self.assertEqual(detect(ev(dst_port=2222, SSH=1, failed_attempts=80), None)["attack_type"], "Brute Force")

    def test_dos_high_rate(self):
        d = detect(ev(Rate=9000.0, connection_attempts=20000), CAMERA)
        self.assertEqual((d["attack_type"], d["mitre_technique"]), ("DoS", "T1498"))

    def test_dos_syn_flood(self):
        self.assertEqual(detect(ev(syn_count=500, connection_attempts=25000), CAMERA)["attack_type"], "DoS")

    def test_dos_without_connection_count_still_detected(self):
        e = ev(Rate=9000.0)
        del e["connection_attempts"]
        self.assertEqual(detect(e, CAMERA)["attack_type"], "DoS")

    def test_unexpected_port_and_protocol(self):
        d = detect(ev(dst_port=4444), CAMERA)
        self.assertEqual((d["attack_type"], d["mitre_technique"], d["confidence"]), ("Unexpected Protocol/Port", "T1571", 0.6))
        self.assertEqual(detect(ev(protocol="ICMP"), CAMERA)["attack_type"], "Unexpected Protocol/Port")
        self.assertEqual(detect(ev(dst_port=4444, protocol="ICMP"), CAMERA)["confidence"], 0.75)

    def test_unexpected_needs_profile(self):
        self.assertEqual(detect(ev(dst_port=4444), None)["label"], "BENIGN")
        self.assertEqual(detect(ev(dst_port=4444), {})["label"], "BENIGN")

    def test_confidence_rises_with_strength(self):
        weak = detect(ev(Rate=1100.0, connection_attempts=5000))["confidence"]
        strong = detect(ev(Rate=9000.0, connection_attempts=5000))["confidence"]
        self.assertTrue(0 <= weak < strong <= 1)

    def test_most_confident_rule_wins(self):
        self.assertEqual(detect(ev(Rate=9000.0, connection_attempts=5000, unique_dst_ports=21), CAMERA)["attack_type"], "DoS")


class TestDirection(unittest.TestCase):
    def test_outbound_cloud_traffic_is_not_unexpected(self):
        for port in (53, 123, 443, 8883):
            self.assertEqual(detect(ev(direction="outbound", dst_port=port), CAMERA)["label"], "BENIGN", port)

    def test_outbound_to_an_unlisted_port_is_flagged(self):
        d = detect(ev(direction="outbound", dst_port=4444), CAMERA)
        self.assertEqual(d["attack_type"], "Unexpected Protocol/Port")

    def test_outbound_without_a_port_list_judges_the_protocol_only(self):
        profile = {k: v for k, v in CAMERA.items() if k != "expected_outbound_ports"}
        self.assertEqual(detect(ev(direction="outbound", dst_port=4444), profile)["label"], "BENIGN")
        self.assertEqual(detect(ev(direction="outbound", dst_port=4444, protocol="GRE"), profile)["label"], "ATTACK")

    def test_inbound_uses_the_served_ports(self):
        self.assertEqual(detect(ev(direction="inbound", dst_port=8883), CAMERA)["label"], "ATTACK")
        self.assertEqual(detect(ev(direction="inbound", dst_port=554), CAMERA)["label"], "BENIGN")

    def test_missing_or_odd_direction_is_treated_as_inbound(self):
        self.assertEqual(detect(ev(direction="sideways", dst_port=8883), CAMERA)["label"], "ATTACK")

    def test_bad_profile_entries_do_not_crash(self):
        profile = dict(CAMERA, expected_ports=["x", None, 554, True, "80", 70000], expected_protocols=[None, "tcp"])
        self.assertEqual(detect(ev(dst_port=554), profile)["label"], "BENIGN")
        self.assertEqual(detect(ev(dst_port=80), profile)["label"], "BENIGN")
        self.assertEqual(detect(ev(dst_port=81), profile)["label"], "ATTACK")


class TestEvasion(unittest.TestCase):
    """KNOWN LIMITATIONS: the rules miss these. The ML model of the next phase should cover part of them."""

    def test_slow_scan_is_missed(self):
        self.assertEqual(detect(ev(unique_dst_ports=5), CAMERA)["label"], "BENIGN")

    def test_low_rate_brute_force_is_missed(self):
        self.assertEqual(detect(ev(dst_port=22, failed_attempts=10, connection_attempts=12), None)["label"], "BENIGN")

    def test_low_rate_dos_is_missed(self):
        self.assertEqual(detect(ev(Rate=300.0, syn_count=20), CAMERA)["label"], "BENIGN")

    def test_attack_on_an_expected_port_and_protocol_is_missed(self):
        self.assertEqual(detect(ev(dst_port=80, protocol="TCP", Rate=50.0), CAMERA)["label"], "BENIGN")


class TestRobustEvents(unittest.TestCase):
    def test_missing_and_bad_input(self):
        for bad in ({}, None, "x", 5, [1], {"Rate": None}):
            self.assertEqual(detect(bad)["label"], "BENIGN")

    def test_csv_strings_nan_and_inf(self):
        self.assertEqual(detect({"Rate": "9000", "dst_port": "80", "connection_attempts": "5000"})["attack_type"], "DoS")
        self.assertEqual(detect({"Rate": "nan", "syn_count": "inf"})["label"], "BENIGN")
        self.assertEqual(detect({"failed_attempts": "abc", "dst_port": "22"})["label"], "BENIGN")
        self.assertEqual(detect({"failed_attempts": True, "dst_port": 22})["label"], "BENIGN")

    def test_output_contract_keys(self):
        for e in (ev(Rate=9000.0, connection_attempts=5000), ev()):
            self.assertEqual(set(detect(e)), {"label", "attack_type", "confidence", "mitre_technique"})


class TestConfigValidation(unittest.TestCase):
    def assertRejected(self, cfg, text=None):
        with self.assertRaises(RuleConfigError) as cm:
            validate_config(cfg)
        if text:
            self.assertIn(text, str(cm.exception))

    def test_shipped_file_is_valid(self):
        validate_config(good_config())

    def test_misspelled_key_is_an_error_not_a_silent_off_switch(self):
        cfg = good_config()
        cfg["rules"]["brute_force"]["min_failed_attemptz"] = cfg["rules"]["brute_force"].pop("min_failed_attempts")
        self.assertRejected(cfg, "min_failed_attempts")
        path = os.path.join(tempfile.mkdtemp(), "bad.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f)
        with self.assertRaises(RuleConfigError):
            detect(ev(dst_port=22, failed_attempts=300), None, config_path=path)

    def test_other_bad_configs(self):
        def mutate(fn):
            cfg = good_config()
            fn(cfg)
            return cfg
        self.assertRejected(mutate(lambda c: c["rules"].pop("dos")), "dos")
        self.assertRejected(mutate(lambda c: c["rules"].update(extra={})), "unknown rule")
        self.assertRejected(mutate(lambda c: c["rules"]["dos"].update(base_confidence=1.5)))
        self.assertRejected(mutate(lambda c: c["rules"]["dos"].update(base_confidence=0.99, max_confidence=0.5)))
        self.assertRejected(mutate(lambda c: c["rules"]["dos"].update(min_rate=-1)))
        self.assertRejected(mutate(lambda c: c["rules"]["dos"].update(min_rate="fast")))
        self.assertRejected(mutate(lambda c: c["rules"]["dos"].update(enabled="yes")))
        self.assertRejected(mutate(lambda c: c["rules"]["dos"].update(mitre_technique="1498")))
        self.assertRejected(mutate(lambda c: c["rules"]["brute_force"].update(target_ports=[])))
        self.assertRejected(mutate(lambda c: c["rules"]["brute_force"].update(target_ports=[99999])))
        self.assertRejected(mutate(lambda c: c["settings"].update(benign_confidence=2)))
        self.assertRejected(mutate(lambda c: c.update(oops=1)))
        self.assertRejected(None)
        self.assertRejected([])

    def test_missing_file_and_bad_yaml(self):
        with self.assertRaises(RuleConfigError):
            detector.load_config("/nonexistent/rules.yaml")
        path = os.path.join(tempfile.mkdtemp(), "x.yaml")
        with open(path, "w") as f:
            f.write("rules: [unclosed")
        with self.assertRaises(RuleConfigError):
            detector.load_config(path)

    def test_edits_are_picked_up_without_restart(self):
        path = os.path.join(tempfile.mkdtemp(), "r.yaml")
        cfg = good_config()
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f)
        self.assertEqual(detect(ev(unique_dst_ports=25), None, config_path=path)["label"], "ATTACK")
        cfg["rules"]["port_scan"]["enabled"] = False
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f)
        os.utime(path, ns=(10 ** 18, 10 ** 18))   # make sure the modification time differs
        self.assertEqual(detect(ev(unique_dst_ports=25), None, config_path=path)["label"], "BENIGN")

    def test_disabled_rule_is_skipped(self):
        cfg = good_config()
        cfg["rules"]["dos"]["enabled"] = False
        path = os.path.join(tempfile.mkdtemp(), "d.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f)
        self.assertEqual(detect(ev(Rate=9000.0, connection_attempts=5000), None, config_path=path)["label"], "BENIGN")

    def test_zero_disables_the_connection_check(self):
        cfg = good_config()
        cfg["rules"]["dos"]["min_connection_attempts"] = 0
        path = os.path.join(tempfile.mkdtemp(), "z.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f)
        self.assertEqual(detect(ev(Rate=9000.0, connection_attempts=1), None, config_path=path)["attack_type"], "DoS")


if __name__ == "__main__":
    unittest.main()
