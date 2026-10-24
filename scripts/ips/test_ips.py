"""Offline tests for the IPS helper scripts (no broker, no API).  Run:  python scripts/ips/test_ips.py"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_ips_publisher as pub  # noqa: E402
import ips_to_backend as m  # noqa: E402
import notifier  # noqa: E402
import seed_ips_devices as seed  # noqa: E402

SAMPLES = pub.load_samples()
BRUTE = next(s for s in SAMPLES if s["name"] == "brute_force")


class TestNaming(unittest.TestCase):
    def test_ids_and_types(self):
        self.assertEqual(m.backend_device_id("CAM-001"), "cam_001")
        self.assertEqual(m.backend_device_id(" Weird Name!! "), "weird_name")
        self.assertEqual(m.backend_device_type("surveillance_camera"), "camera")
        self.assertEqual(m.backend_device_type("Smart Plug"), "plug")
        self.assertEqual(m.event_type("Brute Force"), "cyber.brute_force")
        self.assertEqual(m.event_type("Unexpected Protocol/Port"), "cyber.unexpected_traffic")
        self.assertEqual(m.event_type("New Thing"), "cyber.new_thing")

    def test_zone_choice(self):
        self.assertEqual(m.device_zone("CAM-001"), "entrance")
        self.assertEqual(m.device_zone("X-9"), "network")
        self.assertEqual(m.device_zone("X-9", {"zone": "Living Room"}), "living_room")
        self.assertEqual(m.device_zone("CAM-001", None, known_zones=["garage"]), "network")


class TestMessages(unittest.TestCase):
    def test_every_sample_is_valid(self):
        for s in SAMPLES:
            res = m.build_messages(s["incident"], s["report"], s["profile"])
            self.assertEqual([t for t, _ in res["messages"]], ["security/alerts/cyber", "security/alerts/engine", "security/risk", "security/incidents"])
            for topic, payload in res["messages"]:
                m.check_message(topic, payload)

    def test_incident_links_its_events_in_time_order(self):
        res = m.build_messages(BRUTE["incident"], BRUTE["report"], BRUTE["profile"])
        alert, report, risk, inc = (p for _, p in res["messages"])
        self.assertEqual(inc["events"], [alert["id"], report["id"]])
        self.assertLess(alert["ts"], report["ts"])
        self.assertEqual((inc["level"], inc["trigger"], inc["id"]), ("critical", "cyber.brute_force", "INC-00033"))
        self.assertEqual(alert["data"]["target"], "cam_001")
        self.assertIn("block_source", inc["actions"])
        self.assertNotIn("create_incident", inc["actions"])
        self.assertTrue(report["data"]["report_technical"] and report["data"]["mitre_technique"] == "T1110")

    def test_port_scan_carries_ports(self):
        s = next(x for x in SAMPLES if x["name"] == "port_scan")
        alert = m.build_messages(s["incident"], s["report"], s["profile"])["messages"][0][1]
        self.assertEqual(alert["type"], "cyber.port_scan")
        self.assertIsInstance(alert["data"]["ports"], list)

    def test_a_repeat_updates_the_same_incident(self):
        first = m.build_messages(BRUTE["incident"], BRUTE["report"], BRUTE["profile"])
        second = m.build_messages(BRUTE["incident"], BRUTE["report"], BRUTE["profile"], previous_event_ids=first["event_ids"])
        self.assertEqual(second["messages"][3][1]["id"], first["messages"][3][1]["id"])
        self.assertEqual(second["messages"][3][1]["events"][:2], first["event_ids"])
        self.assertEqual(len(set(second["event_ids"])), 4)
        again = m.build_messages(BRUTE["incident"], BRUTE["report"], BRUTE["profile"])
        self.assertEqual(again["event_ids"], first["event_ids"])           # same input, same ids (idempotent)

    def test_hostile_and_broken_input_stays_valid(self):
        bad = dict(BRUTE["incident"], id="INC-9\n\x00", device_id="A B/../C", src_ip="x" * 500, attack_type="<script>", level="nope",
                   score="abc", confidence="nan", factors={"x": {"value": None}, "Y z": "5"}, actions=["block_ip", "a b", 7, None],
                   mitre_technique="T1110' OR 1=1", dst_port="NaN")
        res = m.build_messages(bad, {"technical": "a" * 50000, "executive": None, "notification": None}, {"zone": "../x"})
        for topic, payload in res["messages"]:
            m.check_message(topic, payload)
        self.assertLessEqual(len(json.dumps(res["messages"][1][1]["data"])), 32 * 1024)
        self.assertIsNone(res["messages"][1][1]["data"].get("mitre_technique"))

    def test_checker_rejects_what_the_api_rejects(self):
        good = m.build_messages(BRUTE["incident"], BRUTE["report"], BRUTE["profile"])["messages"][0][1]
        for key, value in (("type", "nodot"), ("zone", "Bad Zone"), ("id", "short"), ("severity_hint", "huge"), ("data", [])):
            with self.assertRaises(m.MessageError):
                m.check_message("security/alerts/cyber", dict(good, **{key: value}))
        with self.assertRaises(m.MessageError):
            m.check_message("security/alerts/cyber", dict(good, extra=1))
        inc = m.build_messages(BRUTE["incident"], BRUTE["report"], BRUTE["profile"])["messages"][3][1]
        with self.assertRaises(m.MessageError):
            m.check_message("security/incidents", dict(inc, score=85.5))


class TestPlanAndSeed(unittest.TestCase):
    def test_plan_counts_and_repeat(self):
        self.assertEqual(len(pub.plan(SAMPLES)), 4 * len(SAMPLES))
        self.assertEqual(len(pub.plan(SAMPLES, only=["brute_force"], repeat=3)), 12)
        self.assertEqual(pub.plan(SAMPLES, only=["brute_force"], repeat=3)[-1][1]["id"], "INC-00033")

    def test_seed_payloads(self):
        path = Path(tempfile.mkdtemp()) / "d.json"
        path.write_text(json.dumps({"devices": [{"device_id": "CAM-001", "device_type": "surveillance_camera", "ip": "192.168.1.50", "criticality": "high"},
                                                {"device_id": "ODD 7", "device_type": "gizmo", "zone": "garage"}, {"nope": 1}]}))
        profs = seed.load_profiles(path)
        self.assertEqual(len(profs), 2)
        cam = seed.device_payload(profs[0])
        self.assertEqual((cam["device_id"], cam["device_type"], cam["zone"], cam["online"]), ("cam_001", "camera", "entrance", True))
        self.assertEqual(cam["state"]["ip"], "192.168.1.50")
        odd = seed.device_payload(profs[1])
        self.assertEqual((odd["device_id"], odd["device_type"], odd["zone"]), ("odd_7", "gizmo", "garage"))
        path.write_text("[1,2]")
        self.assertEqual(seed.load_profiles(path), [])


class TestNotifier(unittest.TestCase):
    INCS = [{"id": "INC-1", "level": "critical", "summary": "s1"}, {"id": "INC-2", "level": "medium"}, {"id": "other", "level": "critical"},
            {"id": "INC-3", "level": "high", "summary": "s3"}]

    def test_selection(self):
        self.assertEqual([i["id"] for i in notifier.select_new(self.INCS, {})], ["INC-1", "INC-3"])
        self.assertEqual([i["id"] for i in notifier.select_new(self.INCS, {"INC-1": 3, "INC-3": 2})], [])
        self.assertEqual([i["id"] for i in notifier.select_new(self.INCS, {"INC-3": 1})], ["INC-1", "INC-3"])   # got worse

    def test_run_once_sends_each_alert_once(self):
        class Fake:
            def api(self, method, path, body=None, params=None):
                if path == "/incidents":
                    return 200, TestNotifier.INCS
                return 200, [{"type": "engine.ips_report", "data": {"notification": "ALERT TEXT"}}]
        sent, state = [], Path(tempfile.mkdtemp()) / "s.json"
        sender = lambda text: sent.append(text) or True       # noqa: E731
        self.assertEqual(notifier.run_once(Fake(), state, sender), ["INC-1", "INC-3"])
        self.assertEqual(notifier.run_once(Fake(), state, sender), [])
        self.assertEqual(sent, ["ALERT TEXT", "ALERT TEXT"])

    def test_failed_send_is_retried(self):
        class Fake:
            def api(self, *a, **k):
                return 200, [{"id": "INC-1", "level": "high"}] if a[1] == "/incidents" else []
        state = Path(tempfile.mkdtemp()) / "s.json"
        self.assertEqual(notifier.run_once(Fake(), state, lambda t: False), ["INC-1"])
        self.assertEqual(notifier.run_once(Fake(), state, lambda t: True), ["INC-1"])
        self.assertEqual(notifier.run_once(Fake(), state, lambda t: True), [])


if __name__ == "__main__":
    unittest.main()
