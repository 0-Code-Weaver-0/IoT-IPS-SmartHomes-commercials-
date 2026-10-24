"""Tests for db.py (Person 6)."""
import os
import sqlite3
import stat
import tempfile
import unittest

from db import IncidentDB, IncidentError, IncidentDBError


def good(**kw):
    inc = {"timestamp": "2026-10-20T08:00:00Z", "device_id": "CAM-001", "device_type": "camera",
           "src_ip": "203.0.113.5", "dst_ip": "192.168.1.50", "dst_port": 22, "attack_type": "brute_force",
           "confidence": 0.9, "risk_score": 77, "risk_level": "High", "risk_factors": {}, "risk_warnings": [],
           "weight_set": "balanced", "attempts": 40, "action": ["create_incident"], "action_result": ["create_incident:simulated:ok"],
           "reason": "rule high_probable matched", "rule_id": "high_probable", "status": "open"}
    inc.update(kw)
    return inc


class TestInsertQuery(unittest.TestCase):
    def setUp(self):
        self.db = IncidentDB(":memory:")
        self.addCleanup(self.db.close)

    def test_insert_and_get(self):
        stored = self.db.insert_incident(good())
        self.assertEqual(stored["incident_id"], "INC-00001")
        got = self.db.get_incident("INC-00001")
        self.assertEqual(got["risk_score"], 77)
        self.assertEqual(got["src_ip"], "203.0.113.5")

    def test_ids_increase(self):
        ids = [self.db.insert_incident(good())["incident_id"] for _ in range(3)]
        self.assertEqual(ids, ["INC-00001", "INC-00002", "INC-00003"])

    def test_missing_fields_do_not_crash(self):
        stored = self.db.insert_incident({"risk_score": 50, "risk_level": "Medium"})
        got = self.db.get_incident(stored["incident_id"])
        self.assertEqual(got["risk_level"], "Medium")

    def test_unusable_score_or_level_rejected(self):
        for bad in ({"risk_score": "x", "risk_level": "High"}, {"risk_score": 50, "risk_level": "Huge"},
                    {"risk_score": float("nan"), "risk_level": "High"}, {"risk_score": True, "risk_level": "High"},
                    {"risk_score": 101, "risk_level": "High"}, "text", None, []):
            with self.assertRaises(IncidentError, msg=repr(bad)):
                self.db.insert_incident(bad)
        self.assertEqual(self.db.count(), 0)

    def test_sql_injection_is_just_data(self):
        self.db.insert_incident(good(device_id="x'; DROP TABLE incidents;--", src_ip="1.2.3.4'; DROP TABLE incidents;--"))
        self.assertEqual(self.db.count(), 1)
        with self.assertRaises(ValueError):
            self.db.query_incidents(device_id="x' OR '1'='1")
        with self.assertRaises(ValueError):
            self.db.query_incidents(level="High' OR 1=1--")
        self.assertEqual(self.db.count(), 1)

    def test_query_filters(self):
        self.db.insert_incident(good())
        self.db.insert_incident(good(risk_level="Critical", risk_score=90, device_id="IND-001", src_ip="203.0.113.50"))
        self.assertEqual(len(self.db.query_incidents(level="Critical")), 1)
        self.assertEqual(len(self.db.query_incidents(device_id="CAM-001")), 1)
        self.assertEqual(len(self.db.query_incidents(src_ip="203.0.113.50")), 1)
        self.assertEqual(len(self.db.query_incidents(since="2026-10-21")), 0)
        self.assertEqual(len(self.db.query_incidents(limit=1)), 1)
        for bad in (0, -1, 10 ** 9, "5", True):
            with self.assertRaises(ValueError):
                self.db.query_incidents(limit=bad)

    def test_summary(self):
        for level, score in (("Low", 10), ("Low", 20), ("High", 70)):
            self.db.insert_incident(good(risk_level=level, risk_score=score))
        self.assertEqual(self.db.summary_by_level(), {"Low": 2, "Medium": 0, "High": 1, "Critical": 0})

    def test_status_is_only_mutable_field(self):
        self.db.insert_incident(good())
        self.db.set_status("INC-00001", "resolved")
        self.assertEqual(self.db.get_incident("INC-00001")["status"], "resolved")
        self.assertTrue(self.db.verify_chain()["ok"])
        with self.assertRaises(ValueError):
            self.db.set_status("INC-00001", "deleted")
        with self.assertRaises(KeyError):
            self.db.set_status("INC-00099", "open")
        with self.assertRaises(ValueError):
            self.db.get_incident("1; DROP")

    def test_reports_hook(self):
        self.db.insert_incident(good(), make_reports=lambda i: {"technical": "T " + i["incident_id"], "non_technical": "P"})
        got = self.db.get_incident("INC-00001")
        self.assertEqual(got["report_technical"], "T INC-00001")
        self.assertEqual(got["report_plain"], "P")

    def test_executive_and_notification_keys(self):
        self.db.insert_incident(good(), make_reports=lambda i: {"technical": "T", "executive": "E", "notification": "N\nline2\x07"})
        got = self.db.get_incident("INC-00001")
        self.assertEqual((got["report_technical"], got["report_plain"]), ("T", "E"))
        self.assertEqual(got["report_notification"], "N\nline2?")
        self.assertTrue(self.db.verify_chain()["ok"])

    def test_report_text_is_in_the_hash(self):
        self.db.insert_incident(good(), make_reports=lambda i: {"technical": "T", "executive": "E"})
        self.db._conn.execute("UPDATE incidents SET report_plain='changed' WHERE id=1")
        self.assertFalse(self.db.verify_chain()["ok"])

    def test_failing_report_hook_does_not_lose_incident(self):
        def boom(_):
            raise RuntimeError("x")
        self.db.insert_incident(good(), make_reports=boom)
        self.assertEqual(self.db.count(), 1)


class TestChain(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "t.db")

    def tearDown(self):
        self.dir.cleanup()

    def _fill(self, key=None, n=4):
        with IncidentDB(self.path, hmac_key=key) as d:
            for _ in range(n):
                d.insert_incident(good())

    def _edit(self, sql, *args):
        con = sqlite3.connect(self.path)
        con.execute(sql, args)
        con.commit()
        con.close()

    def _verify(self, key=None, head=None):
        with IncidentDB(self.path, hmac_key=key) as d:
            return d.verify_chain(expected_head=head)

    def test_intact(self):
        self._fill()
        self.assertTrue(self._verify()["ok"])

    def test_edited_score_detected(self):
        self._fill()
        self._edit("UPDATE incidents SET risk_score=1 WHERE id=2")
        self.assertFalse(self._verify()["ok"])

    def test_edited_level_detected(self):
        self._fill()
        self._edit("UPDATE incidents SET risk_level='Low' WHERE id=3")
        self.assertFalse(self._verify()["ok"])

    def test_deleted_middle_detected(self):
        self._fill()
        self._edit("DELETE FROM incidents WHERE id=2")
        self.assertFalse(self._verify()["ok"])

    def test_deleted_tail_detected(self):
        self._fill()
        self._edit("DELETE FROM incidents WHERE id=4")
        self.assertFalse(self._verify()["ok"])

    def test_saved_head_detects_tail_rewrite(self):
        self._fill()
        head = self._verify()["head"]
        self.assertTrue(self._verify(head=head)["ok"])
        self.assertFalse(self._verify(head="0" * 64)["ok"])

    def test_hmac_mode_needs_key(self):
        key = b"k" * 32
        self._fill(key=key)
        self.assertTrue(self._verify(key=key)["ok"])
        with self.assertRaises(IncidentDBError):
            IncidentDB(self.path)
        with self.assertRaises(IncidentDBError):
            IncidentDB(self.path, hmac_key=b"short")

    def test_wrong_key_fails_verification(self):
        self._fill(key=b"k" * 32)
        self.assertFalse(self._verify(key=b"z" * 32)["ok"])

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_file_mode_0600(self):
        self._fill()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_symlink_refused(self):
        link = os.path.join(self.dir.name, "link.db")
        os.symlink(self.path, link)
        with self.assertRaises(IncidentDBError):
            IncidentDB(link)

    def test_directory_refused(self):
        with self.assertRaises(IncidentDBError):
            IncidentDB(self.dir.name)


if __name__ == "__main__":
    unittest.main()
