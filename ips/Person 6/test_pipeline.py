"""Tests for run_pipeline.py (Person 6): the whole chain, bad input, limits and the command line."""
import contextlib
import io
import os
import sys
import tempfile
import unittest

import run_pipeline as rp
import db as dbmod

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample_events.csv")
DEVICES = os.path.join(HERE, "devices.json")
HEADER = "device_id,timestamp,src_ip,dst_ip,dst_port,protocol,failed_attempts,connection_attempts,Rate,syn_flag_number\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "i.db")
        self.log = os.path.join(self.tmp.name, "a.jsonl")

    def csv(self, body, header=HEADER):
        path = os.path.join(self.tmp.name, "e.csv")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(header + body)
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = rp.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def run_events(self, path, *extra, real_detector=False):
        """The tests of this file are about the pipeline, so by default they use the built-in placeholder detector:
        the results then do not depend on whether Person 3's detector.py is next to this folder."""
        mode = [] if real_detector else ["--placeholders", "detector"]
        return self.run_cli("run", path, "--db", self.db_path, "--devices", DEVICES, "--action-log", self.log, "--reset", *mode, *extra)

    def rows(self):
        with dbmod.IncidentDB(self.db_path) as d:
            return d.query_incidents(limit=1000)


def Pipeline_for(case, modules, **kwargs):
    policy_cfg = modules.policy.load_policy()
    database = dbmod.IncidentDB(":memory:")
    case.addCleanup(database.close)
    executor = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=case.log)
    pipeline = rp.Pipeline(database, modules, rp.load_devices(DEVICES), executor, policy_cfg, **kwargs)
    pipeline.database = database
    return pipeline


class TestSampleRun(Base):
    def test_levels_match_the_expected_level_column(self):
        code, out, _ = self.run_events(SAMPLE)
        self.assertEqual(code, 0, out)
        got = sorted((r["timestamp"], r["risk_level"]) for r in self.rows())
        import csv
        with open(SAMPLE, encoding="utf-8", newline="") as f:
            expected = [r["expected_level"] for r in csv.DictReader(f) if r["expected_level"] != "none"]
        self.assertEqual(sorted(l for _t, l in got), sorted(expected))

    def test_counts_in_the_run_summary(self):
        _c, out, _e = self.run_events(SAMPLE)
        self.assertIn("benign       : 3", out)
        self.assertIn("attacks      : 9, incidents stored: 9", out)

    def test_expected_columns_never_reach_the_detector(self):
        seen = []
        modules = rp.Modules(force_placeholders={"detector"})
        modules.detect = lambda e, p=None: (seen.append(dict(e)), {"label": "BENIGN"})[1]
        pipeline = Pipeline_for(self, modules)
        for _l, event, _p in rp.read_events(SAMPLE):
            pipeline.process_event(event)
        self.assertTrue(seen)
        self.assertFalse([k for e in seen for k in e if k.lower().startswith("expected_")])

    def test_benign_rows_store_nothing(self):
        self.run_events(SAMPLE)
        self.assertEqual(len(self.rows()), 9)

    def test_chain_intact_after_run(self):
        self.run_events(SAMPLE)
        code, out, _ = self.run_cli("verify", "--db", self.db_path)
        self.assertEqual(code, 0)
        self.assertIn("intact", out)

    def test_show_prints_summary(self):
        self.run_events(SAMPLE)
        code, out, _ = self.run_cli("show", "--db", self.db_path)
        self.assertEqual(code, 0)
        self.assertIn("Incidents by level: Low 2, Medium 1, High 3, Critical 3", out)
        code, out, _ = self.run_cli("show", "--db", self.db_path, "--level", "Critical")
        self.assertEqual(out.count("INC-"), 3)

    def test_full_incident_view_has_reports(self):
        self.run_events(SAMPLE)
        code, out, _ = self.run_cli("show", "--db", self.db_path, "--full", "INC-00001")
        self.assertEqual(code, 0)
        self.assertIn("technical report", out)

    def test_nothing_real_is_executed_everything_simulated(self):
        self.run_events(SAMPLE)
        import json
        with open(self.log, encoding="ascii") as f:
            records = [json.loads(line) for line in f]
        self.assertTrue(records)
        self.assertTrue(all(r["dry_run"] for r in records))
        self.assertTrue(all(r["status"] in ("simulated", "skipped", "refused") for r in records))

    def test_spoofed_router_source_is_never_blocked(self):
        self.run_events(SAMPLE)
        import json
        with open(self.log, encoding="ascii") as f:
            records = [json.loads(line) for line in f]
        self.assertFalse([r for r in records if r["target"] == "192.168.1.1" and r["status"] == "simulated"])

    def test_dry_run_flag_stored(self):
        self.run_events(SAMPLE)
        self.assertTrue(all(r["dry_run"] for r in self.rows()))
        self.assertTrue(all(r["status"] != "contained" for r in self.rows()))

    def test_rerun_with_reset_gives_same_count(self):
        self.run_events(SAMPLE)
        self.run_events(SAMPLE)
        self.assertEqual(len(self.rows()), 9)


class TestBadInput(Base):
    def test_missing_fields_do_not_crash(self):
        path = self.csv(",,,,,,,,,\n,,,,22,,50,50,,\nCAM-001,,,,,,,,,\nCAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n")
        code, out, err = self.run_events(path)
        self.assertEqual(code, 0, out + err)
        rows = self.rows()
        self.assertTrue(rows)
        warnings = " ".join(" ".join(r["risk_warnings"]) for r in rows)
        self.assertIn("missing_src_ip", warnings)

    def test_garbage_values(self):
        path = self.csv("CAM-001,xx,1.2.3.999,y,99999,TCP,nan,inf,-5,1e999\nCAM-001,2026,<script>,,-1,TCP,40,40,,\n"
                        "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,'; DROP TABLE incidents;--,50,,\n")
        code, out, err = self.run_events(path)
        self.assertIn(code, (0, 2), out + err)
        self.assertNotIn("Traceback", err)
        for r in self.rows():
            self.assertIn(r["risk_level"], dbmod.LEVELS)

    def test_untrusted_text_is_not_echoed(self):
        marker = "EVIL_MARKER_123"
        path = self.csv("%s,2026-10-20T08:00:00Z,%s,%s,22,TCP,50,50,,\n" % (marker, marker, marker))
        code, out, err = self.run_events(path)
        self.assertNotIn(marker, out + err)

    def test_extra_fields_row_rejected_not_fatal(self):
        path = self.csv("CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,,EXTRA,EXTRA\n"
                        "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n")
        code, out, _ = self.run_events(path)
        self.assertEqual(code, 2)
        self.assertIn("too_many_fields", out)
        self.assertEqual(len(self.rows()), 1)

    def test_file_level_problems(self):
        empty = os.path.join(self.tmp.name, "empty.csv")
        open(empty, "w").close()
        for path, text in ((empty, "empty"), (os.path.join(self.tmp.name, "nope.csv"), "cannot read")):
            code, _o, err = self.run_events(path)
            self.assertEqual(code, 2)
            self.assertIn(text, err)
        dup = self.csv("", header="device_id,Device_ID\n")
        self.assertEqual(self.run_events(dup)[0], 2)
        weird = self.csv("", header="device_id,<script>\n")
        self.assertEqual(self.run_events(weird)[0], 2)
        binary = os.path.join(self.tmp.name, "b.csv")
        with open(binary, "wb") as f:
            f.write(b"device_id\n\xff\xfe\x00\x01\n")
        self.assertEqual(self.run_events(binary)[0], 2)

    def test_row_limit(self):
        body = "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n" * 10
        code, out, _ = self.run_events(self.csv(body), "--max-rows", "3")
        self.assertIn("row limit", out)
        self.assertEqual(len(self.rows()), 3)

    def test_incident_limit(self):
        body = "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n" * 5
        code, out, _ = self.run_events(self.csv(body), "--max-incidents", "2")
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(code, 2)
        self.assertIn("incident_limit_reached", out)

    def test_bad_cli_numbers(self):
        for v in ("0", "-1", "99999999999"):
            self.assertEqual(self.run_cli("run", SAMPLE, "--max-rows", v)[0], 2)

    def test_missing_database_for_show_and_verify(self):
        self.assertEqual(self.run_cli("show", "--db", os.path.join(self.tmp.name, "none.db"))[0], 2)
        self.assertEqual(self.run_cli("verify", "--db", os.path.join(self.tmp.name, "none.db"))[0], 2)

    def test_show_bad_filters(self):
        self.run_events(SAMPLE)
        self.assertEqual(self.run_cli("show", "--db", self.db_path, "--level", "x'--")[0], 2)
        self.assertEqual(self.run_cli("show", "--db", self.db_path, "--full", "1;DROP")[0], 2)
        self.assertEqual(self.run_cli("show", "--db", self.db_path, "--full", "INC-99999")[0], 2)

    def test_tampering_found_by_verify_command(self):
        import sqlite3
        self.run_events(SAMPLE)
        con = sqlite3.connect(self.db_path)
        con.execute("UPDATE incidents SET risk_level='Low' WHERE id=5")
        con.commit()
        con.close()
        code, out, _ = self.run_cli("verify", "--db", self.db_path)
        self.assertEqual(code, 1)
        self.assertIn("TAMPERING", out)

    def test_no_devices_file_uses_cautious_defaults(self):
        code, out, err = self.run_cli("run", SAMPLE, "--db", self.db_path, "--devices", os.path.join(self.tmp.name, "none.json"),
                                      "--action-log", self.log, "--reset")
        self.assertEqual(code, 0, err)
        self.assertIn("not found", out)
        self.assertTrue(self.rows())


class TestModuleFailures(Base):
    def make(self, **overrides):
        modules = rp.Modules(force_placeholders={"detector"})
        for k, v in overrides.items():
            setattr(modules, k, v)
        policy_cfg = modules.policy.load_policy()
        database = dbmod.IncidentDB(":memory:")
        self.addCleanup(database.close)
        executor = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=self.log)
        return rp.Pipeline(database, modules, rp.load_devices(DEVICES), executor, policy_cfg), database

    EVENT = {"device_id": "CAM-001", "timestamp": "2026-10-20T08:00:00Z", "src_ip": "203.0.113.5",
             "dst_ip": "192.168.1.50", "dst_port": "22", "failed_attempts": "50", "connection_attempts": "50"}

    def test_detector_crash_is_contained(self):
        def boom(_e, _p=None):
            raise RuntimeError("secret detail")
        pipeline, database = self.make(detect=boom)
        res = pipeline.process_event(self.EVENT)
        self.assertEqual(res["outcome"], "error")
        self.assertNotIn("secret", res["error"])
        self.assertEqual(database.count(), 0)

    def test_detector_bad_output_is_contained(self):
        for bad in (None, "ATTACK", {"label": "MAYBE"}, {"label": 5}, []):
            pipeline, _d = self.make(detect=lambda e, p=None, b=bad: b)
            self.assertEqual(pipeline.process_event(self.EVENT)["error"], "detector_invalid_output")

    def test_report_crash_does_not_lose_the_incident(self):
        def boom(_i):
            raise RuntimeError("x")
        pipeline, database = self.make(make_report=boom)
        self.assertEqual(pipeline.process_event(self.EVENT)["outcome"], "incident")
        self.assertEqual(database.count(), 1)

    def test_non_mapping_event(self):
        pipeline, _d = self.make()
        for bad in (None, 5, "x", [1]):
            self.assertEqual(pipeline.process_event(bad)["outcome"], "rejected")

    def test_attack_without_create_incident_is_not_stored(self):
        pipeline, database = self.make()
        original = pipeline.m.policy.decide
        pipeline.m.policy = type("P", (), {"decide": staticmethod(lambda *a, **k: dict(original(*a, **k), action=["log"])),
                                          "PolicyConfigError": pipeline.m.policy.PolicyConfigError})
        res = pipeline.process_event(self.EVENT)
        self.assertEqual(res["outcome"], "no_incident")
        self.assertEqual(database.count(), 0)

    def test_real_detector_is_picked_up_without_code_changes(self):
        d = os.path.join(self.tmp.name, "mods")
        os.makedirs(d)
        with open(os.path.join(d, "detector_probe.py"), "w") as f:
            f.write("def detect(e):\n    return {'label': 'BENIGN'}\n")
        sys.path.insert(0, d)
        self.addCleanup(sys.path.remove, d)
        import importlib
        self.assertTrue(callable(importlib.import_module("detector_probe").detect))


class TestRealReportModule(Base):
    def setUp(self):
        super().setUp()
        self.m = rp.Modules()
        if self.m.sources["report"] != "real":
            self.skipTest("SKIPPED: Person 7's report.py not found next to this folder (sibling folder person7)")

    def test_reports_stored_and_notification_only_for_high_and_critical(self):
        self.run_events(SAMPLE)
        with dbmod.IncidentDB(self.db_path) as d:
            for inc in d.query_incidents(limit=100, include_reports=True):
                self.assertTrue(inc["report_technical"] and inc["report_plain"])
                self.assertIn(inc["incident_id"], inc["report_technical"])
                if inc["risk_level"] in ("High", "Critical"):
                    self.assertTrue(inc["report_notification"], inc["incident_id"])
                else:
                    self.assertIsNone(inc["report_notification"])

    def test_report_score_matches_database_score(self):
        self.run_events(SAMPLE)
        with dbmod.IncidentDB(self.db_path) as d:
            for inc in d.query_incidents(limit=100, include_reports=True):
                self.assertIn("%d/100" % inc["risk_score"], inc["report_plain"] + inc["report_technical"])

    def test_report_status_matches_database_status(self):
        self.run_events(SAMPLE)
        with dbmod.IncidentDB(self.db_path) as d:
            crit = d.query_incidents(level="Critical", include_reports=True)[0]
        self.assertIn("Status: Open", crit["report_notification"])
        self.assertNotIn("Status: Contained", crit["report_notification"])

    def test_csv_text_cannot_become_a_markdown_link_in_a_report(self):
        evil = "[click here](http://evil.example) <img src=x>"
        path = self.csv('CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,"%s",50,50,,\n' % evil)
        self.assertEqual(self.run_events(path)[0], 0)
        with dbmod.IncidentDB(self.db_path) as d:
            inc = d.get_incident("INC-00001")
        text = inc["report_technical"] + inc["report_plain"] + (inc["report_notification"] or "")
        for bad in ("evil", "<img", "]("):
            self.assertNotIn(bad, text)

    def test_attempt_count_reaches_the_report(self):
        path = self.csv("CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n")
        self.run_events(path)
        with dbmod.IncidentDB(self.db_path) as d:
            self.assertIn("50", d.get_incident("INC-00001")["report_technical"])

    def test_report_survives_missing_numbers(self):
        import report as reportmod
        r = reportmod.make_report({"id": "INC-00001", "score": None, "confidence": None, "level": None,
                                    "attack_type": None, "actions": None, "factors": None,
                                    "skipped": None, "warnings": None, "commands": None})
        self.assertTrue(r["technical"] and r["executive"])

    def test_report_shows_the_duration_when_the_csv_has_one(self):
        header = "device_id,timestamp,src_ip,dst_ip,dst_port,protocol,failed_attempts,connection_attempts,duration\n"
        path = self.csv("CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,4 minutes\n", header)
        self.run_events(path)
        with dbmod.IncidentDB(self.db_path) as d:
            self.assertIn("4 minutes", d.get_incident("INC-00001")["report_technical"])

    def test_no_incident_is_marked_contained(self):
        self.run_events(SAMPLE)
        self.assertNotIn("contained", [r["status"] for r in self.rows()])


class TestDevicesFile(Base):
    def write(self, text):
        p = os.path.join(self.tmp.name, "d.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_loads_sample(self):
        devices = rp.load_devices(DEVICES)
        self.assertEqual(devices["CAM-001"]["criticality"], "high")
        self.assertEqual(devices["CAM-001"]["expected_ports"], [554, 443])

    def test_invalid_things_are_dropped_or_refused(self):
        devs = rp.load_devices(self.write('[{"device_id":"A","ip":"999","criticality":"galactic","expected_ports":[1,"x",true,70000]},'
                                          '{"device_id":"bad id!"}, 5]'))
        self.assertEqual(list(devs), ["A"])
        self.assertIsNone(devs["A"]["ip"])
        self.assertIsNone(devs["A"]["criticality"])
        self.assertEqual(devs["A"]["expected_ports"], [1])
        for text in ("not json", "5", "[NaN]", '[{"device_id":"A"},{"device_id":"A"}]', "[" * 100000):
            with self.assertRaises(rp.PipelineError, msg=text[:20]):
                rp.load_devices(self.write(text))


class TestModulesAndKey(Base):
    def test_folder_discovery_is_spelling_independent(self):
        base = os.path.join(self.tmp.name, "Person 6")
        os.makedirs(base)
        for name in ("Person 4", "person_5", "other"):
            os.makedirs(os.path.join(self.tmp.name, name))
        before = list(sys.path)
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), before))
        added = [os.path.basename(p) for p in rp.add_module_folders(base)]
        self.assertEqual(sorted(added), ["Person 4", "person_5"])

    def test_db_key_rules(self):
        old = os.environ.get("IOTIPS_DB_KEY")
        self.addCleanup(lambda: os.environ.__setitem__("IOTIPS_DB_KEY", old) if old else os.environ.pop("IOTIPS_DB_KEY", None))
        os.environ.pop("IOTIPS_DB_KEY", None)
        self.assertIsNone(rp.db_key_from_env())
        os.environ["IOTIPS_DB_KEY"] = "short"
        with self.assertRaises(rp.PipelineError):
            rp.db_key_from_env()
        os.environ["IOTIPS_DB_KEY"] = "a" * 24
        self.assertEqual(len(rp.db_key_from_env()), 24)

    def test_keyed_run_then_wrong_mode_refused(self):
        old = os.environ.get("IOTIPS_DB_KEY")
        self.addCleanup(lambda: os.environ.__setitem__("IOTIPS_DB_KEY", old) if old else os.environ.pop("IOTIPS_DB_KEY", None))
        os.environ["IOTIPS_DB_KEY"] = "k" * 32
        self.assertEqual(self.run_events(SAMPLE)[0], 0)
        self.assertEqual(self.run_cli("verify", "--db", self.db_path)[0], 0)
        os.environ.pop("IOTIPS_DB_KEY")
        self.assertEqual(self.run_cli("verify", "--db", self.db_path)[0], 2)

    def test_source_has_no_subprocess_or_network(self):
        for name in ("run_pipeline.py", "db.py", "placeholders.py"):
            with open(os.path.join(HERE, name), encoding="utf-8") as fh:
                text = fh.read()
            for word in ("subprocess", "import socket", "os.system", "eval(", "exec(", "pickle", "shell=True"):
                self.assertNotIn(word, text, "%s contains %s" % (name, word))


class TestIntegrationFixes(Base):
    """Profile hand-over, startup checks, repeat grouping, direction, and report/detector agreement."""
    BRUTE = {"label": "ATTACK", "attack_type": "Brute Force", "confidence": 0.95, "mitre_technique": "T1110"}

    def event(self, ts, src="203.0.113.5", **kw):
        e = {"device_id": "CAM-001", "timestamp": ts, "src_ip": src, "dst_ip": "192.168.1.50", "dst_port": "22",
             "protocol": "TCP", "failed_attempts": "300", "connection_attempts": "300"}
        e.update(kw)
        return e

    def make(self, detection=None, **kwargs):
        modules = rp.Modules(force_placeholders={"detector"})
        det = detection or self.BRUTE
        modules.detect = lambda e, p=None: det
        return Pipeline_for(self, modules, **kwargs)

    # --- the detector gets the device profile ---------------------------------------------------
    def test_profile_is_handed_to_the_detector(self):
        seen = []
        modules = rp.Modules(force_placeholders={"detector"})
        modules.detect = lambda e, p=None: (seen.append(p), {"label": "BENIGN"})[1]
        Pipeline_for(self, modules).process_event(self.event("2026-10-20T08:00:00Z"))
        self.assertEqual(seen[0]["device_id"], "CAM-001")
        self.assertIn(554, seen[0]["expected_ports"])
        self.assertIn(8883, seen[0]["expected_outbound_ports"])

    def test_unknown_device_gets_an_empty_profile(self):
        seen = []
        modules = rp.Modules(force_placeholders={"detector"})
        modules.detect = lambda e, p=None: (seen.append(p), {"label": "BENIGN"})[1]
        Pipeline_for(self, modules).process_event(self.event("2026-10-20T08:00:00Z", device_id="NOPE-9"))
        self.assertEqual(seen, [{}])

    def test_outbound_ports_survive_loading_and_bad_entries_are_dropped(self):
        path = os.path.join(self.tmp.name, "d.json")
        with open(path, "w") as f:
            f.write('[{"device_id": "A-1", "expected_outbound_ports": [53, "x", true, 70000, 443]}, {"device_id": "B-1"}]')
        devices = rp.load_devices(path)
        self.assertEqual(devices["A-1"]["expected_outbound_ports"], [53, 443])
        self.assertEqual(devices["B-1"]["expected_outbound_ports"], [])

    # --- placeholder switches -------------------------------------------------------------------
    def test_require_real_stops_when_a_placeholder_would_be_used(self):
        code, out, err = self.run_events(SAMPLE, "--require-real", "--placeholders", "all")
        self.assertEqual(code, 2)
        self.assertIn("placeholder", out + err)

    def test_placeholders_option_can_target_one_module(self):
        m = rp.Modules(force_placeholders={"detector"})
        self.assertEqual(m.sources["detector"], "placeholder")
        m2 = rp.Modules(force_placeholders=True)
        self.assertEqual(m2.sources, {"detector": "placeholder", "report": "placeholder"})

    def test_bad_detector_configuration_stops_the_run_at_the_start(self):
        d = os.path.join(self.tmp.name, "badcfg")
        os.makedirs(d)
        with open(os.path.join(d, "detector.py"), "w") as f:
            f.write("def load_config():\n    raise ValueError('rule dos is missing key(s): min_rate')\n"
                    "def detect(e, p=None):\n    return {'label': 'BENIGN'}\n")
        sys.path.insert(0, d)
        sys.modules.pop("detector", None)
        self.addCleanup(sys.modules.pop, "detector", None)
        self.addCleanup(sys.path.remove, d)
        with self.assertRaises(rp.PipelineError) as cm:
            rp.Modules()
        self.assertIn("detector configuration problem", str(cm.exception))
        self.assertIn("min_rate", str(cm.exception))

    # --- repeat grouping ------------------------------------------------------------------------
    def test_repeats_inside_the_window_are_stored_once(self):
        p = self.make(dedup_window=60)
        first = p.process_event(self.event("2026-10-20T08:00:00Z"))
        again = p.process_event(self.event("2026-10-20T08:00:30Z"))
        self.assertEqual((first["outcome"], again["outcome"]), ("incident", "duplicate"))
        self.assertEqual(again["incident_id"], first["incident_id"])
        self.assertEqual(p.database.count(), 1)
        self.assertEqual(p.duplicates, 1)

    def test_grouping_is_off_by_default(self):
        p = self.make()
        p.process_event(self.event("2026-10-20T08:00:00Z"))
        p.process_event(self.event("2026-10-20T08:00:05Z"))
        self.assertEqual(p.database.count(), 2)

    def test_outside_the_window_or_other_source_or_other_attack_is_a_new_incident(self):
        p = self.make(dedup_window=60)
        p.process_event(self.event("2026-10-20T08:00:00Z"))
        self.assertEqual(p.process_event(self.event("2026-10-20T08:02:00Z"))["outcome"], "incident")
        self.assertEqual(p.process_event(self.event("2026-10-20T08:02:10Z", src="203.0.113.99"))["outcome"], "incident")
        p.m.detect = lambda e, pr=None: {"label": "ATTACK", "attack_type": "Port Scan", "confidence": 0.9, "mitre_technique": "T1046"}
        self.assertEqual(p.process_event(self.event("2026-10-20T08:02:20Z"))["outcome"], "incident")
        self.assertEqual(p.database.count(), 4)

    def test_a_continuing_attack_stays_one_incident_but_a_worse_one_is_new(self):
        p = self.make(dedup_window=60)
        weak = {"label": "ATTACK", "attack_type": "Brute Force", "confidence": 0.60, "mitre_technique": "T1110"}
        p.m.detect = lambda e, pr=None: weak
        self.assertEqual(p.process_event(self.event("2026-10-20T08:00:00Z", failed_attempts="50", connection_attempts="50"))["outcome"], "incident")
        for minute in range(1, 4):   # a slow attack: every event is within 60 s of the previous one
            r = p.process_event(self.event("2026-10-20T08:0%d:00Z" % minute, failed_attempts="50", connection_attempts="50"))
            self.assertEqual(r["outcome"], "duplicate")
        p.m.detect = lambda e, pr=None: self.BRUTE      # same attack, now strong: higher level, must not be hidden
        worse = p.process_event(self.event("2026-10-20T08:04:00Z"))
        self.assertEqual(worse["outcome"], "incident")
        self.assertGreater(p.database.count(), 1)

    def test_events_without_a_usable_time_are_never_grouped(self):
        p = self.make(dedup_window=60)
        for _ in range(2):
            self.assertEqual(p.process_event(self.event("not-a-time"))["outcome"], "incident")

    def test_grouping_from_the_command_line(self):
        body = "".join("CAM-001,2026-10-20T08:00:%02dZ,203.0.113.5,192.168.1.50,22,TCP,300,300,10,0\n" % s for s in (0, 10, 20))
        code, out, _ = self.run_events(self.csv(body), "--dedup-window", "60")
        self.assertEqual(code, 0, out)
        self.assertIn("incidents stored: 1", out)
        self.assertIn("2 repeat(s)", out)
        self.assertEqual(len(self.rows()), 1)

    # --- the real detector and the real report agree --------------------------------------------
    REAL_HEADER = ("device_id,timestamp,src_ip,dst_ip,dst_port,protocol,direction,failed_attempts,connection_attempts,"
                   "unique_dst_ports,Rate,syn_count\n")

    def need_real_detector(self):
        if rp.Modules().sources["detector"] != "real":
            self.skipTest("SKIPPED: Person 3's detector.py not found next to this folder (sibling folder Person 3)")

    def test_normal_camera_traffic_raises_no_incident_with_the_real_detector(self):
        self.need_real_detector()
        body = ("CAM-001,2026-10-20T08:00:00Z,192.168.1.20,192.168.1.50,554,TCP,inbound,0,150,1,40,1\n"      # many viewers
                "CAM-001,2026-10-20T08:01:00Z,192.168.1.50,52.29.14.7,8883,TCP,outbound,0,2,1,20,1\n"        # cloud MQTT
                "CAM-001,2026-10-20T08:02:00Z,192.168.1.50,52.29.14.7,443,TCP,outbound,0,1,1,1040,1\n"       # clip upload
                "CAM-001,2026-10-20T08:03:00Z,192.168.1.50,192.168.1.1,123,UDP,outbound,0,1,1,5,0\n")        # time sync
        code, out, _ = self.run_events(self.csv(body, self.REAL_HEADER), real_detector=True)
        self.assertEqual(code, 0, out)
        self.assertIn("benign       : 4", out)
        self.assertEqual(self.rows(), [])

    def test_report_names_the_same_mitre_technique_as_the_detector(self):
        self.need_real_detector()
        if rp.Modules().sources["report"] != "real":
            self.skipTest("SKIPPED: Person 7's report.py not found")
        body = ("CAM-001,2026-10-20T08:00:00Z,203.0.113.45,192.168.1.50,22,TCP,inbound,300,300,1,150,1\n"       # brute force T1110
                "CAM-001,2026-10-20T08:01:00Z,203.0.113.45,192.168.1.50,554,TCP,inbound,0,25000,1,37000,900\n"   # DoS T1498
                "CAM-001,2026-10-20T08:02:00Z,192.168.1.66,192.168.1.50,554,TCP,inbound,0,1000,1000,150,1\n"     # scan T1046
                "CAM-001,2026-10-20T08:03:00Z,192.168.1.66,192.168.1.50,4444,TCP,inbound,0,2,1,10,1\n")          # T1571
        code, out, _ = self.run_events(self.csv(body, self.REAL_HEADER), real_detector=True)
        self.assertEqual(code, 0, out)
        rows = self.rows()
        with dbmod.IncidentDB(self.db_path) as d:
            rows = d.query_incidents(limit=100, include_reports=True)
        self.assertEqual(len(rows), 4)
        expected = {"brute_force": "T1110", "dos": "T1498", "port_scan": "T1046", "unexpected_protocol_port": "T1571"}
        self.assertEqual({r["attack_type"] for r in rows}, set(expected), [r["attack_type"] for r in rows])
        for r in rows:
            self.assertIn(expected[r["attack_type"]], r["report_technical"], r["attack_type"])
            self.assertNotIn("see risk factors", r["report_technical"])


if __name__ == "__main__":
    unittest.main()
