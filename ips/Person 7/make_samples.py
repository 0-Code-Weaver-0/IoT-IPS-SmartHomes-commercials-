"""make_samples.py - Person 7: build the sample reports from REAL pipeline output.

    python make_samples.py

Runs Person 6's run_pipeline on sample_events.csv with the real report.py, then takes one stored
incident per level (the highest score of that level) and writes its technical report, its
non-technical report and (High/Critical) its notification into ./sample_reports.
The reports are exactly what the pipeline stored in the incident database.
"""
import json
import os
import sys
import tempfile
import warnings
from pathlib import Path

warnings.simplefilter("ignore")
HERE = Path(__file__).resolve().parent
LEVELS = ("Low", "Medium", "High", "Critical")


def find_pipeline_folder():
    for base in (HERE, HERE.parent):
        for d in [base] + sorted(p for p in base.iterdir() if p.is_dir()):
            if (d / "run_pipeline.py").is_file() and (d / "sample_events.csv").is_file() and (d / "devices.json").is_file():
                return d
    sys.exit("run_pipeline.py, sample_events.csv and devices.json (Person 6) were not found next to this folder.")


def main():
    p6 = find_pipeline_folder()
    sys.path.insert(0, str(p6))
    sys.path.insert(1, str(HERE))          # the real report.py (Person 7) before the placeholder
    import run_pipeline, db as dbmod
    with tempfile.TemporaryDirectory() as tmp:
        dbfile, log = os.path.join(tmp, "samples.db"), os.path.join(tmp, "actions.jsonl")
        code = run_pipeline.main(["run", str(p6 / "sample_events.csv"), "--db", dbfile, "--action-log", log,
                                  "--devices", str(p6 / "devices.json"), "--reset"])
        if code not in (0, 2):
            sys.exit("pipeline failed with status %s" % code)
        out = HERE / "sample_reports"
        out.mkdir(exist_ok=True)
        for old in out.iterdir():
            if old.is_file():
                old.unlink()
        _data = json.loads((p6 / "devices.json").read_text(encoding="utf-8"))
        known = {d["device_id"] for d in (_data.get("devices", []) if isinstance(_data, dict) else _data)}   # real devices only, not rows with a missing device
        with dbmod.IncidentDB(dbfile) as database:
            rows = database.query_incidents(limit=1000, include_reports=True)
            for level in LEVELS:
                same = [r for r in rows if r["risk_level"] == level and r.get("report_technical") and r.get("device_id") in known]
                if not same:
                    print("no %s incident in the pipeline output" % level)
                    continue
                inc = max(same, key=lambda r: r["risk_score"])
                tag = "%s_%s" % (inc.get("incident_id") or "INC-%05d" % inc["id"], level.lower())
                (out / (tag + "_technical.md")).write_text(inc["report_technical"], encoding="utf-8", newline="\n")
                (out / (tag + "_executive.md")).write_text(inc["report_plain"], encoding="utf-8", newline="\n")
                if inc.get("report_notification"):
                    (out / (tag + "_notification.txt")).write_text(inc["report_notification"], encoding="utf-8", newline="\n")
                print("wrote", tag, "score", inc["risk_score"])


if __name__ == "__main__":
    main()
