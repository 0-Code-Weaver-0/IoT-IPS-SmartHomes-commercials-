#!/usr/bin/env python3
"""One command for the whole demo:  python run_demo.py

Runs Person 1's sample events (14 events, 6 devices) through the REAL chain - Person 3's detector, Person 4's risk
engine, Person 5's policy engine and Person 7's reports - into incidents.db, prints the incidents and the count by
level, then verifies the hash chain. Nothing here touches a real firewall.

It stops with a clear message if Person 3's or Person 7's folder is missing, so a demo can never silently run on the
placeholders. Use  python run_demo.py --allow-placeholders  to run without them (local sample_events.csv).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_pipeline  # noqa: E402


def sibling_file(person: int, name: str):
    parent = os.path.dirname(HERE)
    for folder in sorted(os.listdir(parent)):
        if re.fullmatch("person%d" % person, re.sub(r"[^a-z0-9]", "", folder.lower())):
            path = os.path.join(parent, folder, name)
            if os.path.isfile(path):
                return path
    return None


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    allow = "--allow-placeholders" in argv
    events = sibling_file(1, "sample_events.csv") or os.path.join(HERE, "sample_events.csv")
    devices = sibling_file(1, "devices.json") or os.path.join(HERE, "devices.json")
    db = os.path.join(HERE, "incidents.db")
    log = os.path.join(HERE, "actions.jsonl")
    run = ["run", events, "--db", db, "--action-log", log, "--devices", devices, "--reset"]
    if not allow:
        run.append("--require-real")
    status = 0
    for step in (run, ["show", "--db", db], ["verify", "--db", db]):
        print("\n$ run_pipeline.py " + step[0] + "\n")
        try:
            status = max(status, run_pipeline.main(step))
        except run_pipeline.PipelineError as exc:
            print("error: %s" % exc)
            return 2
    return status


if __name__ == "__main__":
    sys.exit(main())
