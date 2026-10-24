#!/usr/bin/env python3
"""Checks, through the API, that IPS incidents reached the backend with their reports (run after fake_ips_publisher.py).
Exit code 0 = all checks passed.   python scripts/ips/ips_e2e_check.py [--expect 7]"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ips_transport import add_transport_args, make_transport  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    add_transport_args(p)
    p.add_argument("--expect", type=int, default=7, help="minimum number of INC-* incidents expected")
    a = p.parse_args(argv)
    t = make_transport(a)
    bad = []

    def check(ok, text):
        print(("PASS  " if ok else "FAIL  ") + text)
        if not ok:
            bad.append(text)
    _, devices = t.api("GET", "/devices")
    ids = {d["device_id"] for d in devices or []}
    check({"cam_001", "thermo_001"} <= ids, "IPS devices are registered (%d devices)" % len(ids))
    _, incs = t.api("GET", "/incidents", params={"limit": 100})
    mine = [i for i in incs or [] if str(i["id"]).startswith("INC-")]
    check(len(mine) >= a.expect, "at least %d IPS incidents stored (found %d)" % (a.expect, len(mine)))
    for i in mine:
        _, evs = t.api("GET", "/incidents/%s/events" % i["id"])
        types = [e["type"] for e in evs or []]
        rep = [e for e in evs or [] if e["type"] == "engine.ips_report"]
        ok = bool(rep) and any(x.startswith("cyber.") for x in types)
        d = rep[-1]["data"] if rep else {}
        ok = ok and bool(d.get("report_technical")) and bool(d.get("report_plain")) and bool(d.get("mitre_technique"))
        check(ok, "%s: alert + report events with MITRE and both reports (%d events, %s)" % (i["id"], len(types), i["level"]))
        check([e["ts"] for e in evs or []] == sorted(e["ts"] for e in evs or []), "%s: timeline is in time order" % i["id"])
    _, risk = t.api("GET", "/risk")
    check(any(r["level"] in ("high", "critical") for r in risk or []), "a high or critical zone risk is published")
    print("\n%s" % ("ALL CHECKS PASSED" if not bad else "%d CHECK(S) FAILED" % len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
