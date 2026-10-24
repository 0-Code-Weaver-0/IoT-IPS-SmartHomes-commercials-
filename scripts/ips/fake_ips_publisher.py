#!/usr/bin/env python3
"""Publishes realistic IoT-IPS incidents into the stack, so the dashboard can be built and tested before the real
`cyber` and `engine` services exist. Uses ips_to_backend.py, the same adapter the real engine will use.

    python scripts/ips/fake_ips_publisher.py                       # every sample incident (docker stack)
    python scripts/ips/fake_ips_publisher.py --only brute_force --now --repeat 3
    python scripts/ips/fake_ips_publisher.py --list

--now      use the current time instead of the sample's own time (so Warden shows "just now")
--repeat N the same attack N times: ONE incident that grows (the incident id is re-sent with more events)
"""
import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ips_to_backend as m  # noqa: E402
from ips_transport import add_transport_args, make_transport  # noqa: E402

SAMPLES = Path(__file__).resolve().parent / "ips_samples.json"


def load_samples() -> list:
    return json.loads(SAMPLES.read_text(encoding="utf-8"))


def plan(samples, only=None, now=False, repeat=1, step=20.0):
    """All (topic, payload) pairs to publish, in order. Pure function: used by the tests."""
    base = datetime.now(timezone.utc) if now else None
    out = []
    for n, s in enumerate(samples):
        if only and s["name"] not in only:
            continue
        ids = []
        for r in range(repeat):
            ts = (base + timedelta(seconds=n * 3 + r * step)) if base else (
                datetime.fromisoformat(m.iso(s["incident"].get("timestamp"))) + timedelta(seconds=r * step))
            res = m.build_messages(s["incident"], s["report"], s["profile"], previous_event_ids=ids, ts=ts)
            ids = res["event_ids"]
            for topic, payload in res["messages"]:
                m.check_message(topic, payload)
                out.append((topic, payload))
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    add_transport_args(p)
    p.add_argument("--only", action="append", help="sample name (repeatable); see --list")
    p.add_argument("--list", action="store_true")
    p.add_argument("--now", action="store_true")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--delay", type=float, default=1.0, help="seconds between incidents")
    p.add_argument("--dry-run", action="store_true", help="validate and print, do not publish")
    a = p.parse_args(argv)
    samples = load_samples()
    if a.list:
        for s in samples:
            i = s["incident"]
            print("%-18s %s  %-9s %3s  %s" % (s["name"], i["id"], i["level"], i["score"], i["attack_type"]))
        return 0
    known = {s["name"] for s in samples}
    if a.only and not set(a.only) <= known:
        print("unknown sample(s): %s (see --list)" % ", ".join(sorted(set(a.only) - known)))
        return 2
    msgs = plan(samples, a.only, a.now, max(1, a.repeat))
    if a.dry_run:
        for topic, payload in msgs:
            print(topic, json.dumps(payload)[:140])
        print("%d messages valid" % len(msgs))
        return 0
    t = make_transport(a)
    last = None
    for topic, payload in msgs:
        t.publish(topic, payload)
        if topic == "security/incidents":
            print("incident %s  %-8s %3d  %s" % (payload["id"], payload["level"], payload["score"], payload["summary"]))
            if last != payload["id"]:
                time.sleep(a.delay)
            last = payload["id"]
    if hasattr(t, "close"):
        t.close()
    print("published %d messages" % len(msgs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
