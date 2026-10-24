#!/usr/bin/env python3
"""Sends a Telegram message for every NEW High or Critical IPS incident (and when an incident gets worse).

It only READS the API (polling), so it needs no MQTT user or ACL change. Dry-run (print only) unless Telegram is configured:
    TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... python scripts/ips/notifier.py --once
    python scripts/ips/notifier.py --interval 15            # keep running
State (what was already sent) is kept in a small JSON file so a restart never repeats alerts.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ips_transport import add_transport_args, make_transport  # noqa: E402

RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def select_new(incidents, sent, min_level="high", prefix="INC-"):
    """Incidents to notify now: level >= min_level and not yet sent at that level or higher. Pure function."""
    out = []
    for i in incidents or []:
        lvl = RANK.get(str(i.get("level")), -1)
        if not str(i.get("id", "")).startswith(prefix) or lvl < RANK[min_level]:
            continue
        if sent.get(i["id"], -1) < lvl:
            out.append(i)
    return out


def message_for(incident, events):
    reps = [e for e in events or [] if e.get("type") == "engine.ips_report"]
    text = (reps[-1].get("data", {}).get("notification") if reps else None) or incident.get("summary") or incident["id"]
    return str(text)[:3500]


def send_telegram(token, chat_id, text):
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    with urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % token, data=data, timeout=15) as r:
        return r.status == 200


def run_once(t, state_path, sender, min_level="high", max_per_run=5):
    sent = json.loads(state_path.read_text()) if state_path.exists() else {}
    _, incs = t.api("GET", "/incidents", params={"limit": 100})
    todo = select_new(incs, sent, min_level)[:max_per_run]
    for i in todo:
        _, evs = t.api("GET", "/incidents/%s/events" % i["id"])
        if sender(message_for(i, evs)):
            sent[i["id"]] = RANK[i["level"]]
    state_path.write_text(json.dumps(sent))
    return [i["id"] for i in todo]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    add_transport_args(p)
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=float, default=15)
    p.add_argument("--min-level", default="high", choices=list(RANK))
    p.add_argument("--state", default=str(Path(__file__).resolve().parent / ".notifier_state.json"))
    a = p.parse_args(argv)
    tok, chat = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    sender = (lambda text: send_telegram(tok, chat, text)) if tok and chat else (lambda text: print("[dry-run]\n" + text + "\n") or True)
    t = make_transport(a)
    while True:
        ids = run_once(t, Path(a.state), sender, a.min_level)
        if ids:
            print("notified:", ", ".join(ids))
        if a.once:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
