"""demo_chain.py - a hand-written scenario chain (NOT the project samples; those come from make_samples.py). Runs the real chain: event -> detection -> risk (P4) -> policy (P5) -> incident -> reports (P7).
Needs Person 4's risk.py/weights.yaml and Person 5's policy.py/actions.py/policy.yaml somewhere next to this file
(same folder, a sub-folder, or a sibling folder). Run: python demo_chain.py
"""
import json, sys, warnings
from pathlib import Path
warnings.simplefilter("ignore")
here = Path(__file__).resolve().parent
for base in (here, here.parent):
    for d in [base] + [p for p in base.iterdir() if p.is_dir()]:
        if (d / "risk.py").exists() or (d / "policy.py").exists():
            sys.path.insert(0, str(d))
import risk, policy
from actions import ActionExecutor
from report import build_incident, make_report

def _load_devices():
    for base in (here, here.parent):
        for f in [base / "devices.json"] + [p / "devices.json" for p in sorted(base.iterdir()) if p.is_dir()]:
            if f.is_file():
                data = json.loads(f.read_text(encoding="utf-8"))
                return {x["device_id"]: x for x in (data.get("devices", []) if isinstance(data, dict) else data)}
    sys.exit("devices.json (Person 1 / Person 6) not found next to this folder.")
DEV = _load_devices()   # the one device list of the project (Person 1's devices.json)
A = lambda t, c: {"label": "ATTACK", "attack_type": t, "confidence": c}
SCENARIOS = [  # (device, detection, event)
 ("BULB-001", A("port_scan", .55), {"timestamp": "2026-10-18T09:12:40Z", "src_ip": "192.168.1.20", "dst_port": 80, "connection_attempts": 3, "protocol": "TCP", "duration": "6 seconds"}),
 ("TEMP-001", A("unexpected_protocol", .82), {"timestamp": "2026-10-18T13:47:05Z", "src_ip": "192.168.1.77", "dst_port": 4444, "connection_attempts": 9, "protocol": "TCP", "duration": "3 minutes"}),
 ("CAM-001", A("dos", .91), {"timestamp": "2026-10-19T02:31:18Z", "src_ip": "192.168.1.134", "dst_port": 554, "connection_attempts": 48200, "protocol": "TCP", "duration": "90 seconds"}),
 ("CAM-001", A("brute_force", .94), {"timestamp": "2026-10-19T21:05:52Z", "src_ip": "192.168.1.100", "dst_port": 22, "failed_attempts": 431, "protocol": "TCP", "duration": "4 minutes"}),
 ("CAM-001", A("brute_force", .94), {"timestamp": "2026-10-20T08:20:10Z", "src_ip": "192.168.1.10", "dst_port": 22, "failed_attempts": 431, "protocol": "TCP", "duration": "4 minutes"}),  # allow-listed source
]
if __name__ == "__main__":
    out = here / "demo_chain_out"; out.mkdir(exist_ok=True)
    pol = policy.load_policy(); ex = ActionExecutor.from_policy(pol, log_path=str(out / "action_log.jsonl"))
    built = []
    for i, (dev, det, ev) in enumerate(SCENARIOS, 28):
        prof = DEV[dev]; ev = dict(ev, dst_ip=prof["ip"])
        rk = risk.assess(det, ev, prof)
        dc = policy.decide(rk, det, ev, prof, pol); ex.run(dc)
        inc = build_incident(ev, det, rk, dc, prof, incident_id=f"INC-{i:05d}")
        built.append(inc)
        r = make_report(inc); tag = f"{inc['id']}_{inc['level'].lower()}"
        (out / f"{tag}_technical.md").write_text(r["technical"], encoding="utf-8", newline="\n")
        (out / f"{tag}_executive.md").write_text(r["executive"], encoding="utf-8", newline="\n")
        if r["notification"]: (out / f"{tag}_notification.txt").write_text(r["notification"], encoding="utf-8", newline="\n")
        print(inc["id"], inc["level"], inc["score"], dc["action"], "| skipped:", dc["skipped"])
    # the merged incidents, so `python report.py <file>` can rebuild the same reports from them
    (out / "demo_chain_incidents.json").write_text(json.dumps(built, indent=2, default=str), encoding="utf-8", newline="\n")
    print("wrote demo_chain_out/demo_chain_incidents.json")
