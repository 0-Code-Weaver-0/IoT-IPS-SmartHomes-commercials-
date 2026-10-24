# SmartSecure Home: IoT Intrusion Prevention System (IoT-IPS)

Graduation project. An event (network features plus context) goes in; a detection, a risk score, a policy decision, a simulated response, a stored incident and two readable reports come out. Nothing here runs a real firewall command (dry-run only).

```
event -> Person 3 detector -> Person 4 risk engine -> Person 5 policy -> simulated action
                                                                              |
                         Person 7 reports <- Person 6 incident database <-----+
```

## Folders
| Folder | Owner | What it holds |
|---|---|---|
| `Person 1` | Architecture | design document (PDF) and addendum, shared `devices.json`, 14 sample events, expected results, `evaluate.py` |
| `Person 2` | ML data | CICIoT2023 train/test data, scripts and checks (Python 3.11+) |
| `Person 3` | Detector | rule-based `detector.py` and `rules.yaml` (the ML model replaces it later) |
| `Person 4` | Risk engine | `risk.py`, `weights.yaml` |
| `Person 5` | Policy and actions | `policy.py`, `policy.yaml`, `actions.py` (dry-run) |
| `Person 6` | Pipeline and database | `run_pipeline.py`, hash-chained incident DB, demo and test runner |
| `Person 7` | Reports | `report.py` (MITRE ATT&CK and GRC reports), samples |

The folders find each other by name (`Person 3`, `person3`, `person_3` all work), so keep them side by side.

## Quick start (Python 3.10+)
```
pip install -r requirements.txt
cd "Person 6"
python run_tests.py          # every test of every folder, one total (288)
python run_demo.py           # the 14 sample events through the real chain
cd "../Person 1"
python evaluate.py           # every event checked against expected_results.csv
```

## The event contract
- **features**: the flow statistics the model sees (CICIoT2023 column names: `Rate`, `syn_count`, ...).
- **context**: `device_id, timestamp, src_ip, dst_ip, dst_port, protocol, failed_attempts, connection_attempts`, optional `direction` (`inbound` / `outbound`), `unique_dst_ports`, `unique_dst_ips`. CICIoT2023 does not contain the context fields; the sample events add them by hand.
- **device profile** (`devices.json`): `device_id, device_type, ip, criticality, expected_ports, expected_protocols`, optional `expected_outbound_ports`.
- **detector**: `detect(event, device_profile) -> {label, attack_type, confidence, mitre_technique}`.

## Status
Rule-based detection works end to end (7 of 10 attacks, no false alarms on the 14 sample events). Next: train the ML model on Person 2's data and plug it into the detector slot; calibrate thresholds on the real camera; then consider real blocking. See `Person 1/Integration_Checklist.md` for open decisions and `Person 3/RULES_EXPLAINED.md` for the known limitations.
