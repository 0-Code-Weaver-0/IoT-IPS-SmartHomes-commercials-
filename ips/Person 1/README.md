# Person 1: Architecture and Documentation

Smart Secure Home, IoT-IPS graduation project. Supervisor: Dr. Amr Megahed. Egyptian Chinese University, Faculty of Computer Science.

## Files

| File | What it is |
|---|---|
| `IoT_IPS_Design_Document.pdf` | The design document: architecture, shared contract, risk model, detection rules, response policy, incident database, reports, data, threat model, demo and evaluation. |
| `devices.json` | The six device profiles (CAM-001 is the main one). Used by the pipeline, the risk engine and the demo. |
| `sample_events.csv` | The 14 demo events: Person 2's real CICIoT2023 rows plus the context fields of the contract. |
| `expected_results.csv` | What each event should produce, written from its story before the run. |
| `Integration_Checklist.md` | Status of every integration fix, and what is still open. |
| `Design_Document_Addendum.md` | What changed after the PDF (contract, rules, results, tests). |
| `evaluate.py` | Runs the 14 events through the real chain and compares each with `expected_results.csv`. |

## Run the demo

Put the team folders next to each other (any spelling: `person4`, `Person 4`, `person_4`):

```
project/
  Person 1/   this folder
  person2/    data/
  person3/    detector.py, rules.yaml
  person4/    risk.py, weights.yaml
  person5/    policy.py, policy.yaml, actions.py
  person6/    run_pipeline.py, db.py, placeholders.py, run_demo.py, run_tests.py
  person7/    report.py
```

Then, from the `person6` folder:

```
python run_pipeline.py run "../Person 1/sample_events.csv" --devices "../Person 1/devices.json" --db demo.db --reset
python run_pipeline.py show --db demo.db
python run_pipeline.py verify --db demo.db
python run_tests.py
```

Or, from this folder: `python evaluate.py`.

Needs Python 3.10 or newer and PyYAML (`pip install pyyaml`). Person 2's data scripts need Python 3.11 or newer.

## Result of the integrated demo

14 events (4 benign, 10 attacks) give 7 incidents (2 Medium, 1 High, 4 Critical). 7 of 10 attacks raise an alert and none of the 4 benign events does (precision 1.00, recall 0.70, F1 0.82). Run `python evaluate.py` to see every event. The PDF still shows the first release (6 of 10, 1 false alarm); see `Design_Document_Addendum.md`.

## Changes made to Person 2's sample events

Columns `unique_dst_ports` and `unique_dst_ips` were added (the port-scan rule reads them). `failed_attempts` counts failed logins only, so it is 0 for scans, floods, the vulnerability scan and the command injection. The port-scan event uses port 8080 as the last port probed. The feature values are unchanged, and Person 2's 32 data checks still pass.
