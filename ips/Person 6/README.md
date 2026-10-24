# Person 6: pipeline and incident database

One command per job:

| Command | What it does |
|---|---|
| `python run_demo.py` | Whole demo: run Person 1's `sample_events.csv` through the real chain, print the incidents and a count by level, verify the database. Stops if Person 3's or Person 7's folder is missing (`--allow-placeholders` overrides). |
| `python run_tests.py` | Every unit test in this folder and in the sibling `person3` ... `person7` folders, one total. |
| `python run_pipeline.py run sample_events.csv` | Process a CSV into `incidents.db` (add `--reset` to start clean). |
| `python run_pipeline.py show` | Table of stored incidents plus the count by level and by status. Filters: `--level`, `--device`, `--source`, `--attack`, `--status`, `--since`, `--limit`. |
| `python run_pipeline.py show --full INC-00005` | One incident with its technical report, executive report and notification. |
| `python run_pipeline.py verify` | Checks the hash chain for edited or deleted rows. Exit code 1 if tampering is found. |

Needs Python 3.10+ and PyYAML (`pip install pyyaml`).

## Folder layout

Put the team folders next to each other. Any spelling works (`person4`, `Person 4`, `person_4`):

```
project/
  person4/   risk.py, weights.yaml
  person5/   policy.py, policy.yaml, actions.py
  person6/   run_pipeline.py, db.py, placeholders.py ...   <- this folder
  person7/   report.py
  person3/   detector.py, rules.yaml
```

`risk.py`, `policy.py` and `actions.py` are required. `detector.py` (needs `detect(event)`) and `report.py` (needs `make_report` and `build_incident`) replace the placeholders automatically when they are found. The first line of every run prints which modules are real.

## The flow

```
CSV row -> detect -> risk.assess -> policy.decide -> ActionExecutor.run -> (create_incident?) -> IncidentDB + reports
```

* A benign verdict stores nothing.
* An incident is stored only when the policy's actions contain `create_incident`.
* Everything is a simulation. `dry_run` is always true; no firewall command runs. Because of that the status is `open` (or `monitoring` for Low), never `contained`.

## Incident table

Person 1's fields, with these differences: the single `report` column is three (`report_technical`, `report_plain` = the executive report, `report_notification` = High/Critical only), and the risk and action fields are split into `risk_score`, `risk_level`, `risk_factors`, `action`, `action_result`.

`incident_id, timestamp, device_id, device_type, src_ip, dst_ip, dst_port, attack_type, confidence, risk_score, risk_level, risk_factors, risk_warnings, weight_set, attempts, action, action_result, reason, rule_id, status, dry_run, report_*, created_at, prev_hash, row_hash`

Python use:

```python
from db import IncidentDB
with IncidentDB("incidents.db") as d:
    d.query_incidents(level="Critical")
    d.summary_by_level()
    d.set_status("INC-00005", "resolved")      # the only editable field
```

## Input format (CSV)

Columns used: `device_id, timestamp, src_ip, dst_ip, dst_port, protocol, failed_attempts, connection_attempts` plus any CICIoT2023-style columns (`Rate`, `syn_flag_number`, ...). Columns starting with `expected_` are for humans and are never passed on. A missing value becomes a cautious default and a note such as `missing_src_ip` in the incident's warnings.

Devices come from `devices.json`; each profile needs `device_id, device_type, ip, criticality, expected_ports`. Without `ip`, isolation is skipped; without `expected_ports`, deviation scoring is skipped.

## Safety

* Only parameterised SQL. Every field is validated and length-limited before it is stored.
* Rows are hash-chained (SHA-256). Set the environment variable `IOTIPS_DB_KEY` (16+ characters) for an HMAC chain that someone who can edit the file cannot recompute. Keep the `head hash` that `run` prints somewhere else and pass it to `verify --head` to also catch deleted last rows.
* The database file is created with owner-only permissions; symbolic links are refused.
* CSV limits: 20 MB, 100,000 rows, 300 columns; bad rows are skipped and counted; text from the CSV is never printed back in errors.
* Exit codes: 0 clean, 1 tampering found, 2 bad input or errors.

## Options and behaviour added in the integration release

| Option | What it does |
|---|---|
| `--dedup-window SECONDS` | A repeat of the same attack (same device, source and attack type) inside the window is counted, not stored again. The window slides, so one continuing attack stays one incident. A repeat with a higher level is always stored. Default 0 (off). |
| `--placeholders [all\|detector\|report]` | Use the built-in placeholder for that module. The unit tests use `--placeholders detector`, so they do not depend on Person 3's thresholds. |
| `--require-real` | Stop with an error if Person 3's detector or Person 7's report module was not found. |

* The detector now receives the device profile: `detect(event, device_profile)`. Any replacement detector (the ML model) must accept both arguments.
* `rules.yaml` is validated when the run starts; a misspelled or missing key stops the run with `detector configuration problem: ...` instead of silently switching a rule off.
* Device profiles may carry `expected_outbound_ports`. Events may carry `direction` (`inbound` or `outbound`).
* Actions run before the incident is saved on purpose: containment must not depend on the database. If saving fails, the event is reported as an error and the action log still holds what was done.

## Known limitations

* Without Person 3's folder the pipeline falls back to a placeholder detector (a few thresholds); `run_demo.py` and `--require-real` refuse to run that way. Attack names must match the other modules (`brute_force`, `dos`, `port_scan`, ...); Person 4's `canonical_attack_name()` accepts the detector's names.
* The 10 sample scenarios were hand-picked; they show the chain works, they are not a measurement of accuracy.

## CI

`.github/workflows/tests.yml` (in the root of the repository, next to the team folders) runs `run_tests.py`, `run_demo.py`, `demo_chain.py` and `make_samples.py` on every push (Python 3.10 and 3.12). It finds the folders itself, so `Person 6`, `person6` and `person_6` all work.
