# Person 2: ML data (CICIoT2023)

## What is inside

| File | What it is |
|---|---|
| `data/train.csv` | 160,000 rows: 18 features + `label` (BENIGN/ATTACK) + `attack_group` + `original_label` |
| `data/test.csv` | 40,000 rows, same columns, no row shared with train |
| `data/features.txt` | the 18 features, what each means, why it was chosen, and what was dropped |
| `data/data_summary.md` | sources, what was removed, class balance, missing context fields |
| `data/sample_events.csv` | 14 events (4 benign, 10 attacks incl. 2 evasion cases): real test rows with all 39 features + context fields |
| `scripts/check_data.py` | 32 checks of the files above against the task plan |
| `scripts/prepare_data.py`, `make_sample_events.py`, `write_docs.py` | how the files were built |

`sample_events.csv` columns: `event_id, device_id, timestamp, src_ip, dst_ip, dst_port, protocol,
failed_attempts, connection_attempts`, then the 39 CICIoT2023 features, then
`expected_label, expected_attack_type, original_label, story`. The `expected_*` columns are the
answers for checking results; the detector must not read them. Device ids CAM-001, THERMO-001,
PLUG-001 = 192.168.1.50 / .51 / .52.

## Check the files (Windows, from this folder)

Needs Python 3.11 or newer (the data scripts only; the IPS modules of the other people run on 3.10+).

Note: `data/sample_events.csv` is the integrated version maintained in the `Person 1` folder (adds `direction`, `unique_dst_ports` and `unique_dst_ips`). `make_sample_events.py` builds the older layout; copy Person 1's file over it after regenerating.

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts\check_data.py
```

It must end with `32/32 checks passed`. On macOS/Linux: `source .venv/bin/activate` and
`python scripts/check_data.py`.

## Use the data in your own code

```python
import pandas as pd
train = pd.read_csv("data/train.csv")
events = pd.read_csv("data/sample_events.csv")
features = [c for c in train.columns if c not in ("label", "attack_group", "original_label")]
```

## Rebuilding from the raw dataset (only Person 2)

`prepare_data.py`, `make_sample_events.py` and `write_docs.py` rebuild everything from the raw
CICIoT2023 CSV files (about 600 MB, not included). The results are reproducible: fixed random
seeds give byte-identical files.

## Before training the model (next week)
- **Split:** `train.csv` / `test.csv` are a random row split. Rows from the same capture are correlated, so metrics on this test set are optimistic. Use a capture-aware split if capture identifiers can be recovered, otherwise keep a separate hold-out file that is never used for tuning, and also test on Person 1's 14 events.
- **Coverage:** only part of the CICIoT2023 files was downloaded (see `data_summary.md`).
- **Class balance:** the data is balanced 50/50 on purpose. Real traffic is almost all benign, so expect more false alarms live; report the false-positive rate, not only accuracy.
- **Interface:** the model must expose `detect(event, device_profile)` and return the four keys of the detector contract (see `Person 3/RULES_EXPLAINED.md`).
