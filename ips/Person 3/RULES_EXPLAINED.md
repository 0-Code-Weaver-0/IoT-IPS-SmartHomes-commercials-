# Detection rules explained

`detector.py` reads every threshold from `rules.yaml`. Each rule looks at ONE event (plus the device profile) and returns a confidence if it fires. The rule with the highest confidence wins; ties go to the more severe rule (order in the file).

| Rule | Attack type | MITRE | Fires when | Confidence |
|---|---|---|---|---|
| DoS | DoS | T1498 | `Rate` >= 1000 packets/s **or** `syn_count` >= 100, **and** (if the event carries it) `connection_attempts` >= 1000 | 0.80 at the threshold, 0.99 at 3x |
| Brute Force | Brute Force | T1110 | login port (22, 23, 554) or SSH/Telnet flag, **and** `failed_attempts` >= 50 | 0.80 to 0.98 |
| Port Scan | Port Scan | T1046 | `unique_dst_ports` >= 20 or `unique_dst_ips` >= 10 | 0.75 to 0.97 |
| Unexpected traffic | Unexpected Protocol/Port | T1571 | port or protocol is not in the device profile (see below) | 0.60 (one violation), 0.75 (both) |

## Why the rules look like this
- **Brute force counts failed logins only.** Many connections to the camera's own stream port (554) are normal viewing, not password guessing.
- **DoS needs many connections too.** A high packet rate from 1-3 connections is a bulk transfer (a video upload), not a flood. The check is skipped when the event has no `connection_attempts`; set `min_connection_attempts: 0` to turn it off.
- **Direction matters for unexpected traffic.** `direction: inbound` (or missing) is compared with the profile's `expected_ports` (what the device serves). `direction: outbound` is compared with `expected_outbound_ports` (where the device may connect: DNS, NTP, its cloud). If the profile has no outbound list, only the protocol is judged.
- **The profile must be passed.** `detect(event, device_profile)`: without it the unexpected-traffic rule cannot run (the pipeline passes it).

## rules.yaml is validated
A missing key, a misspelled key (`min_failed_attemptz`), an unknown rule, a negative threshold or a confidence outside 0..1 raises `RuleConfigError` with a clear message when the file loads. The pipeline checks it at start-up. Edits are picked up without restarting.

## Known limitations (evasion tests in `test_detector.py`)
- A **slow scan or low-rate brute force** that stays under the thresholds is missed by the scan and brute-force rules. (If it uses a port the camera does not serve, the unexpected-traffic rule may still raise a Medium alert, with the wrong attack type.)
- An **attack on an allowed port and protocol** at low volume looks normal.
- **ARP spoofing, web attacks and command injection** are not detected: they need ARP/MAC data or payload inspection.
- Rules judge one event at a time, with no memory across events. Repeated alerts are grouped by the pipeline's `--dedup-window`.
- The thresholds are starting values chosen by reasoning, not tuned on traffic from the real camera.

The ML model (next phase) must expose the same `detect(event, device_profile)` function and return the same four keys.

## Run
```
pip install pyyaml
python test_detector.py        # 35 tests (also works with: python -m pytest)
python detector.py             # one demo event
```
