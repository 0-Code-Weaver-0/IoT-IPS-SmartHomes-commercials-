# IoT-IPS in Warden: how the pieces connect

The `cyber` and `engine` services in this backend are placeholders, and the API accepts incidents only through MQTT. The IoT-IPS therefore sends four messages per incident (built by `scripts/ips/ips_to_backend.py`):

| Topic | Type | Purpose |
|---|---|---|
| `security/alerts/cyber` | `cyber.port_scan`, `cyber.brute_force`, `cyber.dos`, `cyber.unexpected_traffic` | the detection |
| `security/alerts/engine` | `engine.ips_report` | the reports and MITRE tag in free-form `data` (the API drops unknown incident fields, so they cannot ride on the incident) |
| `security/risk` | zone risk | the dashboard gauge |
| `security/incidents` | incident | re-sent with the SAME id and a longer `events` list when the attack continues |

Event ids are deterministic, so re-sending is safe (the API ignores duplicate events).

## Try it (docker stack running: `docker compose up -d`)
```bash
python scripts/ips/seed_ips_devices.py --devices "ips/Person 1/devices.json"   # registers the 6 IPS devices
python scripts/ips/fake_ips_publisher.py --now --repeat 2                     # 7 incidents, each updated once
python scripts/ips/ips_e2e_check.py                                           # PASS/FAIL checks through the API
python scripts/ips/test_ips.py                                                # offline unit tests
cd services/frontend/test && npm install && npm test                          # dashboard test (real API fixtures)
```
Rebuild the dashboard after changing `index.html`: `docker compose up --build -d frontend`, then Ctrl+F5.
`python scripts/ips/fake_ips_publisher.py --list` shows the sample incidents; `--only brute_force` sends one.

## Notifications
`python scripts/ips/notifier.py --once` prints the alert (dry-run). Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` to send for real. It only reads the API (no ACL change).

## Contract additions still to merge (docs/CONTRACT.md, config/risk_scores.yaml)
- event types `cyber.dos`, `cyber.unexpected_traffic`, `engine.ips_report` (+ the `data` fields used in `ips_to_backend.py`)
- levels: the IPS uses 0/30/60/80, `risk_scores.yaml` uses 0/31/61/91; pick one scale
- device `status` for IPS devices needs a publisher (ACL: only `simulators` and `admin` may write `home/+/+/+/status`)

## Not done yet
The Devices page, the first Live Alerts entries, the Security Copilot answers and the top counters still show demo data.
