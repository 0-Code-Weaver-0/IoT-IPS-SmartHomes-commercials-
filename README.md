# IoT-IPS (graduation project)

One repository: the SmartSecure Home backend and our IoT-IPS, linked together:

| Part | Where | What it is |
|---|---|---|
| **Backend** (from the SmartSecure-Home repo) | `services/`, `libs/`, `infra/`, `config/`, `contract/`, `docker-compose.yml`, `Makefile` | API (JWT, REST, WebSocket), MQTT broker with TLS and ACLs, simulators, `cyber` (Suricata detection and blocking), `engine` (risk, incidents, responses), `vision`. Its own readme: `docs/BACKEND_README.md`; message formats: `docs/CONTRACT.md`. |
| **IoT-IPS** (our work) | `ips/` | Rule-based detector (Person 3), risk engine (4), policy and simulated actions (5), pipeline and hash-chained incident database (6), MITRE/GRC reports (7), data and design (1, 2). 288 tests. Start with `ips/README.md`. |
| **Warden dashboard** (our work) | `services/frontend/index.html` | Floor-plan digital twin, network graph, live incident list and incident detail (MITRE, risk factors, reports, timeline). Tested with `services/frontend/test`. The backend team's original dashboard is kept for reference in `services/frontend/reference/`. |
| **Link between them** | `scripts/ips/`, `docs/IPS_WARDEN.md` | Adapter from an IPS detection to the contract-v1.2 events, device seeding, a fake publisher, an end-to-end checker. Design: `docs/IPS_INTEGRATION.md`. |

## Run
```bash
make setup && make up                     # backend + dashboard (http://localhost:8080)
cd ips/"Person 6" && python run_tests.py  # the IoT-IPS tests (needs: pip install -r ips/requirements.txt)
python run_demo.py                        # the IoT-IPS demo
python scripts/ips/seed_ips_devices.py --devices "ips/Person 1/devices.json"   # IPS devices into Warden
python scripts/ips/fake_ips_publisher.py --now --repeat 2                      # sample IPS incidents
```

## Status
- Backend and IoT-IPS each work and are tested on their own.
- The link is built and tested against a real API and broker, but it still publishes incidents directly. Next: make the IPS feed the backend `engine` with scored `cyber.*` alerts.
