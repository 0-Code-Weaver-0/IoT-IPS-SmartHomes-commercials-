# Security Incident Report: INC-00003

**Classification:** CRITICAL (82/100) | **Status:** Open | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00003 |
| Detected (UTC) | 2026-10-20T08:08:15Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 15 minutes (proposed internal target) |
| Escalation | Immediate escalation to the IoT Security Lead and the System Owner; management informed. |

## 1. Executive summary
The IoT-IPS detected **credential brute-force attempt** against **CAM-001** from **192.168.1.77** with 98% confidence. The event is rated **Critical** (82/100). Response taken: block decided (dry-run, not executed); isolation decided (dry-run, not executed); notification sent to the administrator. Current status: **open**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 192.168.1.77 (unknown internal host) |
| Destination | 192.168.1.50:22 / TCP |
| Attempts or events observed | 431 |
| Duration | - |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | T1110 Brute Force |
| Reference | https://attack.mitre.org/techniques/T1110/ |
| Security property at risk | Confidentiality (exposure of data) |

**Analyst assessment:** The source made a large number of failed authentication attempts against a device service (for example SSH, Telnet or RTSP) to guess valid credentials.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 98/100 | 0.20 | 19.6 |
| Attack Severity | 70/100 | 0.25 | 17.5 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 100/100 | 0.15 | 15.0 |
| Source Trust | 60/100 | 0.10 | 6.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 75/100 | 0.05 | 3.8 |

- **Likelihood:** High (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** Critical (82/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a high likelihood that this incident (credential brute-force attempt against CAM-001) results in exposure of data, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Block decided (dry-run, not executed); Isolation decided (dry-run, not executed); Notification sent to the administrator.

Dry-run commands (not executed):
```
iptables -I FORWARD -s 192.168.1.77 -m comment --comment iot-ips -j DROP
iptables -I FORWARD -s 192.168.1.50 -m comment --comment iot-ips -j DROP
iptables -I FORWARD -d 192.168.1.50 -m comment --comment iot-ips -j DROP
```

**Policy decision:** rule critical_certain matched: level Critical, score 82, confidence 0.98, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Simulated (dry-run, nothing executed) |
| Eradication and recovery | Pending analyst verification |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Block the source (the system only simulated the block) and verify that no login succeeded.
2. Check the device for new accounts or configuration changes.
3. Change the device credentials if there is any doubt.

**Short term (corrective)**
1. Replace default credentials with unique strong ones.
2. Disable Telnet and any remote access that is not needed.
3. Add lockout or rate limiting for failed logins.

**Long term (preventive)**
1. Use certificate or key based access where the device supports it.
2. Include credential hygiene in the IoT onboarding checklist.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.AE | Adverse event analysis |
| NIST CSF 2.0 | RS.MI | Incident mitigation |
| ISO/IEC 27001:2022 | A.8.5 | Secure authentication |
| ISO/IEC 27001:2022 | A.5.26 | Response to information security incidents |

- **Risk register:** record as *RISK-INC-00003*: Credential brute-force attempt on CAM-001; inherent rating Critical; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `946d6e5bdeddddea7646a4275ce7ea70bec3154b85ae4ea37c526414527a0088`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
