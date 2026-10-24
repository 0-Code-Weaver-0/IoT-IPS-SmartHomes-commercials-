# Security Incident Report: INC-00030

**Classification:** HIGH (76/100) | **Status:** Simulated containment | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00030 |
| Detected (UTC) | 2026-10-19T02:31:18Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 1 hour (proposed internal target) |
| Escalation | Escalate to the IoT Security Lead; the System Owner is informed. |

## 1. Executive summary
The IoT-IPS detected **network denial-of-service (syn flood)** against **CAM-001** from **192.168.1.134** with 91% confidence. The event is rated **High** (76/100). Response taken: temporary block decided (dry-run, not executed); notification sent to the administrator. Current status: **simulated containment**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 192.168.1.134 (unknown internal host) |
| Destination | 192.168.1.50:554 / TCP |
| Attempts or events observed | 48200 |
| Duration | 90 seconds |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Impact (TA0040) |
| Technique | T1498 Network Denial of Service |
| Reference | https://attack.mitre.org/techniques/T1498/ |
| Security property at risk | Availability (loss of service) |

**Analyst assessment:** The source sent traffic at a rate far above the device's baseline, aiming to exhaust its network or processing capacity and make it unavailable.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 91/100 | 0.20 | 18.2 |
| Attack Severity | 75/100 | 0.25 | 18.8 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 100/100 | 0.15 | 15.0 |
| Source Trust | 60/100 | 0.10 | 6.0 |
| Behavioral Deviation | 0/100 | 0.05 | 0.0 |
| Potential Impact | 70/100 | 0.05 | 3.5 |

- **Likelihood:** High (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** High (76/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a high likelihood that this incident (network denial-of-service (syn flood) against CAM-001) results in loss of service, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Temporary block decided (dry-run, not executed); Notification sent to the administrator.

Dry-run commands (not executed):
```
iptables -I FORWARD -s 192.168.1.134 -m comment --comment iot-ips-temp -j DROP
```

**Policy decision:** rule high_probable matched: level High, score 76, confidence 0.91, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Simulated (dry-run, nothing executed) |
| Eradication and recovery | Pending analyst verification |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Block the source (the system only simulated the block) and confirm that the device responds normally.
2. Check upstream links for congestion.

**Short term (corrective)**
1. Apply rate limits for the device at the gateway.
2. Confirm the device firmware is current.

**Long term (preventive)**
1. Define a traffic baseline per device and alert on deviations.
2. Plan capacity and failover for critical devices.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.CM | Continuous monitoring |
| NIST CSF 2.0 | RS.MI | Incident mitigation |
| ISO/IEC 27001:2022 | A.8.20 | Networks security |
| ISO/IEC 27001:2022 | A.5.26 | Response to information security incidents |

- **Risk register:** record as *RISK-INC-00030*: Network denial-of-service (SYN flood) on CAM-001; inherent rating High; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `ceec8568924caa6f0c1fcc762d163a01c5177e63057661cc54c920173dc66b3b`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
