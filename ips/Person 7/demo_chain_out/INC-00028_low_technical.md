# Security Incident Report: INC-00028

**Classification:** LOW (29/100) | **Status:** Monitoring | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00028 |
| Detected (UTC) | 2026-10-18T09:12:40Z |
| Affected asset | BULB-001 (smart_bulb), criticality low |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 24 hours (proposed internal target) |
| Escalation | Logged and reviewed by the security analyst during routine monitoring. |

## 1. Executive summary
The IoT-IPS detected **network service discovery (port scan)** against **BULB-001** from **192.168.1.20** with 55% confidence. The event is rated **Low** (29/100). Response taken: continued monitoring of the device. Current status: **monitoring**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 192.168.1.20 (trusted internal host) |
| Destination | 192.168.1.60:80 / TCP |
| Attempts or events observed | 3 |
| Duration | 6 seconds |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Discovery (TA0007) |
| Technique | T1046 Network Service Discovery |
| Reference | https://attack.mitre.org/techniques/T1046/ |
| Security property at risk | Confidentiality (exposure of data) |

**Analyst assessment:** The source probed multiple ports on the device to learn which services are exposed. This is typically the reconnaissance step before an intrusion attempt.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 55/100 | 0.20 | 11.0 |
| Attack Severity | 25/100 | 0.25 | 6.2 |
| Device Criticality | 25/100 | 0.20 | 5.0 |
| Persistence | 24/100 | 0.15 | 3.6 |
| Source Trust | 20/100 | 0.10 | 2.0 |
| Behavioral Deviation | 0/100 | 0.05 | 0.0 |
| Potential Impact | 15/100 | 0.05 | 0.8 |

- **Likelihood:** Low (detection confidence and persistence of the activity).
- **Impact:** Low (criticality of the affected device).
- **Overall rating:** Low (29/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a low likelihood that this incident (network service discovery (port scan) against BULB-001) results in exposure of data, with a low impact on the organisation.

## 5. Response and containment
**Action taken:** Continued monitoring of the device.

**Policy decision:** rule low matched: level Low, score 29, confidence 0.55, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Monitoring only |
| Eradication and recovery | Not required at this level |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Confirm whether the source is an authorised scanner or asset.
2. Keep the source under monitoring and review its other connections.

**Short term (corrective)**
1. Disable every service the device does not need.
2. Restrict management ports to the admin network only.

**Long term (preventive)**
1. Segment IoT devices into their own VLAN.
2. Review firewall rules at least quarterly.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.CM | Continuous monitoring |
| NIST CSF 2.0 | DE.AE | Adverse event analysis |
| ISO/IEC 27001:2022 | A.8.16 | Monitoring activities |
| ISO/IEC 27001:2022 | A.8.20 | Networks security |

- **Risk register:** record as *RISK-INC-00028*: Network service discovery (port scan) on BULB-001; inherent rating Low; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `fa6cf5741999a19c97b3f0c653872e212b65bddda03e9814f5cd7bb2d6ccfe2c`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
