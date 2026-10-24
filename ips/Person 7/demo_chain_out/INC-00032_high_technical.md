# Security Incident Report: INC-00032

**Classification:** HIGH (77/100) | **Status:** Open | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00032 |
| Detected (UTC) | 2026-10-20T08:20:10Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 1 hour (proposed internal target) |
| Escalation | Escalate to the IoT Security Lead; the System Owner is informed. |

## 1. Executive summary
The IoT-IPS detected **credential brute-force attempt** against **CAM-001** from **192.168.1.10** with 94% confidence. The event is rated **High** (77/100). Response taken: notification sent to the administrator. Current status: **open**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 192.168.1.10 (trusted internal host) |
| Destination | 192.168.1.50:22 / TCP |
| Attempts or events observed | 431 |
| Duration | 4 minutes |
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
| Confidence | 94/100 | 0.20 | 18.8 |
| Attack Severity | 70/100 | 0.25 | 17.5 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 100/100 | 0.15 | 15.0 |
| Source Trust | 20/100 | 0.10 | 2.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 75/100 | 0.05 | 3.8 |

- **Likelihood:** High (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** High (77/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a high likelihood that this incident (credential brute-force attempt against CAM-001) results in exposure of data, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Notification sent to the administrator.

**Policy decision:** rule high_probable matched: level High, score 77, confidence 0.94, attack known.

**Not executed:** temporary_block (source_allow_listed) (the reason is in brackets). An analyst should review this manually.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Monitoring only |
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

- **Risk register:** record as *RISK-INC-00032*: Credential brute-force attempt on CAM-001; inherent rating High; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `e1b5fe75cad0eee4c27762f2f27cea010a7080142dbe7c5fd4979eddef465fdb`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
