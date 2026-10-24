# Security Incident Report: INC-00029

**Classification:** MEDIUM (54/100) | **Status:** Monitoring | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00029 |
| Detected (UTC) | 2026-10-18T13:47:05Z |
| Affected asset | TEMP-001 (temperature_sensor), criticality medium |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 4 hours (proposed internal target) |
| Escalation | Handled by the security analyst on duty; the System Owner is informed. |

## 1. Executive summary
The IoT-IPS detected **traffic on an unexpected port or protocol** against **TEMP-001** from **192.168.1.77** with 82% confidence. The event is rated **Medium** (54/100). Response taken: notification sent to the administrator. Current status: **monitoring**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 192.168.1.77 (unknown internal host) |
| Destination | 192.168.1.70:4444 / TCP |
| Attempts or events observed | 9 |
| Duration | 3 minutes |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Command and Control (TA0011) |
| Technique | T1571 Non-Standard Port |
| Reference | https://attack.mitre.org/techniques/T1571/ |
| Security property at risk | Integrity (unauthorised change or control) |

**Analyst assessment:** Traffic reached or left the device on a port or protocol outside its approved profile. This can indicate unauthorised access or command-and-control activity from a compromised device.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 82/100 | 0.20 | 16.4 |
| Attack Severity | 35/100 | 0.25 | 8.8 |
| Device Criticality | 50/100 | 0.20 | 10.0 |
| Persistence | 40/100 | 0.15 | 6.0 |
| Source Trust | 60/100 | 0.10 | 6.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 35/100 | 0.05 | 1.8 |

- **Likelihood:** Medium (detection confidence and persistence of the activity).
- **Impact:** Medium (criticality of the affected device).
- **Overall rating:** Medium (54/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a medium likelihood that this incident (traffic on an unexpected port or protocol against TEMP-001) results in unauthorised change or control, with a medium impact on the organisation.

## 5. Response and containment
**Action taken:** Notification sent to the administrator.

**Policy decision:** rule medium matched: level Medium, score 54, confidence 0.82, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Monitoring only |
| Eradication and recovery | Not required at this level |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Verify whether the destination belongs to the vendor or a known service.
2. Review the device for signs of compromise (unknown processes, changed settings).

**Short term (corrective)**
1. Allow outbound traffic only to approved destinations.
2. Reset the device to a known-good firmware if compromise is suspected.

**Long term (preventive)**
1. Maintain an approved-communications profile for every device type.
2. Subscribe to vendor security advisories.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.AE | Adverse event analysis |
| NIST CSF 2.0 | RS.AN | Incident analysis |
| ISO/IEC 27001:2022 | A.8.16 | Monitoring activities |
| ISO/IEC 27001:2022 | A.8.22 | Segregation of networks |

- **Risk register:** record as *RISK-INC-00029*: Traffic on an unexpected port or protocol on TEMP-001; inherent rating Medium; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `964015e5fe29244a8cbb17ff15020f3b91f8d300079c96d0ab049f749dbe3471`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
