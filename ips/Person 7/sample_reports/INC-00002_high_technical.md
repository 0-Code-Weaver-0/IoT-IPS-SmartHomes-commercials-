# Security Incident Report: INC-00002

**Classification:** HIGH (61/100) | **Status:** Open | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00002 |
| Detected (UTC) | 2026-10-20T08:05:00Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 1 hour (proposed internal target) |
| Escalation | Escalate to the IoT Security Lead; the System Owner is informed. |

## 1. Executive summary
The IoT-IPS detected **traffic on an unexpected port or protocol** against **CAM-001** from **203.0.113.5** with 60% confidence. The event is rated **High** (61/100). Response taken: temporary block decided (dry-run, not executed); notification sent to the administrator. Current status: **open**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 203.0.113.5 (external host) |
| Destination | 192.168.1.50:22 / TCP |
| Attempts or events observed | 40 |
| Duration | - |
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
| Confidence | 60/100 | 0.20 | 12.0 |
| Attack Severity | 35/100 | 0.25 | 8.8 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 65/100 | 0.15 | 9.8 |
| Source Trust | 90/100 | 0.10 | 9.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 35/100 | 0.05 | 1.8 |

- **Likelihood:** Medium (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** High (61/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a medium likelihood that this incident (traffic on an unexpected port or protocol against CAM-001) results in unauthorised change or control, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Temporary block decided (dry-run, not executed); Notification sent to the administrator.

Dry-run commands (not executed):
```
iptables -I FORWARD -s 203.0.113.5 -m comment --comment iot-ips-temp -j DROP
```

**Policy decision:** rule high_probable matched: level High, score 61, confidence 0.6, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Simulated (dry-run, nothing executed) |
| Eradication and recovery | Pending analyst verification |
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

- **Risk register:** record as *RISK-INC-00002*: Traffic on an unexpected port or protocol on CAM-001; inherent rating High; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `6e07b7916c469ec760209e07b832e1bb1ca96ac8a0dc4c65ed923fbcf5ced05e`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
