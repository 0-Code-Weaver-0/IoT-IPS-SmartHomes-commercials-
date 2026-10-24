# Security Incident Summary: INC-00031

## Status: CRITICAL: IMMEDIATE ATTENTION

**Device:** CAM-001 (surveillance camera)
**Risk rating:** Critical (81 out of 100)
**Time detected:** 2026-10-19T21:05:52Z

### What happened?
Someone tried to guess the device's password many times in a row. The system noticed this on 2026-10-19T21:05:52Z and rated it with 94% confidence.

### What did the system do?
Block decided (dry-run). Isolation decided (dry-run). Administrator notified.

### Is the device safe?
The system decided how to contain the threat, but this is a simulation: nothing was actually blocked or isolated. The device is under close monitoring and still needs a person to check it.

### What could it have meant for the business?
Loss of video coverage or exposure of live footage; physical security is weakened while the camera is affected.

### What is needed from management?
- Confirm that the device should be isolated until the security team verifies it (the system only simulated the isolation).
- Approve the corrective actions listed by the security team (for example new credentials).

### Governance note
This incident was recorded, rated and escalated according to the security response procedure. Immediate escalation to the IoT Security Lead and the System Owner; management informed. The full technical report and evidence are available to the security team.
