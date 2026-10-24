"""
placeholders.py - stand-ins for modules that other people are still writing.

run_pipeline.py uses these ONLY when the real module is not found:
  * detect(event)         replaces Person 3's detector.py
  * make_report(incident) replaces Person 7's report.py

They follow the shared contract, so swapping in the real module needs no change
in the pipeline: put detector.py / report.py next to run_pipeline.py (or in a
folder called "Person 3" / "Person 7" beside it).

These are deliberately simple and are NOT a security control: the detector is a
few thresholds, the reports are one plain paragraph each.
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Mapping
from typing import Any, Optional

__all__ = ["detect", "make_report", "PLACEHOLDER_NOTE"]

PLACEHOLDER_NOTE = "PLACEHOLDER"
_REMOTE_LOGIN_PORTS = {21, 22, 23, 554, 3389}


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Real):
        number = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 32:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


def detect(event: Any, device_profile: Any = None) -> dict:
    """Threshold detector (placeholder for Person 3). Returns the Detection message."""
    if not isinstance(event, Mapping):
        event = {}
    failed = _num(event.get("failed_attempts"))
    conns = _num(event.get("connection_attempts"))
    port = _num(event.get("dst_port"))
    rate = _num(event.get("Rate"))
    syn = _num(event.get("syn_flag_number"))

    if failed is not None and failed >= 10 and port is not None and int(port) in _REMOTE_LOGIN_PORTS:
        return {"label": "ATTACK", "attack_type": "brute_force", "confidence": round(min(0.95, 0.60 + failed / 200.0), 2),
                "mitre_technique": "T1110"}
    if (rate is not None and rate >= 5000) or (syn is not None and syn >= 500):
        return {"label": "ATTACK", "attack_type": "dos",
                "confidence": 0.95 if (rate is not None and rate >= 20000) else 0.85, "mitre_technique": "T1498"}
    if conns is not None and conns >= 20:
        return {"label": "ATTACK", "attack_type": "port_scan", "confidence": 0.70, "mitre_technique": "T1046"}
    if conns is not None and conns >= 5:
        return {"label": "ATTACK", "attack_type": "port_scan", "confidence": 0.45, "mitre_technique": "T1046"}
    return {"label": "BENIGN", "attack_type": "benign", "confidence": 0.90, "mitre_technique": None}


def make_report(incident: Any) -> dict:
    """Two short plain paragraphs (placeholder for Person 7's report.py).

    Only fields that db.py has already validated are used.
    """
    if not isinstance(incident, Mapping):
        incident = {}
    actions = ", ".join(incident.get("action") or []) or "none"
    technical = (
        "[%s REPORT] %s | %s | device %s | %s to %s port %s | attack %s | confidence %s | risk %s/100 (%s) | actions: %s (simulated)"
        % (PLACEHOLDER_NOTE, incident.get("incident_id"), incident.get("timestamp"), incident.get("device_id"),
           incident.get("src_ip") or "unknown", incident.get("dst_ip") or "unknown", incident.get("dst_port") or "unknown",
           incident.get("attack_type"), incident.get("confidence"), incident.get("risk_score"), incident.get("risk_level"), actions))
    plain = (
        "[%s REPORT] %s risk. The system saw %s activity aimed at %s. In test mode it decided on: %s. "
        "No real change was made to the network." % (
            PLACEHOLDER_NOTE, incident.get("risk_level"), str(incident.get("attack_type") or "unknown").replace("_", " "),
            incident.get("device_id"), actions))
    return {"technical": technical, "non_technical": plain}
