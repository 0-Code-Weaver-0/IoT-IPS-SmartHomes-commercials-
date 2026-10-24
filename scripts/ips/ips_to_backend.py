"""ips_to_backend.py - turns one IoT-IPS incident into the MQTT messages the SmartSecure backend understands.

Pure functions, no network. The future `engine` service (Person 6) calls build_messages() for every incident it
creates or updates; fake_ips_publisher.py calls it with sample incidents so the dashboard can be built and tested
before the real services exist.

Messages, in publish order (see docs/IPS_WARDEN.md):
  security/alerts/cyber   cyber.<attack>        one alert per detection (event envelope, CONTRACT section 2)
  security/alerts/engine  engine.ips_report     the reports (free-form `data`: the API keeps unknown incident fields out)
  security/risk           zone risk             what the dashboard gauge shows
  security/incidents      incident              re-sent with the SAME id to update (CONTRACT 4.4)
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOKEN = re.compile(r"^[a-z0-9_]+$")
EVENT_TYPE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
NAMESPACE = uuid.UUID("6f1d2c52-6c0e-4d0b-9d6e-0b1c6d3b7a11")
LEVELS = ("low", "medium", "high", "critical")
MAX_REPORT_CHARS = 9000            # the API limits one event's data to 32 KB; three texts of this size fit easily
BOOKKEEPING_ACTIONS = ("log", "create_incident")

# ----------------------------------------------------------------------------- naming
DEVICE_TYPES = {                   # IoT-IPS device_type -> backend device_type (topic token)
    "surveillance_camera": "camera", "ip_camera": "camera", "camera": "camera",
    "temperature_sensor": "temperature", "thermostat": "temperature",
    "smart_bulb": "bulb", "smart_plug": "plug", "industrial_sensor": "industrial_sensor",
}
DEFAULT_ZONES = {                  # used when devices.json has no "zone" field (ask Person 1 to add it)
    "CAM-001": "entrance", "THERMO-001": "living_room", "PLUG-001": "kitchen",
    "TEMP-001": "kitchen", "BULB-001": "living_room", "IND-001": "garage",
}
ATTACK_EVENT_TYPES = {             # canonical attack name -> backend event type (CONTRACT section 3)
    "port_scan": "cyber.port_scan", "reconnaissance": "cyber.port_scan",
    "brute_force": "cyber.brute_force",
    "dos": "cyber.dos", "ddos": "cyber.dos",
    "unexpected_protocol_port": "cyber.unexpected_traffic", "unexpected_protocol": "cyber.unexpected_traffic",
    "unexpected_traffic": "cyber.unexpected_traffic",
    "spoofing": "cyber.rogue_device", "arp_spoofing": "cyber.rogue_device",
}
MITRE_NAMES = {
    "T1046": "Network Service Discovery", "T1110": "Brute Force", "T1498": "Network Denial of Service",
    "T1571": "Non-Standard Port", "T1071": "Application Layer Protocol", "T1557": "Adversary-in-the-Middle",
    "T1595": "Active Scanning", "T1190": "Exploit Public-Facing Application",
    "T1584.005": "Compromise Infrastructure: Botnet", "T1078": "Valid Accounts",
}
_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def token(value: Any, default: str = "unknown") -> str:
    """Lowercase letters, digits and underscores only (what topics and ids may contain)."""
    s = re.sub(r"[^a-z0-9]+", "_", str(value if value is not None else "").lower()).strip("_")
    return s or default


def backend_device_id(ips_id: Any) -> str:
    return token(ips_id)[:100]


def backend_device_type(ips_type: Any) -> str:
    return DEVICE_TYPES.get(token(ips_type), token(ips_type))


def device_zone(ips_id: Any, profile: Optional[dict] = None, known_zones: Iterable[str] = ()) -> str:
    """Zone of a device: devices.json "zone" field, else the default table, else "network"."""
    z = token((profile or {}).get("zone"), "") if isinstance(profile, dict) else ""
    z = z or DEFAULT_ZONES.get(str(ips_id), "")
    known = set(known_zones)
    return z if z and (not known or z in known) else "network"


def event_type(attack_type: Any) -> str:
    key = token(attack_type)
    return ATTACK_EVENT_TYPES.get(key) or "cyber." + key


# ----------------------------------------------------------------------------- value helpers
def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return default
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return int(f) if f == f and abs(f) < 10 ** 12 else default


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if f == f and abs(f) != float("inf") else default


def clean_text(value: Any, limit: int = MAX_REPORT_CHARS) -> str:
    """Keep newlines and tabs, drop other control characters, cap the length."""
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(value if value is not None else ""))
    return s[:limit]


def level_of(value: Any) -> str:
    v = str(value or "").strip().lower()
    return v if v in LEVELS else "low"


def iso(value: Any = None) -> str:
    """UTC ISO-8601 with milliseconds and +00:00 (CONTRACT: ts is never local time)."""
    if isinstance(value, datetime):
        moment = value
    else:
        moment = None
        if value:
            try:
                moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except ValueError:
                moment = None
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _shift(ts: str, seconds: float) -> str:
    return iso(datetime.fromisoformat(ts) + timedelta(seconds=seconds))


def _drop_none(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def event_id(incident_id: Any, kind: str, seq: int) -> str:
    """Deterministic id: re-sending the same incident re-sends the same ids (the API ignores duplicate events)."""
    return str(uuid.uuid5(NAMESPACE, "%s:%s:%d" % (incident_id, kind, seq)))


def clean_factors(factors: Any) -> Dict[str, dict]:
    """Person 4's nested factors (value / weight / contribution) as plain numbers; unused factors are dropped."""
    out: Dict[str, dict] = {}
    for name, f in (factors or {}).items() if isinstance(factors, dict) else []:
        d = f if isinstance(f, dict) else {"value": f}
        if d.get("value") is None:
            continue
        out[token(name)] = _drop_none({"value": round(to_float(d.get("value")), 1),
                                       "weight": None if d.get("weight") is None else round(to_float(d["weight"]), 3),
                                       "contribution": None if d.get("contribution") is None else round(to_float(d["contribution"]), 1)})
    return out


def visible_actions(actions: Iterable[str]) -> List[str]:
    acts = [str(a) for a in (actions or []) if isinstance(a, str) and TOKEN.match(a)]
    vis = [a for a in acts if a not in BOOKKEEPING_ACTIONS]
    return vis or acts[:1] or ["log"]


def mitre_of(inc: dict) -> Tuple[Optional[str], Optional[str]]:
    m = str(inc.get("mitre_technique") or "").strip()
    return (m, MITRE_NAMES.get(m)) if _MITRE_ID.match(m) else (None, None)


# ----------------------------------------------------------------------------- the four messages
def alert_event(inc: dict, zone: str, *, ts: str, seq: int = 0) -> dict:
    bdev = backend_device_id(inc.get("device_id"))
    etype = event_type(inc.get("attack_type"))
    port = to_int(inc.get("dst_port"))
    mid, _ = mitre_of(inc)
    data = _drop_none({
        "src_ip": clean_text(inc.get("src_ip"), 64) or None, "dst_ip": clean_text(inc.get("dst_ip"), 64) or None,
        "dst_port": port, "protocol": clean_text(inc.get("protocol"), 16) or None,
        "direction": clean_text(inc.get("direction"), 16) or None,
        "device_id": bdev, "ips_device_id": clean_text(inc.get("device_id"), 64), "target": bdev,
        "attack_type": clean_text(inc.get("attack_type"), 64),
        "confidence": round(to_float(inc.get("confidence")), 3), "mitre_technique": mid,
        "attempts": to_int(inc.get("attempts")), "incident_id": clean_text(inc.get("id"), 100),
    })
    if etype == "cyber.port_scan":
        data["ports"] = [port] if port is not None else []
    if etype == "cyber.rogue_device":
        data.setdefault("mac", "unknown")
        data["ip"] = data.get("src_ip", "unknown")
    return {"id": event_id(inc.get("id"), "alert", seq), "ts": ts, "source": "cyber", "type": etype, "zone": zone,
            "severity_hint": level_of(inc.get("level")), "data": data}


def report_event(inc: dict, report: Optional[dict], zone: str, *, ts: str, seq: int = 0) -> dict:
    mid, mname = mitre_of(inc)
    rep = report or {}
    data = _drop_none({
        "incident_id": clean_text(inc.get("id"), 100), "device_id": backend_device_id(inc.get("device_id")),
        "attack_type": clean_text(inc.get("attack_type"), 64), "src_ip": clean_text(inc.get("src_ip"), 64) or None,
        "mitre_technique": mid, "mitre_name": mname,
        "ips_score": to_int(inc.get("score"), 0), "ips_level": level_of(inc.get("level")),
        "confidence": round(to_float(inc.get("confidence")), 3),
        "actions": visible_actions(inc.get("actions")), "status": clean_text(inc.get("status"), 40) or None,
        "rule_id": clean_text(inc.get("rule_id"), 60) or None, "reason": clean_text(inc.get("reason"), 300) or None,
        "weight_set": clean_text(inc.get("weight_set"), 40) or None,
        "factors": clean_factors(inc.get("factors")),
        "report_technical": clean_text(rep.get("technical")), "report_plain": clean_text(rep.get("executive")),
        "notification": clean_text(rep.get("notification"), 2000) or None,
    })
    return {"id": event_id(inc.get("id"), "report", seq), "ts": ts, "source": "engine", "type": "engine.ips_report",
            "zone": zone, "severity_hint": level_of(inc.get("level")), "data": data}


def risk_message(zone: str, level: str, score: int, factors: Any, actions: Iterable[str], *, ts: str) -> dict:
    fl = [{"type": n, "weight": f.get("contribution", f.get("value", 0)), "value": f.get("value", 0)}
          for n, f in clean_factors(factors).items()]
    return {"ts": ts, "zone": zone, "level": level_of(level), "score": max(0, to_int(score, 0) or 0),
            "factors": fl, "actions": visible_actions(actions)}


def summary_of(inc: dict) -> str:
    mid, _ = mitre_of(inc)
    return clean_text("%s %s on %s from %s (%srisk %s/100)" % (
        str(inc.get("level") or "").capitalize(), inc.get("attack_type") or "alert", inc.get("device_id") or "device",
        inc.get("src_ip") or "unknown source", (mid + ", ") if mid else "", to_int(inc.get("score"), 0)), 300)


def incident_message(inc: dict, zone: str, event_ids: List[str], *, ts: str) -> dict:
    return {"id": clean_text(inc.get("id"), 100), "ts": ts, "zone": zone, "level": level_of(inc.get("level")),
            "score": max(0, to_int(inc.get("score"), 0) or 0), "trigger": event_type(inc.get("attack_type")),
            "events": list(event_ids), "actions": visible_actions(inc.get("actions")), "summary": summary_of(inc)}


def build_messages(inc: dict, report: Optional[dict] = None, profile: Optional[dict] = None, *,
                   previous_event_ids: Iterable[str] = (), ts: Optional[Any] = None,
                   known_zones: Iterable[str] = ()) -> dict:
    """All messages for one incident update. Returns {"messages": [(topic, payload), ...], "event_ids": [...]}.

    previous_event_ids: event ids already attached to this incident (a repeat of the same attack adds one alert and one
    report and re-sends the incident with the longer list). ts: event time (default: the incident's own timestamp).
    """
    prev = list(previous_event_ids)
    seq = sum(1 for _ in prev) // 2
    base = iso(ts or inc.get("timestamp"))
    zone = device_zone(inc.get("device_id"), profile, known_zones)
    alert = alert_event(inc, zone, ts=base, seq=seq)
    rep = report_event(inc, report, zone, ts=_shift(base, 0.5), seq=seq)
    ids = prev + [alert["id"], rep["id"]]
    when = _shift(base, 1.0)
    msgs = [
        ("security/alerts/cyber", alert),
        ("security/alerts/engine", rep),
        ("security/risk", risk_message(zone, inc.get("level"), inc.get("score"), inc.get("factors"), inc.get("actions"), ts=when)),
        ("security/incidents", incident_message(inc, zone, ids, ts=when)),
    ]
    return {"messages": msgs, "event_ids": ids}


# ----------------------------------------------------------------------------- validation (used by tests and the publisher)
class MessageError(ValueError):
    pass


def check_message(topic: str, payload: dict) -> None:
    """Raise MessageError unless the payload would be accepted by the API (the same rules as services/api/mqtt_handler.py)."""
    import json
    if topic.startswith("security/alerts/"):
        for key in ("id", "ts", "source", "type", "zone", "severity_hint", "data"):
            if key not in payload:
                raise MessageError("%s: missing %s" % (topic, key))
        if set(payload) - {"id", "ts", "source", "type", "zone", "severity_hint", "data"}:
            raise MessageError("%s: unknown key(s) %s" % (topic, sorted(set(payload) - {"id", "ts", "source", "type", "zone", "severity_hint", "data"})))
        if not 8 <= len(payload["id"]) <= 100 or not payload["source"] or len(payload["source"]) > 100:
            raise MessageError("%s: bad id or source" % topic)
        if not EVENT_TYPE.match(payload["type"]) or not TOKEN.match(payload["zone"]):
            raise MessageError("%s: bad type or zone" % topic)
        if payload["severity_hint"] not in ("info",) + LEVELS:
            raise MessageError("%s: bad severity_hint" % topic)
        if not isinstance(payload["data"], dict) or len(json.dumps(payload["data"])) > 32 * 1024:
            raise MessageError("%s: data must be an object under 32 KB" % topic)
    elif topic == "security/incidents":
        need = ("id", "ts", "zone", "level", "score", "trigger", "events", "actions", "summary")
        if any(k not in payload for k in need):
            raise MessageError("incident: missing " + ", ".join(k for k in need if k not in payload))
        if not payload["id"] or len(payload["id"]) > 100 or not TOKEN.match(payload["zone"]) or payload["level"] not in LEVELS:
            raise MessageError("incident: bad id, zone or level")
        if not isinstance(payload["score"], int) or isinstance(payload["score"], bool) or payload["score"] < 0:
            raise MessageError("incident: score must be a non-negative integer")
        if not all(isinstance(e, str) for e in payload["events"]) or not all(isinstance(a, str) for a in payload["actions"]):
            raise MessageError("incident: events/actions must be lists of strings")
        if len(payload["summary"]) > 4000:
            raise MessageError("incident: summary over 4000 characters")
    elif topic == "security/risk":
        if not TOKEN.match(payload.get("zone", "")) or payload.get("level") not in LEVELS:
            raise MessageError("risk: bad zone or level")
        if not isinstance(payload.get("score"), int) or isinstance(payload.get("score"), bool) or payload["score"] < 0:
            raise MessageError("risk: score must be a non-negative integer")
        if not isinstance(payload.get("factors"), list) or not isinstance(payload.get("actions"), list):
            raise MessageError("risk: factors and actions must be lists")
    else:
        raise MessageError("unexpected topic " + topic)
