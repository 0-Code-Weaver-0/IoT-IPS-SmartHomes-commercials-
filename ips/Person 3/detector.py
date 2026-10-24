"""
detector.py - Rule-based IPS detector (Phase 1: an IPS without AI).

    detect(event, device_profile=None) -> Detection dict

Detection message (the same contract the ML model will use next phase):
    {"label": "BENIGN" | "ATTACK", "attack_type": str, "confidence": float 0..1, "mitre_technique": str | None}

The ML model only has to expose the same detect(event, device_profile) function to replace this file.
All thresholds live in rules.yaml, which is VALIDATED when it is loaded: a missing, misspelled or
out-of-range key raises RuleConfigError instead of silently switching a rule off.
"""
import math
import os
import re

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "rules.yaml")


class RuleConfigError(ValueError):
    """rules.yaml is missing, malformed, or has a missing/unknown/out-of-range key."""


# --------------------------------------------------------------------------
# configuration (validated)
# --------------------------------------------------------------------------
_COMMON = {"attack_type", "mitre_technique"}
SCHEMA = {   # rule name -> (required keys, optional keys); order in rules.yaml = severity order
    "dos": ({"min_rate", "min_syn_count", "base_confidence", "max_confidence"} | _COMMON, {"enabled", "min_connection_attempts"}),
    "brute_force": ({"target_ports", "min_failed_attempts", "base_confidence", "max_confidence"} | _COMMON, {"enabled"}),
    "port_scan": ({"min_unique_ports", "min_unique_destinations", "base_confidence", "max_confidence"} | _COMMON, {"enabled"}),
    "unexpected_traffic": ({"confidence_one_violation", "confidence_both_violations"} | _COMMON, {"enabled"}),
}
_THRESHOLDS = {"min_rate", "min_syn_count", "min_connection_attempts", "min_failed_attempts", "min_unique_ports", "min_unique_destinations"}
_CONFIDENCES = {"base_confidence", "max_confidence", "confidence_one_violation", "confidence_both_violations"}
_MITRE = re.compile(r"T\d{4}(\.\d{3})?")


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def validate_config(config):
    """Raise RuleConfigError unless the configuration is complete and sane. Returns the config."""
    if not isinstance(config, dict):
        raise RuleConfigError("rules.yaml must contain a mapping")
    unknown_top = set(config) - {"settings", "rules"}
    if unknown_top:
        raise RuleConfigError("unknown top-level key(s): %s" % ", ".join(sorted(map(str, unknown_top))))
    settings = config.get("settings")
    if not isinstance(settings, dict) or set(settings) != {"benign_confidence"}:
        raise RuleConfigError("settings must contain exactly: benign_confidence")
    if not _is_number(settings["benign_confidence"]) or not 0 <= settings["benign_confidence"] <= 1:
        raise RuleConfigError("settings.benign_confidence must be a number from 0 to 1")
    rules = config.get("rules")
    if not isinstance(rules, dict):
        raise RuleConfigError("rules must be a mapping")
    for name in rules:
        if name not in SCHEMA:
            raise RuleConfigError("unknown rule '%s' (known: %s)" % (name, ", ".join(SCHEMA)))
    for name, (required, optional) in SCHEMA.items():
        cfg = rules.get(name)
        if cfg is None:
            raise RuleConfigError("rule '%s' is missing" % name)
        if not isinstance(cfg, dict):
            raise RuleConfigError("rule '%s' must be a mapping" % name)
        missing, extra = required - set(cfg), set(cfg) - required - optional
        if missing:
            raise RuleConfigError("rule '%s' is missing key(s): %s" % (name, ", ".join(sorted(missing))))
        if extra:
            raise RuleConfigError("rule '%s' has unknown key(s) (typo?): %s" % (name, ", ".join(sorted(map(str, extra)))))
        if "enabled" in cfg and not isinstance(cfg["enabled"], bool):
            raise RuleConfigError("rule '%s': enabled must be true or false" % name)
        if not isinstance(cfg["attack_type"], str) or not cfg["attack_type"].strip():
            raise RuleConfigError("rule '%s': attack_type must be a non-empty string" % name)
        if not isinstance(cfg["mitre_technique"], str) or not _MITRE.fullmatch(cfg["mitre_technique"]):
            raise RuleConfigError("rule '%s': mitre_technique must look like T1110 or T1557.002" % name)
        for key in _THRESHOLDS & set(cfg):
            if not _is_number(cfg[key]) or cfg[key] < 0:
                raise RuleConfigError("rule '%s': %s must be a number >= 0 (0 disables that trigger)" % (name, key))
        for key in _CONFIDENCES & set(cfg):
            if not _is_number(cfg[key]) or not 0 <= cfg[key] <= 1:
                raise RuleConfigError("rule '%s': %s must be a number from 0 to 1" % (name, key))
        if "base_confidence" in cfg and cfg["base_confidence"] > cfg["max_confidence"]:
            raise RuleConfigError("rule '%s': base_confidence must not exceed max_confidence" % name)
        if name == "unexpected_traffic" and cfg["confidence_one_violation"] > cfg["confidence_both_violations"]:
            raise RuleConfigError("rule 'unexpected_traffic': one-violation confidence must not exceed both-violations")
        if name == "brute_force":
            ports = cfg["target_ports"]
            if not isinstance(ports, list) or not ports or not all(isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535 for p in ports):
                raise RuleConfigError("rule 'brute_force': target_ports must be a non-empty list of ports")
    return config


_config_cache = {}


def load_config(path=DEFAULT_CONFIG):
    """Read, validate and cache rules.yaml (re-read automatically when the file changes)."""
    try:
        stamp = (path, os.stat(path).st_mtime_ns)
    except OSError as exc:
        raise RuleConfigError("cannot read %s (%s)" % (path, exc.strerror or "error"))
    if stamp not in _config_cache:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise RuleConfigError("rules.yaml is not valid YAML (%s)" % type(exc).__name__)
        _config_cache[stamp] = validate_config(data)
    return _config_cache[stamp]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _num(value, default=0.0):
    """Safe number: CSV values may be strings, empty, NaN or inf."""
    if isinstance(value, bool):
        return default
    try:
        x = float(value)
    except (TypeError, ValueError):
        return default
    return default if (math.isnan(x) or math.isinf(x)) else x


def _num_or_none(value):
    x = _num(value, None)
    return x


def _scale(ratio, base, maximum):
    """ratio == 1 -> base, ratio >= 3 -> maximum, linear in between."""
    frac = min(max((ratio - 1.0) / 2.0, 0.0), 1.0)
    return round(base + frac * (maximum - base), 2)


def _ratio(value, threshold):
    """How many times the value exceeds the threshold (0 if the trigger is disabled)."""
    if threshold is None or threshold <= 0:
        return 0.0
    return value / threshold


def _ports(values):
    """Clean list of ints from a profile entry (bad entries are ignored)."""
    out = []
    for p in values if isinstance(values, (list, tuple)) else []:
        if isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535:
            out.append(p)
        elif isinstance(p, str) and p.strip().isdigit() and int(p) <= 65535:
            out.append(int(p))
    return out


def _result(label, attack_type, confidence, mitre):
    return {"label": label, "attack_type": attack_type, "confidence": confidence, "mitre_technique": mitre}


# --------------------------------------------------------------------------
# rules - each returns a confidence (float) if it fires, otherwise None
# --------------------------------------------------------------------------
def rule_dos(event, cfg, profile):
    ratio = max(
        _ratio(_num(event.get("Rate")), cfg["min_rate"]),
        _ratio(_num(event.get("syn_count")), cfg["min_syn_count"]),
    )
    if ratio < 1.0:
        return None
    # A high packet rate from only a handful of connections is a bulk transfer (video, backup), not a flood.
    # The check applies only when the event carries the connection count.
    needed = cfg.get("min_connection_attempts", 0)
    seen = _num_or_none(event.get("connection_attempts"))
    if needed and seen is not None and seen < needed:
        return None
    return _scale(ratio, cfg["base_confidence"], cfg["max_confidence"])


def rule_brute_force(event, cfg, profile):
    """Many FAILED logins on a login service. Plain connection counts are not evidence of password guessing
    (a camera's own stream port is opened many times by normal viewers)."""
    port = _num(event.get("dst_port"), -1)
    on_target_service = (
        (port == int(port) and int(port) in cfg["target_ports"])
        or _num(event.get("SSH")) == 1
        or _num(event.get("Telnet")) == 1
    )
    if not on_target_service:
        return None
    ratio = _ratio(_num(event.get("failed_attempts")), cfg["min_failed_attempts"])
    if ratio >= 1.0:
        return _scale(ratio, cfg["base_confidence"], cfg["max_confidence"])
    return None


def rule_port_scan(event, cfg, profile):
    ratio = max(
        _ratio(_num(event.get("unique_dst_ports")), cfg["min_unique_ports"]),
        _ratio(_num(event.get("unique_dst_ips")), cfg["min_unique_destinations"]),
    )
    if ratio >= 1.0:
        return _scale(ratio, cfg["base_confidence"], cfg["max_confidence"])
    return None


def rule_unexpected_traffic(event, cfg, profile):
    """Compare the event with the device profile.
    direction 'outbound' (the device talks to someone) is checked against expected_outbound_ports;
    anything else is inbound (someone talks to the device) and is checked against expected_ports.
    Without a port list for that direction the port is not judged (nothing to compare against)."""
    if not isinstance(profile, dict) or not profile:
        return None
    outbound = str(event.get("direction") or "").strip().lower() == "outbound"
    expected = _ports(profile.get("expected_outbound_ports" if outbound else "expected_ports"))
    violations = 0
    port = _num(event.get("dst_port"), None)
    if expected and port is not None and (port != int(port) or int(port) not in expected):
        violations += 1
    protocols = [str(p).upper() for p in (profile.get("expected_protocols") or []) if isinstance(p, str)]
    protocol = str(event.get("protocol") or "").upper()
    if protocols and protocol and protocol not in protocols:
        violations += 1
    if violations == 0:
        return None
    return cfg["confidence_both_violations"] if violations == 2 else cfg["confidence_one_violation"]


RULES = {   # dict order = severity order
    "dos": rule_dos,
    "brute_force": rule_brute_force,
    "port_scan": rule_port_scan,
    "unexpected_traffic": rule_unexpected_traffic,
}


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def detect(event, device_profile=None, config_path=DEFAULT_CONFIG):
    """Run all enabled rules on one event and return the Detection message.

    event           dict of features + context (bad or missing fields are tolerated)
    device_profile  optional dict (expected_protocols, expected_ports, expected_outbound_ports, ...)
    A broken EVENT never stops the detector; a broken CONFIGURATION raises RuleConfigError.
    """
    config = load_config(config_path)
    benign = _result("BENIGN", "None", config["settings"]["benign_confidence"], None)
    if not isinstance(event, dict):
        return benign
    best = None  # (confidence, rule_cfg)
    for name, func in RULES.items():
        cfg = config["rules"][name]
        if not cfg.get("enabled", True):
            continue
        try:
            confidence = func(event, cfg, device_profile)
        except (TypeError, ValueError, OverflowError):
            confidence = None  # bad event data in one rule must not stop the others
        if confidence is not None and (best is None or confidence > best[0]):
            best = (confidence, cfg)
    if best is None:
        return benign
    confidence, cfg = best
    return _result("ATTACK", cfg["attack_type"], confidence, cfg["mitre_technique"])


if __name__ == "__main__":
    demo = {"device_id": "cam-01", "dst_port": 22, "failed_attempts": 300, "connection_attempts": 320, "Rate": 12.0}
    print(detect(demo))
