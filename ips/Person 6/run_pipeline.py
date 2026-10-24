#!/usr/bin/env python3
"""
run_pipeline.py - the IoT-IPS pipeline (Person 6)

    python run_pipeline.py run  sample_events.csv [--db incidents.db] [--reset]
    python run_pipeline.py show [--db incidents.db] [--level High] [--full INC-00007]
    python run_pipeline.py verify [--db incidents.db]

For every row of the CSV:  detector -> risk -> policy -> actions -> incident database

    event (CSV row)
      -> detector.detect(event)                      Person 3 (placeholder until it exists)
      -> risk.assess(detection, event, profile)      Person 4
      -> policy.decide(risk, detection, event, profile)   Person 5
      -> ActionExecutor.run(decision)                Person 5 (simulated, writes the action log)
      -> if the decision contains create_incident:
         IncidentDB.insert_incident(...)  with reports from report.make_report (Person 7, placeholder until it exists)

Module search: this folder first, then sibling folders called person3 ... person7
(any spelling: "Person 4", "person_4"). A real detector.py / report.py replaces the
placeholders automatically. risk.py, policy.py and actions.py are required.

The CSV is untrusted input: it is size-limited, row-limited, decoded strictly and
every field is length-limited. A bad row is counted and skipped, a missing value
becomes a cautious default, and a failing module is reported without stopping the
run. Nothing in this program runs a real firewall command.

Exit status: 0 = clean run, 1 = verify found tampering, 2 = errors (bad file, rejected
rows, module failures).
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import importlib
import ipaddress
import json
import math
import numbers
import os
import re
import sys
from collections.abc import Mapping
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))

MAX_CSV_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_ROWS = 100_000
DEFAULT_MAX_INCIDENTS = 10_000
MAX_COLUMNS = 300
MAX_FIELD_CHARS = 500
MAX_DEVICES_BYTES = 1024 * 1024
CONTEXT_FIELDS = ("device_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "failed_attempts", "connection_attempts")
EXPECTED_PREFIX = "expected_"   # columns such as expected_level are for humans and never reach the modules

_DEVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}")
_PROTOCOL_RE = re.compile(r"[A-Za-z0-9_-]{1,20}")
_DURATION_RE = re.compile(r"[A-Za-z0-9 .:,-]{1,60}")
_COLUMN_RE = re.compile(r"[A-Za-z0-9_ ./()%+-]{1,80}")
_PERSON_DIR_RE = re.compile(r"person[1-7]")
_CRIT_VALUES = ("low", "medium", "high", "critical")

csv.field_size_limit(MAX_FIELD_CHARS * 20)


class PipelineError(RuntimeError):
    """A problem that stops the run (bad input file, missing required module, bad configuration)."""


# ---------------------------------------------------------------------------
# Finding and loading the other people's modules
# ---------------------------------------------------------------------------

def add_module_folders(base: str = HERE) -> List[str]:
    """Add this folder's siblings named person3..person7 (any case/spelling) to sys.path (last)."""
    added = []
    parent = os.path.dirname(base)
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        names = []
    for name in names:
        full = os.path.join(parent, name)
        if full != base and os.path.isdir(full) and _PERSON_DIR_RE.fullmatch(re.sub(r"[^a-z0-9]", "", name.lower())):
            if full not in sys.path:
                sys.path.append(full)
                added.append(full)
    return added


class Modules:
    """The functions the pipeline calls, and where each one came from."""

    def __init__(self, force_placeholders: Any = False) -> None:
        """force_placeholders: True ignores Person 3's detector and Person 7's report module (tests, demos without them);
        a collection such as {"detector"} or {"report"} ignores only those."""
        add_module_folders()
        try:
            import risk
            import policy
            import actions
        except ImportError as exc:
            raise PipelineError("required module not found (%s). Put risk.py, policy.py and actions.py next to "
                                "run_pipeline.py, or in folders named like 'Person 4' and 'Person 5' beside this one."
                                % (exc.name or "unknown"))
        self.risk, self.policy, self.actions = risk, policy, actions
        import placeholders
        self.detect: Callable[[dict], Any] = placeholders.detect
        self.make_report: Callable[[dict], Any] = placeholders.make_report
        self.sources = {"detector": "placeholder", "report": "placeholder"}
        self.build_incident = None
        forced = {"detector", "report"} if force_placeholders is True else set(force_placeholders or ())
        wanted = tuple(item for item in (("detector", "detect", "detector"), ("report", "make_report", "report")) if item[2] not in forced)
        for module_name, attr, key in wanted:
            try:
                module = importlib.import_module(module_name)
            except ModuleNotFoundError as exc:
                if exc.name != module_name:
                    raise PipelineError("%s.py was found but needs a missing package (%s)" % (module_name, exc.name))
                continue
            function = getattr(module, attr, None)
            if not callable(function):
                raise PipelineError("%s.py was found but has no function %s()" % (module_name, attr))
            if key == "detector" and callable(getattr(module, "load_config", None)):
                try:                       # a bad rules.yaml must stop the run at the start, not fail every event later
                    module.load_config()
                except ValueError as exc:
                    raise PipelineError("detector configuration problem: %s" % exc)
            setattr(self, "detect" if key == "detector" else "make_report", function)
            if key == "report":
                self.build_incident = getattr(module, "build_incident", None)
                if not callable(self.build_incident):
                    raise PipelineError("report.py was found but has no function build_incident()")
            self.sources[key] = "real"


# ---------------------------------------------------------------------------
# Device profiles (Person 1's devices.json)
# ---------------------------------------------------------------------------

def load_devices(path: str) -> Dict[str, dict]:
    """Read devices.json: a list of profiles (or {"devices": [...]}). Invalid entries are dropped."""
    try:
        if os.path.getsize(path) > MAX_DEVICES_BYTES:
            raise PipelineError("devices file is too large")
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle, parse_constant=lambda _c: (_ for _ in ()).throw(ValueError("constant")))
    except (OSError, ValueError, RecursionError) as exc:
        raise PipelineError("cannot read devices file (%s)" % type(exc).__name__)
    if isinstance(data, Mapping):
        data = data.get("devices")
    if not isinstance(data, list) or len(data) > 1000:
        raise PipelineError("devices file must hold a list of at most 1000 device profiles")
    devices: Dict[str, dict] = {}
    for entry in data:
        if not isinstance(entry, Mapping):
            continue
        device_id = entry.get("device_id")
        if not isinstance(device_id, str) or not _DEVICE_RE.fullmatch(device_id):
            continue
        if device_id in devices:
            raise PipelineError("devices file lists %s twice" % device_id)
        profile: Dict[str, Any] = {"device_id": device_id}
        device_type = entry.get("device_type")
        if isinstance(device_type, str) and re.fullmatch(r"[A-Za-z0-9_ -]{1,40}", device_type):
            profile["device_type"] = device_type.strip().lower().replace(" ", "_")
        ip = entry.get("ip")
        try:
            profile["ip"] = str(ipaddress.ip_address(ip.strip())) if isinstance(ip, str) else None
        except ValueError:
            profile["ip"] = None
        crit = entry.get("criticality")
        profile["criticality"] = crit.strip().lower() if isinstance(crit, str) and crit.strip().lower() in _CRIT_VALUES else None
        ports = entry.get("expected_ports", entry.get("expected_services"))
        profile["expected_ports"] = [int(p) for p in ports if isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535][:1024] \
            if isinstance(ports, list) else []
        protocols = entry.get("expected_protocols")
        profile["expected_protocols"] = [p for p in protocols if isinstance(p, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,20}", p)][:50] \
            if isinstance(protocols, list) else []
        out_ports = entry.get("expected_outbound_ports")
        profile["expected_outbound_ports"] = [int(p) for p in out_ports if isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535][:1024] \
            if isinstance(out_ports, list) else []
        devices[device_id] = profile
    return devices


# ---------------------------------------------------------------------------
# Reading the CSV (untrusted)
# ---------------------------------------------------------------------------

def read_events(path: str, max_rows: int = DEFAULT_MAX_ROWS) -> Iterator[Tuple[int, Optional[dict], Optional[str]]]:
    """Yield (line_number, event, None) for good rows and (line_number, None, error_code) for bad ones.

    Raises PipelineError for problems with the file itself.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise PipelineError("cannot read the events file (%s)" % (exc.strerror or "error"))
    if size > MAX_CSV_BYTES:
        raise PipelineError("events file is larger than %d MB" % (MAX_CSV_BYTES // (1024 * 1024)))
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = [h.strip() for h in next(reader)]
            except StopIteration:
                raise PipelineError("events file is empty")
            if not header or len(header) > MAX_COLUMNS:
                raise PipelineError("events file needs between 1 and %d columns" % MAX_COLUMNS)
            if any(not _COLUMN_RE.fullmatch(h) for h in header):
                raise PipelineError("events file has a column name that is empty or has unusual characters")
            if len({h.lower() for h in header}) != len(header):
                raise PipelineError("events file has a duplicate column name")
            keep = [(i, h) for i, h in enumerate(header) if not h.lower().startswith(EXPECTED_PREFIX)]
            produced = 0
            for row in reader:
                line = reader.line_num
                if not row or all(not cell.strip() for cell in row):
                    continue
                if produced >= max_rows:
                    yield line, None, "row_limit_reached"
                    return
                produced += 1
                if len(row) > len(header):
                    yield line, None, "too_many_fields"
                    continue
                event: Dict[str, Optional[str]] = {}
                for i, name in keep:
                    cell = row[i].strip() if i < len(row) else ""
                    event[name] = cell[:MAX_FIELD_CHARS] if cell else None
                yield line, event, None
    except UnicodeDecodeError:
        raise PipelineError("events file is not valid UTF-8 text")
    except csv.Error:
        raise PipelineError("events file is not a valid CSV (control characters or a field that is far too long)")
    except OSError as exc:
        raise PipelineError("cannot read the events file (%s)" % (exc.strerror or "error"))


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------

def _finite(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Real):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


class Pipeline:
    """Runs events through the modules and stores incidents."""

    def __init__(self, database, modules: Modules, devices: Dict[str, dict], executor, policy_cfg: dict,
                 max_incidents: int = DEFAULT_MAX_INCIDENTS, dedup_window: float = 0):
        """dedup_window (seconds, 0 = off): a repeat of the same attack (same device, source and attack type) inside the
        window that is not more severe than the stored incident is counted but not stored again."""
        self.dedup_window = float(dedup_window or 0)
        self._seen: Dict[tuple, tuple] = {}
        self.duplicates = 0
        self.db = database
        self.m = modules
        self.devices = devices
        self.executor = executor
        self.policy_cfg = policy_cfg
        self.max_incidents = max_incidents

    def _reports(self, incident: dict, context: tuple) -> Any:
        """Real report.py (Person 7) wants the merged record from build_incident(); the placeholder wants the stored one."""
        if self.m.sources["report"] != "real":
            return self.m.make_report(incident)
        raw_event, detection, risk_msg, decision, profile = context
        # Person 7 gets only values that were already validated (db.py cleaned them); free text from the CSV never reaches a report.
        protocol = raw_event.get("protocol")
        duration = raw_event.get("duration")
        event = {"timestamp": incident.get("timestamp"), "src_ip": incident.get("src_ip"), "dst_ip": incident.get("dst_ip"),
                 "dst_port": incident.get("dst_port"),
                 "protocol": protocol.upper() if isinstance(protocol, str) and _PROTOCOL_RE.fullmatch(protocol) else None,
                 "duration": duration if isinstance(duration, str) and _DURATION_RE.fullmatch(duration) else None,
                 "failed_attempts": incident.get("attempts")}
        merged = self.m.build_incident(event, detection, risk_msg, decision, profile,
                                       incident_id=incident["incident_id"], timestamp=incident.get("timestamp") or incident.get("created_at"),
                                       status=incident["status"].capitalize())
        return self.m.make_report(merged)

    _RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

    def _epoch(self, event: Mapping) -> Optional[float]:
        moment = self._parse_time(event.get("timestamp")) if event.get("timestamp") not in (None, "") else None
        return None if moment is None else moment.replace(tzinfo=_dt.timezone.utc).timestamp()

    def _dedup_key(self, device_id: Optional[str], event: Mapping, detection: Mapping) -> tuple:
        attack = re.sub(r"[^a-z0-9]+", "_", str(detection.get("attack_type", "")).lower()).strip("_")
        return (device_id, str(event.get("src_ip") or "").strip(), attack)

    def process_event(self, event: Any, index: int = 0) -> dict:
        """Handle one event. Never raises for bad data or a failing module (config errors still stop the run)."""
        result: Dict[str, Any] = {"index": index, "outcome": None, "error": None, "level": None, "score": None,
                                  "actions": [], "incident_id": None, "attack_type": None, "device_id": None}
        if not isinstance(event, Mapping):
            result.update(outcome="rejected", error="event_not_a_mapping")
            return result
        raw_device = event.get("device_id")
        device_id = raw_device if isinstance(raw_device, str) and _DEVICE_RE.fullmatch(raw_device) else None
        result["device_id"] = device_id
        profile = self.devices.get(device_id, {}) if device_id else {}

        try:
            detection = self.m.detect(dict(event), profile)
        except Exception as exc:
            result.update(outcome="error", error="detector_failed:" + type(exc).__name__.lower()[:30])
            return result
        label = detection.get("label") if isinstance(detection, Mapping) else None
        label = label.strip().upper() if isinstance(label, str) else None
        if label not in ("BENIGN", "ATTACK"):
            result.update(outcome="error", error="detector_invalid_output")
            return result
        if label == "BENIGN":
            result["outcome"] = "benign"
            return result

        try:
            risk_msg = self.m.risk.assess(detection, event, profile)
            decision = self.m.policy.decide(risk_msg, detection, event, profile, policy=self.policy_cfg)
            records = self.executor.run(decision)
        except (self.m.risk.RiskConfigError, self.m.policy.PolicyConfigError) as exc:
            raise PipelineError("configuration problem: %s" % exc)
        except Exception as exc:
            result.update(outcome="error", error="module_failed:" + type(exc).__name__.lower()[:30])
            return result

        result.update(level=risk_msg.get("level"), score=risk_msg.get("score"),
                      actions=list(decision.get("action", [])), attack_type=detection.get("attack_type"))
        if "create_incident" not in decision.get("action", []):
            result["outcome"] = "no_incident"
            return result
        level = risk_msg.get("level")
        key, moment = self._dedup_key(device_id, event, detection), self._epoch(event)
        seen = self._seen.get(key)
        if (self.dedup_window > 0 and seen and moment is not None and 0 <= moment - seen[0] <= self.dedup_window
                and self._RANK.get(level, 0) <= seen[1]):
            self._seen[key] = (moment, seen[1], seen[2])          # sliding window: a continuing attack stays one incident
            self.duplicates += 1
            result.update(outcome="duplicate", incident_id=seen[2])
            return result
        if self.db.count() >= self.max_incidents:
            result.update(outcome="error", error="incident_limit_reached")
            return result

        notes = ["missing_" + f for f in CONTEXT_FIELDS if event.get(f) in (None, "")]
        if event.get("timestamp") not in (None, "") and self._parse_time(event.get("timestamp")) is None:
            notes.append("invalid_timestamp")
        attempts = [n for n in (_finite(event.get("failed_attempts")), _finite(event.get("connection_attempts")))
                    if n is not None and n >= 0]
        incident = {
            "timestamp": event.get("timestamp"),
            "device_id": device_id,
            "device_type": profile.get("device_type"),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"),
            "attack_type": detection.get("attack_type"),
            "confidence": detection.get("confidence"),
            "risk_score": risk_msg.get("score"),
            "risk_level": level,
            "risk_factors": risk_msg.get("factors"),
            "risk_warnings": list(risk_msg.get("warnings", [])) + list(decision.get("warnings", [])) + notes,
            "weight_set": risk_msg.get("weight_set"),
            "attempts": max(attempts) if attempts else None,
            "action": decision.get("action"),
            "action_result": ["%s:%s:%s" % (r["action"], r["status"], r["note"]) for r in records],
            "reason": decision.get("reason"),
            "rule_id": decision.get("rule_id"),
            "status": "monitoring" if level == "Low" else "open",
        }
        try:
            context = (dict(event), detection, risk_msg, decision, profile)
            stored = self.db.insert_incident(incident, make_reports=lambda inc: self._reports(inc, context))
        except Exception as exc:   # includes IncidentError for an unusable score or level
            result.update(outcome="error", error="store_failed:" + type(exc).__name__.lower()[:30])
            return result
        if moment is not None:
            self._seen[key] = (moment, self._RANK.get(level, 0), stored["incident_id"])
        result.update(outcome="incident", incident_id=stored["incident_id"])
        return result

    @staticmethod
    def _parse_time(value: Any):
        import db as _db
        return _db.parse_time(value)

    def process_csv(self, path: str, max_rows: int = DEFAULT_MAX_ROWS) -> Tuple[List[dict], dict]:
        results: List[dict] = []
        summary = {"rows_read": 0, "rows_rejected": 0, "benign": 0, "attacks": 0, "incidents_stored": 0,
                   "duplicates_suppressed": 0, "errors": {}, "truncated": False}
        for line, event, problem in read_events(path, max_rows):
            if problem == "row_limit_reached":
                summary["truncated"] = True
                break
            summary["rows_read"] += 1
            if problem:
                summary["rows_rejected"] += 1
                summary["errors"][problem] = summary["errors"].get(problem, 0) + 1
                results.append({"index": line, "outcome": "rejected", "error": problem, "level": None, "score": None,
                                "actions": [], "incident_id": None, "attack_type": None, "device_id": None})
                continue
            res = self.process_event(event, line)
            results.append(res)
            if res["outcome"] == "benign":
                summary["benign"] += 1
            elif res["outcome"] in ("incident", "no_incident", "duplicate"):
                summary["attacks"] += 1
                if res["outcome"] == "incident":
                    summary["incidents_stored"] += 1
                elif res["outcome"] == "duplicate":
                    summary["duplicates_suppressed"] += 1
            elif res["outcome"] == "error":
                code = res["error"].split(":")[0] if res["error"] else "error"
                summary["errors"][code] = summary["errors"].get(code, 0) + 1
        summary["by_level"] = self.db.summary_by_level()
        summary["modules"] = dict(self.m.sources, risk="real", policy="real")
        return results, summary


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def db_key_from_env() -> Optional[bytes]:
    """Optional secret for the incident hash chain: environment variable IOTIPS_DB_KEY (16+ characters)."""
    value = os.environ.get("IOTIPS_DB_KEY")
    if not value:
        return None
    if len(value) < 16:
        raise PipelineError("IOTIPS_DB_KEY must be at least 16 characters")
    return value.encode("utf-8")


def _safe_remove(path: str) -> None:
    if os.path.islink(path):
        raise PipelineError("refusing to delete a symbolic link: %s" % path)
    if os.path.isfile(path):
        os.remove(path)


def run_command(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout
    import db as dbmod
    forced = getattr(args, "placeholders", None)
    modules = Modules(force_placeholders=True if forced == "all" else ({forced} if forced else False))
    if getattr(args, "require_real", False):
        fake = sorted(k for k, v in modules.sources.items() if v != "real")
        if fake:
            raise PipelineError("--require-real: still using placeholders for %s (put Person 3's and Person 7's folders beside this one)" % ", ".join(fake))
    policy_cfg = modules.policy.load_policy()
    devices = load_devices(args.devices) if args.devices and os.path.exists(args.devices) else {}
    if args.devices and not os.path.exists(args.devices):
        print("note: devices file %s not found; every device is treated as unknown (cautious defaults)" % args.devices, file=out)
    log_path = args.action_log or os.path.join(os.path.dirname(os.path.abspath(args.db)), "actions.jsonl")
    if args.reset:
        for path in (args.db, log_path, log_path + ".1"):
            _safe_remove(path)
    key = db_key_from_env()
    try:
        database = dbmod.IncidentDB(args.db, hmac_key=key)
    except dbmod.IncidentDBError as exc:
        raise PipelineError(str(exc))
    with database:
        executor = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=log_path)
        pipeline = Pipeline(database, modules, devices, executor, policy_cfg, max_incidents=args.max_incidents,
                            dedup_window=getattr(args, "dedup_window", 0))
        results, summary = pipeline.process_csv(args.events, max_rows=args.max_rows)
        summary["head_hash"] = database.head_hash()
        summary["hash_mode"] = "hmac-sha256" if key else "sha256 (set IOTIPS_DB_KEY for a keyed chain)"
    _print_run_summary(summary, executor, log_path, args, out)
    return 2 if (summary["errors"] or summary["rows_rejected"]) else 0


def _print_run_summary(summary: dict, executor, log_path: str, args: argparse.Namespace, out) -> None:
    modules = summary["modules"]
    print("IoT-IPS pipeline run", file=out)
    print("  modules      : " + ", ".join("%s=%s" % (k, v) for k, v in sorted(modules.items())), file=out)
    print("  rows read    : %d (rejected %d)%s" % (summary["rows_read"], summary["rows_rejected"],
                                                    ", stopped at the row limit" if summary["truncated"] else ""), file=out)
    print("  benign       : %d" % summary["benign"], file=out)
    print("  attacks      : %d, incidents stored: %d" % (summary["attacks"], summary["incidents_stored"]), file=out)
    if getattr(args, "dedup_window", 0):
        print("  duplicates   : %d repeat(s) inside %gs not stored again" % (summary["duplicates_suppressed"], args.dedup_window), file=out)
    print("  by level     : " + ", ".join("%s %d" % (k, v) for k, v in summary["by_level"].items()), file=out)
    if summary["errors"]:
        print("  problems     : " + ", ".join("%s x%d" % (k, v) for k, v in sorted(summary["errors"].items())), file=out)
    print("  action log   : %s (%d records, all simulated)" % (log_path, len(executor.records)), file=out)
    print("  database     : %s" % args.db, file=out)
    print("  chain head   : %s [%s]" % (summary["head_hash"][:16] + "...", summary["hash_mode"]), file=out)


def _clean_cell(value: Any, width: int) -> str:
    text = "-" if value is None else str(value)
    return re.sub(r"[^\x20-\x7e]", "?", text)[:width]


def format_table(incidents: List[dict]) -> str:
    columns = [("id", "incident_id", 9), ("time", "timestamp", 20), ("device", "device_id", 14), ("source", "src_ip", 15),
               ("attack", "attack_type", 14), ("conf", "confidence", 5), ("score", "risk_score", 5),
               ("level", "risk_level", 8), ("actions", "action", 44), ("status", "status", 10)]
    lines = ["  ".join(title.ljust(width) for title, _k, width in columns)]
    lines.append("  ".join("-" * width for _t, _k, width in columns))
    for inc in incidents:
        cells = []
        for _title, key, width in columns:
            value = inc.get(key)
            if key == "action":
                value = ",".join(value or [])
            elif key == "confidence" and value is not None:
                value = "%.2f" % value
            cells.append(_clean_cell(value, width).ljust(width))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def show_command(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout
    import db as dbmod
    if not os.path.isfile(args.db):
        raise PipelineError("database %s does not exist; run the pipeline first" % args.db)
    try:
        database = dbmod.IncidentDB(args.db, hmac_key=db_key_from_env())
    except dbmod.IncidentDBError as exc:
        raise PipelineError(str(exc))
    with database:
        if args.full:
            try:
                inc = database.get_incident(args.full)
            except (KeyError, ValueError):
                raise PipelineError("incident not found or id not valid (use INC-00001)")
            print(format_table([inc]), file=out)
            print("\nreason : %s" % _clean_cell(inc["reason"], 300), file=out)
            print("rule   : %s   weight set: %s   dry run: %s" % (_clean_cell(inc["rule_id"], 40), _clean_cell(inc["weight_set"], 32), inc["dry_run"]), file=out)
            print("results: %s" % ", ".join(inc["action_result"]), file=out)
            print("notes  : %s" % (", ".join(inc["risk_warnings"]) or "none"), file=out)
            print("\n--- technical report ---\n%s\n\n--- executive report ---\n%s" % (inc["report_technical"], inc["report_plain"]), file=out)
            if inc.get("report_notification"):
                print("\n--- notification ---\n%s" % inc["report_notification"], file=out)
            return 0
        try:
            rows = database.query_incidents(level=args.level, device_id=args.device, src_ip=args.source,
                                            attack_type=args.attack, status=args.status, since=args.since, limit=args.limit)
        except ValueError as exc:
            raise PipelineError(str(exc))
        print(format_table(rows) if rows else "(no incidents match)", file=out)
        print("\nIncidents by level: " + ", ".join("%s %d" % (k, v) for k, v in database.summary_by_level().items())
              + "   (total %d)" % database.count(), file=out)
        print("By status         : " + ", ".join("%s %d" % (k, v) for k, v in database.summary_by_status().items()), file=out)
    return 0


def verify_command(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout
    import db as dbmod
    if not os.path.isfile(args.db):
        raise PipelineError("database %s does not exist" % args.db)
    try:
        database = dbmod.IncidentDB(args.db, hmac_key=db_key_from_env())
    except dbmod.IncidentDBError as exc:
        raise PipelineError(str(exc))
    with database:
        report = database.verify_chain(expected_head=args.head)
    print("incidents checked: %d" % report["rows"], file=out)
    print("head hash        : %s" % report["head"], file=out)
    if report["ok"]:
        print("RESULT: chain is intact", file=out)
        return 0
    print("RESULT: TAMPERING OR CORRUPTION FOUND", file=out)
    for problem in report["problems"]:
        print("  - " + problem, file=out)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run_pipeline.py", description="IoT-IPS pipeline: CSV events to incidents.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="process a CSV of events")
    run.add_argument("events", help="events CSV (Person 2's sample_events.csv)")
    run.add_argument("--db", default="incidents.db")
    run.add_argument("--devices", default=os.path.join(HERE, "devices.json"), help="device profiles (Person 1's devices.json)")
    run.add_argument("--action-log", default=None, help="action log file (default: actions.jsonl beside the database)")
    run.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    run.add_argument("--max-incidents", type=int, default=DEFAULT_MAX_INCIDENTS)
    run.add_argument("--reset", action="store_true", help="delete the database and action log first")
    run.add_argument("--dedup-window", type=float, default=0, metavar="SECONDS",
                     help="store a repeat of the same attack (device, source, type) inside this window only once (default 0 = off)")
    run.add_argument("--placeholders", nargs="?", const="all", choices=["all", "detector", "report"], default=None,
                     help="use the built-in placeholder for the detector, the report, or both (tests, demos without Persons 3 and 7)")
    run.add_argument("--require-real", action="store_true", help="stop unless Person 3's detector and Person 7's report module are found")
    run.set_defaults(func=run_command)

    show = sub.add_parser("show", help="print stored incidents and a count by level")
    show.add_argument("--db", default="incidents.db")
    show.add_argument("--level")
    show.add_argument("--device")
    show.add_argument("--source", help="source IP")
    show.add_argument("--attack")
    show.add_argument("--status")
    show.add_argument("--since", help="ISO date or time, for example 2026-10-20")
    show.add_argument("--limit", type=int, default=50)
    show.add_argument("--full", metavar="INC-00001", help="print one incident with both reports")
    show.set_defaults(func=show_command)

    verify = sub.add_parser("verify", help="check the incident database for tampering")
    verify.add_argument("--db", default="incidents.db")
    verify.add_argument("--head", help="head hash saved earlier")
    verify.set_defaults(func=verify_command)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    for name in ("max_rows", "max_incidents", "limit"):
        value = getattr(args, name, None)
        if value is not None and not 1 <= value <= 10_000_000:
            print("error: --%s must be between 1 and 10000000" % name.replace("_", "-"), file=sys.stderr)
            return 2
    try:
        return args.func(args)
    except PipelineError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
