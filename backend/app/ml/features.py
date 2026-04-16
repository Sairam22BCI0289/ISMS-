"""Feature extraction helpers for anomaly models."""

from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Any

BEHAVIOR_EVENT_IDS = {4688, 4656, 4663, 10, 5156}
AUTH_EVENT_IDS = {4624, 4625, 4648, 4672}

LOLBIN_TERMS = {
    "bitsadmin",
    "certutil",
    "cmd.exe",
    "cscript",
    "mshta",
    "powershell",
    "psexec",
    "reg.exe",
    "regsvr32",
    "rundll32",
    "schtasks",
    "wmic",
    "wscript",
}
ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}
WEB_PORTS = {80, 443, 8080, 8443}


def _safe_text(value: Any, max_length: int = 500) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("#text", "text", "Value", "value", "@Value"):
            if key in value:
                return _safe_text(value.get(key), max_length=max_length)
        return ""
    if isinstance(value, list):
        for item in value:
            text = _safe_text(item, max_length=max_length)
            if text:
                return text
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        return text[:max_length]
    return text


def _safe_lower(value: Any, max_length: int = 500) -> str:
    return _safe_text(value, max_length=max_length).lower()


def _parse_raw(event: dict) -> dict:
    raw = event.get("raw")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _safe_int(value: Any, default: int = 0) -> int:
    text = _safe_text(value)
    if not text:
        return default
    try:
        return int(text, 0)
    except Exception:
        try:
            return int(float(text))
        except Exception:
            return default


def _stable_hash(value: Any) -> float:
    text = _safe_lower(value)
    return float(sum(ord(ch) for ch in text) % 1000)


def _numeric_or_default(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        if math.isfinite(result):
            return result
    except Exception:
        pass
    return default


def _find_key(obj: Any, names: set[str]) -> Any:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in names:
                return value
        for value in obj.values():
            found = _find_key(value, names)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_key(item, names)
            if found is not None:
                return found
    return None


def _collect_text(obj: Any, values: list[str] | None = None) -> list[str]:
    if values is None:
        values = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in {"#text", "text", "value", "@value", "message"}:
                text = _safe_text(value, max_length=1000)
                if text:
                    values.append(text)
            elif isinstance(value, (dict, list)):
                _collect_text(value, values)
            else:
                text = _safe_text(value, max_length=1000)
                if text:
                    values.append(text)
    elif isinstance(obj, list):
        for item in obj:
            _collect_text(item, values)
    else:
        text = _safe_text(obj, max_length=1000)
        if text:
            values.append(text)
    return values


def _combined_text(event: dict, raw: dict) -> str:
    parts = [
        _safe_text(event.get("event_type")),
        _safe_text(event.get("actor")),
        _safe_text(event.get("ip")),
        _safe_text(event.get("resource")),
    ]
    parts.extend(_collect_text(raw))
    return " | ".join(part for part in parts if part).lower()


def _event_id_from_event(event: dict, raw: dict | None = None) -> int:
    raw = raw if raw is not None else _parse_raw(event)
    for candidate in (
        raw.get("event_id"),
        raw.get("EventID"),
        raw.get("eventID"),
        event.get("event_id"),
        event.get("EventID"),
    ):
        event_id = _safe_int(candidate)
        if event_id:
            return event_id

    event_type = _safe_lower(event.get("event_type"))
    if event_type == "win_login_success":
        return 4624
    if event_type == "win_login_failed":
        return 4625
    if event_type.startswith("win_event_"):
        return _safe_int(event_type.replace("win_event_", "", 1))
    return 0


def _timestamp_hour(event: dict) -> int:
    value = event.get("timestamp")
    if isinstance(value, datetime):
        return int(value.hour)
    text = _safe_text(value, max_length=80)
    if not text:
        return 0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return int(datetime.fromisoformat(text).hour)
    except Exception:
        return 0


def _counter_frequency(stats: dict | None, counter_name: str, value: Any) -> float:
    if not isinstance(stats, dict):
        return 0.0
    counter = stats.get(counter_name)
    if not isinstance(counter, dict):
        return 0.0
    key = _safe_text(value).lower()
    total = stats.get("total_rows")
    try:
        total_value = float(total)
    except Exception:
        total_value = float(sum(counter.values()))
    if total_value <= 0:
        return 0.0
    return float(counter.get(key, 0)) / total_value


def parse_process_name(event: dict) -> str:
    raw = _parse_raw(event)
    value = _find_key(raw, {
        "process_name",
        "processname",
        "newprocessname",
        "image",
        "application",
    })
    if value is None:
        value = event.get("process_name")
    return _safe_text(value, max_length=500)


def parse_parent_process_name(event: dict) -> str:
    raw = _parse_raw(event)
    value = _find_key(raw, {
        "parent_process_name",
        "parentprocessname",
        "parentimage",
        "creatorprocessname",
    })
    return _safe_text(value, max_length=500)


def parse_destination_port(event: dict) -> int:
    raw = _parse_raw(event)
    value = _find_key(raw, {
        "dest_port",
        "destinationport",
        "destination_port",
        "dport",
        "remoteport",
        "port",
    })
    port = _safe_int(value)
    if port:
        return port

    resource = _safe_text(event.get("resource"), max_length=500)
    if ":" in resource:
        return _safe_int(resource.rsplit(":", 1)[1])
    return 0


def parse_protocol(event: dict) -> int:
    raw = _parse_raw(event)
    value = _find_key(raw, {"protocol", "ipprotocol", "transport"})
    text = _safe_lower(value)
    if text in {"6", "tcp"}:
        return 1
    if text in {"17", "udp"}:
        return 2
    if text in {"1", "icmp"}:
        return 3
    numeric = _safe_int(value)
    return 4 if numeric else 0


def parse_access_mask(event: dict) -> int:
    raw = _parse_raw(event)
    value = _find_key(raw, {"accessmask", "access_mask", "accesses"})
    return _safe_int(value)


def _is_public_ip(ip_value: Any) -> bool:
    text = _safe_lower(ip_value)
    if not text:
        return False
    if text.startswith("10.") or text.startswith("192.168.") or text in {"127.0.0.1", "::1"}:
        return False
    if text.startswith("172."):
        parts = text.split(".")
        if len(parts) > 1:
            second_octet = _safe_int(parts[1], default=-1)
            if 16 <= second_octet <= 31:
                return False
    return True


def extract_network_features(event: dict) -> list[float]:
    """Extract a minimal numeric feature vector for network events."""

    def event_type_num(value: object) -> float:
        mapping = {
            "net_conn_allowed": 1.0,
            "net_conn_high_risk": 2.0,
            "net_listener_open": 3.0,
        }
        return mapping.get(str(value or "").strip().lower(), 0.0)

    def parse_destination(resource: object, fallback_ip: object) -> tuple[str, float]:
        text = str(resource or "").strip()

        if "->" in text:
            destination = text.split("->", 1)[1].strip()
            if ":" in destination:
                ip_part, port_part = destination.rsplit(":", 1)
                try:
                    return ip_part.strip(), float(int(port_part))
                except ValueError:
                    return ip_part.strip(), 0.0
            return destination, 0.0

        ip_text = str(fallback_ip or "").strip()
        return ip_text, 0.0

    destination_ip, destination_port = parse_destination(
        event.get("resource"),
        event.get("ip"),
    )

    return [
        event_type_num(event.get("event_type")),
        _stable_hash(event.get("actor")),
        float(destination_port),
        1.0 if _is_public_ip(destination_ip) else 0.0,
    ]


def extract_cloud_features(event: dict) -> list[float]:
    """Return a minimal placeholder vector for cloud events."""
    return [0.0]


def extract_host_features(event: dict) -> list[float]:
    """Extract host auth features matching the offline host auth IF shape."""
    raw = _parse_raw(event)
    event_id = _event_id_from_event(event, raw)
    event_type = _safe_text(event.get("event_type"))
    actor_value = _safe_text(event.get("actor"))
    actor = actor_value or "unknown"
    hour_of_day = float(_timestamp_hour(event))
    channel = _safe_text(raw.get("channel"))
    source_provider = _safe_text(raw.get("source"))
    source_ip = _safe_text(event.get("ip")) or _safe_text(raw.get("source_ip"))
    process_name = parse_process_name(event) or "unknown"
    process_present = 1.0 if parse_process_name(event) else 0.0
    computer_name = _safe_text(raw.get("computer_name"))
    off_hours = 1.0 if hour_of_day < 6 or hour_of_day > 22 else 0.0

    return [
        float(event_id),
        _stable_hash(event_type),
        _stable_hash(actor),
        1.0 if actor_value else 0.0,
        hour_of_day,
        _stable_hash(channel),
        1.0 if event_id == 4672 else 0.0,
        1.0 if event_type == "win_login_success" else 2.0 if event_type == "win_login_failed" else 0.0,
        _numeric_or_default(raw.get("event_category"), 0.0),
        0.0,
        0.0,
        off_hours,
        1.0 if event_type == "win_login_failed" else 0.0,
        1.0 if event_id == 4672 and off_hours == 1.0 else 0.0,
        1.0 if source_ip else 0.0,
        3.0 if _is_public_ip(source_ip) else 2.0 if source_ip else 0.0,
        _numeric_or_default(raw.get("logon_type"), 0.0),
        _stable_hash(process_name),
        process_present,
        _stable_hash(source_provider),
        _stable_hash(computer_name),
    ]


def extract_host_behavior_features(event: dict, stats: dict | None = None) -> list[float]:
    """Extract fixed-order host behavior features for non-auth host events."""
    raw = _parse_raw(event)
    event_id = _event_id_from_event(event, raw)
    hour_bucket = float(_timestamp_hour(event))
    actor = _safe_text(event.get("actor")) or "unknown"
    ip_value = _safe_text(event.get("ip"))
    resource = _safe_text(event.get("resource"))
    process_name = parse_process_name(event)
    parent_process_name = parse_parent_process_name(event)
    dest_port = parse_destination_port(event)
    protocol_bucket = parse_protocol(event)
    combined = _combined_text(event, raw)
    process_context = f"{process_name} {parent_process_name}".lower()

    return [
        float(event_id),
        hour_bucket,
        1.0 if 8 <= hour_bucket < 18 else 0.0,
        _counter_frequency(stats, "actor_counter", actor),
        _counter_frequency(stats, "ip_counter", ip_value),
        _counter_frequency(stats, "resource_counter", resource),
        1.0 if process_name else 0.0,
        1.0 if any(term in process_context for term in LOLBIN_TERMS) else 0.0,
        1.0 if "powershell" in process_context else 0.0,
        1.0 if "cmd.exe" in process_context or PureWindowsPath(process_name).name.lower() == "cmd.exe" else 0.0,
        1.0 if any(term in process_context for term in {"wscript", "cscript", "mshta"}) else 0.0,
        1.0 if "lsass" in combined else 0.0,
        1.0 if "\\sam" in combined or "/sam" in combined or "security account manager" in combined else 0.0,
        1.0 if "currentversion\\run" in combined or "\\runonce" in combined else 0.0,
        1.0 if "startup" in combined and ("programs" in combined or "start menu" in combined) else 0.0,
        float(dest_port),
        1.0 if dest_port in ADMIN_PORTS else 0.0,
        1.0 if dest_port in WEB_PORTS else 0.0,
        1.0 if dest_port == 3389 else 0.0,
        float(protocol_bucket),
    ]
