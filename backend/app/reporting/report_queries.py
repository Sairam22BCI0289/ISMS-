from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from app.config import DATABASE_URL


def sqlite_path_from_database_url(database_url: str = DATABASE_URL) -> Path | None:
    if not database_url.startswith("sqlite:///"):
        return None
    raw_path = database_url.replace("sqlite:///", "", 1)
    return Path(unquote(raw_path))


def connect_readonly(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or sqlite_path_from_database_url()
    if path is None:
        raise RuntimeError(f"Only sqlite DATABASE_URL values are supported for reporting: {DATABASE_URL}")
    if not path.exists():
        raise FileNotFoundError(f"SQLite database not found: {path}")

    uri = f"file:{path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_security_events() -> list[dict[str, Any]]:
    with connect_readonly() as conn:
        rows = conn.execute("SELECT * FROM security_events ORDER BY timestamp ASC").fetchall()
    return [dict(row) for row in rows]


def fetch_schema_summary() -> list[dict[str, Any]]:
    with connect_readonly() as conn:
        rows = conn.execute("PRAGMA table_info(security_events)").fetchall()
    return [dict(row) for row in rows]


def count_by_field(events: list[dict[str, Any]], field: str, missing_label: str = "not recorded") -> Counter:
    counter: Counter = Counter()
    for event in events:
        value = event.get(field)
        label = str(value).strip() if value not in (None, "") else missing_label
        counter[label] += 1
    return counter


def parse_rules(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
        except Exception:
            pass
        return [text]
    return [str(value)]


def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    for candidate in (text, text.replace("Z", "+00:00")):
        try:
            return datetime.fromisoformat(candidate)
        except Exception:
            pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            pass
    return None


def numeric_value(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except Exception:
        return None
    return number if number == number else None


def event_risk(event: dict[str, Any]) -> float:
    candidates = [
        event.get("host_multilayer_risk"),
        event.get("network_multilayer_risk"),
        event.get("anomaly_risk_10"),
        event.get("anomaly_risk_10_svm"),
        event.get("host_auth_risk"),
        event.get("host_behavior_risk"),
    ]
    values = [numeric_value(value) for value in candidates]
    values = [value for value in values if value is not None]
    return max(values) if values else 0.0


def is_ml_positive(event: dict[str, Any]) -> bool:
    return (
        str(event.get("anomaly_label") or "").lower() == "anomalous"
        or str(event.get("anomaly_label_svm") or "").lower() == "anomalous"
        or (numeric_value(event.get("host_multilayer_risk")) or 0.0) >= 7.0
        or (numeric_value(event.get("network_multilayer_risk")) or 0.0) >= 7.0
    )


def is_rule_positive(event: dict[str, Any]) -> bool:
    return bool(parse_rules(event.get("rules_triggered")))


def entity_keys(event: dict[str, Any]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for field in ("actor", "ip", "resource"):
        value = str(event.get(field) or "").strip()
        if value and value.lower() not in {"-", "unknown", "none", "null", "n/a"}:
            keys.append((field, value))
    return keys
