from __future__ import annotations

import json
import math
import random
import sys
import ipaddress
from collections import Counter
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.base import SessionLocal
from app.db.models import SecurityEvent

OUTPUT_DIR = BACKEND_DIR / "data" / "public_datasets" / "host_local"
TRAIN_PATH = OUTPUT_DIR / "train_host.jsonl"
VAL_PATH = OUTPUT_DIR / "val_host.jsonl"
TRAIN_RATIO = 0.8
RANDOM_SEED = 42

ANOMALY_EVENT_TYPES = {
    "win_login_failed",
    "win_event_4672",
    "win_event_4648",
}

BENIGN_EVENT_TYPES = {
    "win_login_success",
    "win_event_4634",
    "win_event_5379",
    "win_event_4798",
    "win_event_4799",
    "win_event_5058",
    "win_event_5059",
    "win_event_5061",
    "win_event_6",
    "win_event_112",
}


def parse_raw(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def stable_hash(value: Any) -> float:
    text = str(value or "").lower()
    return float(sum(ord(ch) for ch in text) % 1000)


def numeric_or_default(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        if math.isfinite(result):
            return result
    except Exception:
        pass
    return default


def event_id_from_row(event_type: str, raw: dict) -> int:
    raw_event_id = raw.get("event_id")
    try:
        return int(raw_event_id)
    except Exception:
        pass

    prefix = "win_event_"
    if str(event_type).startswith(prefix):
        try:
            return int(str(event_type)[len(prefix):])
        except Exception:
            return 0

    if event_type == "win_login_success":
        return 4624
    if event_type == "win_login_failed":
        return 4625
    return 0


def channel_from_row(resource: Any, raw: dict) -> str:
    channel = str(raw.get("channel") or "").strip()
    if channel:
        return channel

    resource_text = str(resource or "")
    if ":" in resource_text:
        return resource_text.split(":", 1)[0].strip()
    return ""


def auth_outcome_code(event_type: str) -> float:
    if event_type == "win_login_success":
        return 1.0
    if event_type == "win_login_failed":
        return 2.0
    return 0.0


def source_ip_value(row: SecurityEvent, raw: dict) -> str:
    candidate = str(row.ip or "").strip()
    if candidate:
        return candidate
    return str(raw.get("source_ip") or "").strip()


def source_ip_scope_code(ip_text: str) -> float:
    if not ip_text:
        return 0.0

    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return 0.0

    if ip_obj.is_loopback:
        return 1.0
    if ip_obj.is_private:
        return 2.0
    return 3.0


def label_for_event(event_type: str, event_id: int) -> str | None:
    if event_type in ANOMALY_EVENT_TYPES or event_id in {4625, 4672, 4648}:
        return "anomaly"

    if event_type in BENIGN_EVENT_TYPES or event_id in {4624, 4634, 5379, 4798, 4799, 5058, 5059, 5061, 6, 112}:
        return "benign"

    return None


def build_feature_vector(
    row: SecurityEvent,
    raw: dict,
    actor_frequency: Counter,
    event_type_frequency: Counter,
    total_rows: int,
) -> list[float]:
    event_type = str(row.event_type or "")
    actor = str(row.actor or "")
    event_id = event_id_from_row(event_type, raw)
    channel = channel_from_row(row.resource, raw)
    timestamp = row.timestamp
    hour_of_day = float(timestamp.hour if timestamp else 0)
    actor_frequency_norm = (actor_frequency.get(actor, 0) / total_rows) if total_rows else 0.0
    event_type_frequency_norm = (event_type_frequency.get(event_type, 0) / total_rows) if total_rows else 0.0
    off_hours_flag = 1.0 if hour_of_day < 6 or hour_of_day > 22 else 0.0
    failed_login_intensity = 1.0 if event_type == "win_login_failed" else 0.0
    privileged_off_hours_combo = 1.0 if event_id == 4672 and off_hours_flag == 1.0 else 0.0
    source_ip = source_ip_value(row, raw)
    process_name = str(raw.get("process_name") or "")
    source_provider = str(raw.get("source") or "")
    computer_name = str(raw.get("computer_name") or "")

    return [
        float(event_id),
        stable_hash(event_type),
        stable_hash(actor),
        1.0 if actor else 0.0,
        hour_of_day,
        stable_hash(channel),
        1.0 if event_id == 4672 else 0.0,
        auth_outcome_code(event_type),
        numeric_or_default(raw.get("event_category"), 0.0),
        float(actor_frequency_norm),
        float(event_type_frequency_norm),
        off_hours_flag,
        failed_login_intensity,
        privileged_off_hours_combo,
        1.0 if source_ip else 0.0,
        source_ip_scope_code(source_ip),
        numeric_or_default(raw.get("logon_type"), 0.0),
        stable_hash(process_name),
        1.0 if process_name else 0.0,
        stable_hash(source_provider),
        stable_hash(computer_name),
    ]


def export_row(
    row: SecurityEvent,
    actor_frequency: Counter,
    event_type_frequency: Counter,
    total_rows: int,
) -> dict | None:
    raw = parse_raw(row.raw)
    event_type = str(row.event_type or "")
    event_id = event_id_from_row(event_type, raw)
    label = label_for_event(event_type, event_id)
    if label is None:
        return None

    return {
        "id": row.id,
        "source": row.source,
        "event_type": event_type,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "actor": row.actor,
        "ip": row.ip,
        "resource": row.resource,
        "label": label,
        "raw": raw,
        "features": build_feature_vector(row, raw, actor_frequency, event_type_frequency, total_rows),
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def print_counts(name: str, rows: list[dict]) -> None:
    label_counts = Counter(row["label"] for row in rows)
    type_counts = Counter(row["event_type"] for row in rows)

    print(f"[INFO] {name} rows: {len(rows)}")
    for label, count in sorted(label_counts.items()):
        print(f"[INFO] {name} label={label}: {count}")
    for event_type, count in type_counts.most_common():
        print(f"[INFO] {name} event_type={event_type}: {count}")


def main() -> int:
    db = SessionLocal()
    try:
        rows = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.source == "host")
            .order_by(SecurityEvent.id.asc())
            .all()
        )
    finally:
        db.close()

    total_rows = len(rows)
    actor_frequency = Counter(str(row.actor or "") for row in rows)
    event_type_frequency = Counter(str(row.event_type or "") for row in rows)

    exported_rows = []
    skipped_unlabeled = 0
    for row in rows:
        exported = export_row(row, actor_frequency, event_type_frequency, total_rows)
        if exported is None:
            skipped_unlabeled += 1
            continue
        exported_rows.append(exported)

    benign_rows = [row for row in exported_rows if row["label"] == "benign"]
    anomaly_rows = [row for row in exported_rows if row["label"] == "anomaly"]

    rng = random.Random(RANDOM_SEED)
    rng.shuffle(benign_rows)
    rng.shuffle(anomaly_rows)

    benign_cut = max(1, int(len(benign_rows) * TRAIN_RATIO)) if benign_rows else 0
    anomaly_cut = max(1, int(len(anomaly_rows) * TRAIN_RATIO)) if anomaly_rows else 0

    train_rows = benign_rows[:benign_cut] + anomaly_rows[:anomaly_cut]
    val_rows = benign_rows[benign_cut:] + anomaly_rows[anomaly_cut:]

    rng.shuffle(train_rows)
    rng.shuffle(val_rows)

    write_jsonl(TRAIN_PATH, train_rows)
    write_jsonl(VAL_PATH, val_rows)

    print(f"[INFO] Total host rows read: {len(rows)}")
    print(f"[INFO] Labeled rows exported: {len(exported_rows)}")
    print(f"[INFO] Unlabeled rows skipped: {skipped_unlabeled}")
    print_counts("train", train_rows)
    print_counts("val", val_rows)
    print(f"[INFO] Train file: {TRAIN_PATH}")
    print(f"[INFO] Val file: {VAL_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
