from __future__ import annotations

import json
import math
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BACKEND_DIR / "data" / "public_datasets" / "host_external"
TRAIN_PATH = OUTPUT_DIR / "train_host_external.jsonl"
VAL_PATH = OUTPUT_DIR / "val_host_external.jsonl"

RANDOM_SEED = 42
TRAIN_BENIGN_ROWS = 20_000
VAL_BENIGN_ROWS = 4_000
VAL_ANOMALY_ROWS = 3_000

LOGIN_USERS = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi",
    "ivy", "judy", "mallory", "oscar", "peggy", "trent", "victor", "wendy",
]
ADMIN_USERS = ["admin", "secadmin", "backupadmin", "domainadmin"]
SERVICE_USERS = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "svc_backup", "svc_update"]

BENIGN_EVENT_DEFS = [
    {
        "event_id": 4624,
        "event_type": "win_login_success",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12544,
        "actor_pool": LOGIN_USERS + ADMIN_USERS + SERVICE_USERS,
        "hour_weights": {
            "day": 0.72,
            "evening": 0.20,
            "off": 0.08,
        },
        "actor_missing_rate": 0.01,
    },
    {
        "event_id": 4634,
        "event_type": "win_event_4634",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12545,
        "actor_pool": LOGIN_USERS + ADMIN_USERS,
        "hour_weights": {
            "day": 0.60,
            "evening": 0.30,
            "off": 0.10,
        },
        "actor_missing_rate": 0.02,
    },
    {
        "event_id": 5379,
        "event_type": "win_event_5379",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12548,
        "actor_pool": LOGIN_USERS + SERVICE_USERS,
        "hour_weights": {
            "day": 0.55,
            "evening": 0.25,
            "off": 0.20,
        },
        "actor_missing_rate": 0.10,
    },
    {
        "event_id": 4798,
        "event_type": "win_event_4798",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 13824,
        "actor_pool": ADMIN_USERS + SERVICE_USERS,
        "hour_weights": {
            "day": 0.65,
            "evening": 0.20,
            "off": 0.15,
        },
        "actor_missing_rate": 0.08,
    },
    {
        "event_id": 4799,
        "event_type": "win_event_4799",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 13824,
        "actor_pool": ADMIN_USERS + SERVICE_USERS,
        "hour_weights": {
            "day": 0.65,
            "evening": 0.20,
            "off": 0.15,
        },
        "actor_missing_rate": 0.08,
    },
    {
        "event_id": 5058,
        "event_type": "win_event_5058",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12290,
        "actor_pool": SERVICE_USERS + ["SYSTEM"],
        "hour_weights": {
            "day": 0.35,
            "evening": 0.30,
            "off": 0.35,
        },
        "actor_missing_rate": 0.20,
    },
    {
        "event_id": 5059,
        "event_type": "win_event_5059",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12290,
        "actor_pool": SERVICE_USERS + ["SYSTEM"],
        "hour_weights": {
            "day": 0.35,
            "evening": 0.30,
            "off": 0.35,
        },
        "actor_missing_rate": 0.20,
    },
    {
        "event_id": 5061,
        "event_type": "win_event_5061",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12290,
        "actor_pool": SERVICE_USERS + ["SYSTEM"],
        "hour_weights": {
            "day": 0.35,
            "evening": 0.30,
            "off": 0.35,
        },
        "actor_missing_rate": 0.20,
    },
    {
        "event_id": 6,
        "event_type": "win_event_6",
        "channel": "System",
        "source": "Microsoft-Windows-Kernel-General",
        "event_category": 0,
        "actor_pool": ["SYSTEM"],
        "hour_weights": {
            "day": 0.33,
            "evening": 0.27,
            "off": 0.40,
        },
        "actor_missing_rate": 0.55,
    },
    {
        "event_id": 112,
        "event_type": "win_event_112",
        "channel": "System",
        "source": "Microsoft-Windows-FilterManager",
        "event_category": 0,
        "actor_pool": ["SYSTEM", "LOCAL SERVICE"],
        "hour_weights": {
            "day": 0.38,
            "evening": 0.27,
            "off": 0.35,
        },
        "actor_missing_rate": 0.45,
    },
]

ANOMALY_EVENT_DEFS = [
    {
        "event_id": 4625,
        "event_type": "win_login_failed",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12544,
        "actor_pool": LOGIN_USERS + ADMIN_USERS,
        "hour_weights": {
            "day": 0.20,
            "evening": 0.20,
            "off": 0.60,
        },
        "actor_missing_rate": 0.02,
    },
    {
        "event_id": 4672,
        "event_type": "win_event_4672",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12548,
        "actor_pool": ADMIN_USERS + ["SYSTEM"],
        "hour_weights": {
            "day": 0.10,
            "evening": 0.10,
            "off": 0.80,
        },
        "actor_missing_rate": 0.01,
    },
    {
        "event_id": 4648,
        "event_type": "win_event_4648",
        "channel": "Security",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_category": 12544,
        "actor_pool": ADMIN_USERS + LOGIN_USERS,
        "hour_weights": {
            "day": 0.25,
            "evening": 0.20,
            "off": 0.55,
        },
        "actor_missing_rate": 0.02,
    },
]


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


def build_feature_vector(
    row: dict,
    actor_frequency: Counter,
    event_type_frequency: Counter,
    total_rows: int,
) -> list[float]:
    raw = row["raw"]
    event_type = str(row.get("event_type") or "")
    actor = str(row.get("actor") or "")
    event_id = event_id_from_row(event_type, raw)
    channel = channel_from_row(row.get("resource"), raw)
    timestamp = datetime.fromisoformat(str(row["timestamp"]))
    hour_of_day = float(timestamp.hour if timestamp else 0)
    actor_frequency_norm = (actor_frequency.get(actor, 0) / total_rows) if total_rows else 0.0
    event_type_frequency_norm = (event_type_frequency.get(event_type, 0) / total_rows) if total_rows else 0.0
    off_hours_flag = 1.0 if hour_of_day < 6 or hour_of_day > 22 else 0.0
    failed_login_intensity = 1.0 if event_type == "win_login_failed" else 0.0
    privileged_off_hours_combo = 1.0 if event_id == 4672 and off_hours_flag == 1.0 else 0.0

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
    ]


def choose_hour_bucket(rng: random.Random, weights: dict[str, float]) -> str:
    roll = rng.random()
    cumulative = 0.0
    for bucket in ("day", "evening", "off"):
        cumulative += weights.get(bucket, 0.0)
        if roll <= cumulative:
            return bucket
    return "day"


def choose_hour(rng: random.Random, weights: dict[str, float]) -> int:
    bucket = choose_hour_bucket(rng, weights)
    if bucket == "day":
        return rng.choice([7, 8, 8, 9, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
    if bucket == "evening":
        return rng.choice([19, 20, 21, 22])
    return rng.choice([0, 1, 2, 3, 4, 5, 23])


def choose_actor(rng: random.Random, actor_pool: list[str], missing_rate: float) -> str | None:
    if rng.random() < missing_rate:
        return None

    weighted_pool = []
    for actor in actor_pool:
        weight = 1
        if actor in {"alice", "bob", "carol", "SYSTEM"}:
            weight = 3
        elif actor in {"admin", "secadmin"}:
            weight = 2
        weighted_pool.extend([actor] * weight)
    return rng.choice(weighted_pool)


def iso_timestamp(base: datetime, day_offset: int, hour: int, minute: int, second: int) -> str:
    event_dt = (base - timedelta(days=day_offset)).replace(
        hour=hour,
        minute=minute,
        second=second,
        microsecond=0,
    )
    return event_dt.isoformat()


def build_row(
    event_def: dict,
    label: str,
    timestamp: str,
    actor: str | None,
) -> dict:
    channel = event_def["channel"]
    source = event_def["source"]
    event_id = int(event_def["event_id"])

    return {
        "source": "host",
        "event_type": event_def["event_type"],
        "timestamp": timestamp,
        "actor": actor,
        "ip": None,
        "resource": f"{channel}:{source}",
        "rules_triggered": [f"HOST_EVENT_{event_id}"],
        "label": label,
        "raw": {
            "channel": channel,
            "source": source,
            "event_id": event_id,
            "event_category": int(event_def["event_category"]),
        },
    }


def generate_benign_rows(rng: random.Random, count: int, base: datetime) -> list[dict]:
    rows = []
    weighted_defs = (
        [BENIGN_EVENT_DEFS[0]] * 42 +
        [BENIGN_EVENT_DEFS[1]] * 18 +
        [BENIGN_EVENT_DEFS[2]] * 12 +
        [BENIGN_EVENT_DEFS[3]] * 6 +
        [BENIGN_EVENT_DEFS[4]] * 6 +
        [BENIGN_EVENT_DEFS[5]] * 4 +
        [BENIGN_EVENT_DEFS[6]] * 4 +
        [BENIGN_EVENT_DEFS[7]] * 4 +
        [BENIGN_EVENT_DEFS[8]] * 2 +
        [BENIGN_EVENT_DEFS[9]] * 2
    )

    for _ in range(count):
        event_def = rng.choice(weighted_defs)
        actor = choose_actor(rng, event_def["actor_pool"], event_def["actor_missing_rate"])
        hour = choose_hour(rng, event_def["hour_weights"])
        minute = rng.randint(0, 59)
        second = rng.randint(0, 59)
        day_offset = rng.randint(0, 89)
        rows.append(build_row(
            event_def=event_def,
            label="benign",
            timestamp=iso_timestamp(base, day_offset, hour, minute, second),
            actor=actor,
        ))

    return rows


def generate_failed_login_burst_rows(rng: random.Random, total_count: int, base: datetime) -> list[dict]:
    rows = []
    event_def = ANOMALY_EVENT_DEFS[0]
    remaining = total_count

    while remaining > 0:
        burst_size = min(remaining, rng.randint(4, 12))
        target_user = rng.choice(LOGIN_USERS + ADMIN_USERS)
        day_offset = rng.randint(0, 59)
        burst_hour = rng.choice([0, 1, 2, 3, 4, 5, 23, 22])
        base_minute = rng.randint(0, 54)
        base_second = rng.randint(0, 40)

        for i in range(burst_size):
            rows.append(build_row(
                event_def=event_def,
                label="anomaly",
                timestamp=iso_timestamp(
                    base,
                    day_offset,
                    burst_hour,
                    min(59, base_minute + i),
                    min(59, base_second + (i % 15)),
                ),
                actor=target_user,
            ))
        remaining -= burst_size

    return rows


def generate_privileged_rows(rng: random.Random, total_count: int, base: datetime) -> list[dict]:
    rows = []
    event_def = ANOMALY_EVENT_DEFS[1]
    for _ in range(total_count):
        actor = rng.choice(ADMIN_USERS + ["SYSTEM"])
        day_offset = rng.randint(0, 59)
        hour = rng.choice([0, 1, 2, 3, 4, 5, 23])
        minute = rng.randint(0, 59)
        second = rng.randint(0, 59)
        rows.append(build_row(
            event_def=event_def,
            label="anomaly",
            timestamp=iso_timestamp(base, day_offset, hour, minute, second),
            actor=actor,
        ))
    return rows


def generate_explicit_credential_rows(rng: random.Random, total_count: int, base: datetime) -> list[dict]:
    rows = []
    event_def = ANOMALY_EVENT_DEFS[2]
    for _ in range(total_count):
        actor = rng.choice(ADMIN_USERS + LOGIN_USERS[:8])
        day_offset = rng.randint(0, 59)
        hour = rng.choice([1, 2, 3, 4, 5, 21, 22, 23])
        minute = rng.randint(0, 59)
        second = rng.randint(0, 59)
        rows.append(build_row(
            event_def=event_def,
            label="anomaly",
            timestamp=iso_timestamp(base, day_offset, hour, minute, second),
            actor=actor,
        ))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    rng = random.Random(RANDOM_SEED)
    base = datetime.now(timezone.utc).replace(microsecond=0)

    train_benign_rows = generate_benign_rows(rng, TRAIN_BENIGN_ROWS, base)
    val_benign_rows = generate_benign_rows(rng, VAL_BENIGN_ROWS, base)

    anomaly_rows = []
    anomaly_rows.extend(generate_failed_login_burst_rows(rng, 1_500, base))
    anomaly_rows.extend(generate_privileged_rows(rng, 900, base))
    anomaly_rows.extend(generate_explicit_credential_rows(rng, 600, base))

    all_rows = train_benign_rows + val_benign_rows + anomaly_rows
    total_rows = len(all_rows)
    actor_frequency = Counter(str(row.get("actor") or "") for row in all_rows)
    event_type_frequency = Counter(str(row.get("event_type") or "") for row in all_rows)

    for row in all_rows:
        row["features"] = build_feature_vector(row, actor_frequency, event_type_frequency, total_rows)

    rng.shuffle(train_benign_rows)
    val_rows = val_benign_rows + anomaly_rows
    rng.shuffle(val_rows)

    write_jsonl(TRAIN_PATH, train_benign_rows)
    write_jsonl(VAL_PATH, val_rows)

    print(f"[INFO] Train benign rows written: {len(train_benign_rows)}")
    print(f"[INFO] Validation rows written: {len(val_rows)}")
    print(f"[INFO] Validation benign rows: {len(val_benign_rows)}")
    print(f"[INFO] Validation anomaly rows: {len(anomaly_rows)}")
    print(f"[INFO] Train file: {TRAIN_PATH}")
    print(f"[INFO] Validation file: {VAL_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
