from __future__ import annotations

import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.base import SessionLocal
from app.db.models import SecurityEvent
from app.ml.features import BEHAVIOR_EVENT_IDS, extract_host_behavior_features

MODEL_PATH = BACKEND_DIR / "models" / "host_behavior_iforest.joblib"
META_PATH = BACKEND_DIR / "models" / "host_behavior_iforest_meta.json"
MIN_TRAINING_ROWS = 20


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


def event_id_from_row(row: SecurityEvent, raw: dict) -> int:
    try:
        return int(raw.get("event_id"))
    except Exception:
        pass

    event_type = str(row.event_type or "")
    prefix = "win_event_"
    if event_type.startswith(prefix):
        try:
            return int(event_type[len(prefix):])
        except Exception:
            return 0
    return 0


def is_valid_feature_vector(vector: object) -> bool:
    if not isinstance(vector, list) or not vector:
        return False
    for value in vector:
        if not isinstance(value, (int, float)):
            return False
        if not math.isfinite(float(value)):
            return False
    return True


def compute_quantile(sorted_values: list[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("cannot compute quantile for empty input")
    if len(sorted_values) == 1:
        return float(sorted_values[0])

    position = (len(sorted_values) - 1) * probability
    lower_index = int(math.floor(position))
    upper_index = int(math.ceil(position))
    lower_value = float(sorted_values[lower_index])
    upper_value = float(sorted_values[upper_index])

    if lower_index == upper_index:
        return lower_value

    weight = position - lower_index
    return lower_value + ((upper_value - lower_value) * weight)


def row_to_event(row: SecurityEvent, raw: dict) -> dict:
    return {
        "source": row.source,
        "event_type": row.event_type,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "actor": row.actor,
        "ip": row.ip,
        "resource": row.resource,
        "raw": raw,
    }


def build_stats(events: list[dict]) -> dict:
    return {
        "total_rows": len(events),
        "actor_counter": Counter(str(event.get("actor") or "unknown").strip().lower() for event in events),
        "ip_counter": Counter(str(event.get("ip") or "").strip().lower() for event in events),
        "resource_counter": Counter(str(event.get("resource") or "").strip().lower() for event in events),
    }


def main() -> int:
    try:
        import joblib
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        print(f"[ERROR] Missing training dependency: {exc}")
        return 1

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
    behavior_events: list[dict] = []

    for row in rows:
        raw = parse_raw(row.raw)
        event_id = event_id_from_row(row, raw)
        if event_id not in BEHAVIOR_EVENT_IDS:
            continue
        behavior_events.append(row_to_event(row, raw))

    stats = build_stats(behavior_events)
    feature_rows: list[list[float]] = []

    for event in behavior_events:
        features = extract_host_behavior_features(event, stats)
        if not is_valid_feature_vector(features):
            continue
        feature_rows.append([float(value) for value in features])

    print(f"[INFO] Total host rows read: {total_rows}")
    print(f"[INFO] Host behavior candidate rows: {len(behavior_events)}")
    print(f"[INFO] Usable host behavior rows: {len(feature_rows)}")

    if len(feature_rows) < MIN_TRAINING_ROWS:
        print(f"[ERROR] Need at least {MIN_TRAINING_ROWS} behavior rows to train safely.")
        return 1

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        max_samples="auto",
    )
    model.fit(feature_rows)

    training_scores = [float(value) for value in model.decision_function(feature_rows)]
    sorted_scores = sorted(training_scores)
    mean_score = sum(training_scores) / len(training_scores)
    variance = sum((score - mean_score) ** 2 for score in training_scores) / len(training_scores)

    score_meta = {
        "model": "iforest_host_behavior_v1",
        "source_profile": "host_behavior",
        "feature_count": len(feature_rows[0]) if feature_rows else 0,
        "training_rows": len(feature_rows),
        "min": float(sorted_scores[0]),
        "max": float(sorted_scores[-1]),
        "mean": float(mean_score),
        "std": float(math.sqrt(variance)),
        "q01": float(compute_quantile(sorted_scores, 0.01)),
        "q05": float(compute_quantile(sorted_scores, 0.05)),
        "q10": float(compute_quantile(sorted_scores, 0.10)),
        "q25": float(compute_quantile(sorted_scores, 0.25)),
        "q50": float(compute_quantile(sorted_scores, 0.50)),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    META_PATH.write_text(json.dumps(score_meta, indent=2), encoding="utf-8")

    print(f"[INFO] Saved model to: {MODEL_PATH}")
    print(f"[INFO] Saved metadata to: {META_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
