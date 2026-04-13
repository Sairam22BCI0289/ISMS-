from __future__ import annotations

import json
import math
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.base import SessionLocal
from app.db.models import SecurityEvent
from app.ml.features import extract_network_features

MIN_TRAINING_ROWS = 20
MODEL_PATH = BACKEND_DIR / "models" / "network_isolation_forest.joblib"
MODEL_META_PATH = BACKEND_DIR / "models" / "network_isolation_forest_meta.json"


def is_valid_feature_vector(vector: list[float]) -> bool:
    if not vector:
        return False

    for value in vector:
        if not isinstance(value, (int, float)):
            return False
        if not math.isfinite(float(value)):
            return False

    return True


def row_to_event_dict(row: SecurityEvent) -> dict:
    return {
        "event_type": row.event_type,
        "actor": row.actor,
        "ip": row.ip,
        "resource": row.resource,
    }


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


def main() -> int:
    try:
        from sklearn.ensemble import IsolationForest
        import joblib
    except ImportError as exc:
        print(f"[ERROR] Missing training dependency: {exc}")
        return 1

    db = SessionLocal()
    try:
        rows = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.source == "network")
            .order_by(SecurityEvent.id.asc())
            .all()
        )

        total_network_events = len(rows)
        feature_rows: list[list[float]] = []

        for row in rows:
            try:
                event_dict = row_to_event_dict(row)
                vector = extract_network_features(event_dict)
                if is_valid_feature_vector(vector):
                    feature_rows.append([float(value) for value in vector])
            except Exception:
                continue
    finally:
        db.close()

    if len(feature_rows) < MIN_TRAINING_ROWS:
        print(f"[INFO] Read {total_network_events} network events from the database.")
        print(
            f"[INFO] Only {len(feature_rows)} valid feature rows were available. "
            f"Need at least {MIN_TRAINING_ROWS} to train the model safely."
        )
        return 0

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
    MODEL_META_PATH.write_text(json.dumps(score_meta, indent=2), encoding="utf-8")

    print(f"[INFO] Read {total_network_events} network events from the database.")
    print(f"[INFO] Used {len(feature_rows)} feature rows for training.")
    print(f"[INFO] Saved model to: {MODEL_PATH}")
    print(f"[INFO] Saved model metadata to: {MODEL_META_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
