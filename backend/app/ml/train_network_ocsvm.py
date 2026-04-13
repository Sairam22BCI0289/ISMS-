from __future__ import annotations

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
MODEL_PATH = BACKEND_DIR / "models" / "network_ocsvm.joblib"


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


def main() -> int:
    try:
        import joblib
        from sklearn.svm import OneClassSVM
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

    model = OneClassSVM(
        kernel="rbf",
        gamma="scale",
        nu=0.05,
    )
    model.fit(feature_rows)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print(f"[INFO] Read {total_network_events} network events from the database.")
    print(f"[INFO] Used {len(feature_rows)} feature rows for training.")
    print(f"[INFO] Saved model to: {MODEL_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
