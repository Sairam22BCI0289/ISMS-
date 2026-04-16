from __future__ import annotations

import json
import math
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
INPUT_PATH = BACKEND_DIR / "data" / "public_datasets" / "host_public" / "val_host_public.jsonl"
MODEL_PATH = BACKEND_DIR / "models" / "host_isolation_forest.joblib"


def is_valid_feature_vector(vector: object) -> bool:
    if not isinstance(vector, list) or not vector:
        return False

    for value in vector:
        if not isinstance(value, (int, float)):
            return False
        if not math.isfinite(float(value)):
            return False

    return True


def main() -> int:
    try:
        import joblib
    except ImportError as exc:
        print(f"[ERROR] Missing evaluation dependency: {exc}")
        return 1

    model = joblib.load(MODEL_PATH)

    benign_total = 0
    benign_flagged = 0
    anomaly_total = 0
    anomaly_flagged = 0

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except Exception:
                continue

            features = row.get("features")
            label = row.get("label")
            if not is_valid_feature_vector(features):
                continue

            score = float(model.decision_function([[float(value) for value in features]])[0])
            is_anomaly = score < 0

            if label == "benign":
                benign_total += 1
                if is_anomaly:
                    benign_flagged += 1
            elif label == "anomaly":
                anomaly_total += 1
                if is_anomaly:
                    anomaly_flagged += 1

    benign_rate = (benign_flagged / benign_total * 100) if benign_total else 0.0
    anomaly_rate = (anomaly_flagged / anomaly_total * 100) if anomaly_total else 0.0

    print(f"[INFO] Benign total: {benign_total}")
    print(f"[INFO] Benign flagged anomalous: {benign_flagged} ({benign_rate:.2f}%)")
    print(f"[INFO] Anomaly total: {anomaly_total}")
    print(f"[INFO] Anomaly flagged anomalous: {anomaly_flagged} ({anomaly_rate:.2f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
