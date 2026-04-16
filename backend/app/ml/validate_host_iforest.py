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


def mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def format_stat(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.4f}"


def main() -> int:
    try:
        import joblib
    except ImportError as exc:
        print(f"[ERROR] Missing validation dependency: {exc}")
        return 1

    model = joblib.load(MODEL_PATH)

    benign_scores: list[float] = []
    anomaly_scores: list[float] = []

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
            if label == "benign":
                benign_scores.append(score)
            elif label == "anomaly":
                anomaly_scores.append(score)

    print(f"[INFO] Benign count: {len(benign_scores)}")
    print(f"[INFO] Anomaly count: {len(anomaly_scores)}")
    print(f"[INFO] Benign mean: {format_stat(mean_or_none(benign_scores))}")
    print(f"[INFO] Anomaly mean: {format_stat(mean_or_none(anomaly_scores))}")
    print(f"[INFO] Benign min/max: {format_stat(min(benign_scores) if benign_scores else None)} / {format_stat(max(benign_scores) if benign_scores else None)}")
    print(f"[INFO] Anomaly min/max: {format_stat(min(anomaly_scores) if anomaly_scores else None)} / {format_stat(max(anomaly_scores) if anomaly_scores else None)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
