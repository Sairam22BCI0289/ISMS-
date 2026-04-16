from __future__ import annotations

import json
import math
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
INPUT_PATH = BACKEND_DIR / "data" / "public_datasets" / "host_public" / "train_host_public.jsonl"
MODEL_PATH = BACKEND_DIR / "models" / "host_isolation_forest.joblib"
META_PATH = BACKEND_DIR / "models" / "host_isolation_forest_meta.json"
MIN_TRAINING_ROWS = 20


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


def main() -> int:
    try:
        import joblib
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        print(f"[ERROR] Missing training dependency: {exc}")
        return 1

    benign_rows = 0
    feature_rows: list[list[float]] = []

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except Exception:
                continue

            if row.get("label") != "benign":
                continue

            features = row.get("features")
            if not is_valid_feature_vector(features):
                continue

            benign_rows += 1
            feature_rows.append([float(value) for value in features])

    print(f"[INFO] Usable benign training rows: {benign_rows}")

    if len(feature_rows) < MIN_TRAINING_ROWS:
        print(f"[ERROR] Need at least {MIN_TRAINING_ROWS} benign rows to train safely.")
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
