from __future__ import annotations

import json
import math
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "train_sample.jsonl"

MODEL_PATH = BASE_DIR / "models" / "network_iforest_cicids.joblib"
META_PATH = BASE_DIR / "models" / "network_iforest_cicids_meta.json"
SCALER_PATH = BASE_DIR / "models" / "network_iforest_scaler.joblib"


def extract_features(event: dict) -> list[float]:
    raw = json.loads(event["raw"])

    return [
        float(raw.get("dst_port", 0)),
        float(raw.get("protocol", 0)),
        math.log1p(float(raw.get("flow_duration", 0))),
        math.log1p(float(raw.get("tot_fwd_pkts", 0))),
        math.log1p(float(raw.get("tot_bwd_pkts", 0))),
        math.log1p(float(raw.get("flow_bytes_s", 0))),
        math.log1p(float(raw.get("flow_pkts_s", 0))),
    ]


def main() -> int:
    print("[INFO] Loading BENIGN-only training data...")

    X = []
    benign_count = 0
    skipped_attack_count = 0

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
                raw = json.loads(event["raw"])
                label = str(raw.get("label", "BENIGN")).strip().upper()

                # Train ONLY on normal data
                if label != "BENIGN":
                    skipped_attack_count += 1
                    continue

                features = extract_features(event)
                X.append(features)
                benign_count += 1
            except Exception:
                continue

    X = np.array(X, dtype=float)

    print(f"[INFO] BENIGN feature rows used: {benign_count}")
    print(f"[INFO] Attack rows skipped: {skipped_attack_count}")

    if len(X) < 100:
        print("[ERROR] Not enough BENIGN data to train")
        return 1

    print("[INFO] Training Isolation Forest on BENIGN-only data...")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )

    model.fit(X_scaled)

    scores = model.decision_function(X_scaled)

    meta = {
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
        "mean": float(np.mean(scores)),
        "std": float(np.std(scores)),
        "q01": float(np.quantile(scores, 0.01)),
        "q05": float(np.quantile(scores, 0.05)),
        "q10": float(np.quantile(scores, 0.10)),
        "q25": float(np.quantile(scores, 0.25)),
        "q50": float(np.quantile(scores, 0.50)),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    with META_PATH.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"[INFO] Model saved to: {MODEL_PATH}")
    print(f"[INFO] Scaler saved to: {SCALER_PATH}")
    print(f"[INFO] Meta saved to: {META_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
