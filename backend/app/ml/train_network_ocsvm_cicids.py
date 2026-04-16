from __future__ import annotations

import json
import math
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
import joblib


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "train_sample.jsonl"

MODEL_PATH = BASE_DIR / "models" / "network_ocsvm_cicids.joblib"
SCALER_PATH = BASE_DIR / "models" / "network_ocsvm_cicids_scaler.joblib"


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

    print("[INFO] Training One-Class SVM on BENIGN-only data...")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = OneClassSVM(
        kernel="rbf",
        gamma="scale",
        nu=0.05,
    )

    model.fit(X_scaled)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print(f"[INFO] Model saved to: {MODEL_PATH}")
    print(f"[INFO] Scaler saved to: {SCALER_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
