from __future__ import annotations

import json
import math
import numpy as np
from pathlib import Path
import joblib


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "val_sample.jsonl"

MODEL_PATH = BASE_DIR / "models" / "network_iforest_cicids.joblib"
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
    print("[INFO] Loading model...")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    print("[INFO] Loading validation data...")

    normal_scores = []
    attack_scores = []

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)
            raw = json.loads(event["raw"])
            label = raw.get("label", "BENIGN")

            features = extract_features(event)
            features_scaled = scaler.transform(np.array([features], dtype=float))
            score = model.decision_function(features_scaled)[0]

            if str(label).upper() == "BENIGN":
                normal_scores.append(score)
            else:
                attack_scores.append(score)

    print(f"[INFO] Normal samples: {len(normal_scores)}")
    print(f"[INFO] Attack samples: {len(attack_scores)}")

    print("\n--- SCORE STATS ---")
    print(f"Normal mean: {np.mean(normal_scores):.4f}")
    print(f"Attack mean: {np.mean(attack_scores):.4f}")

    print(f"Normal min/max: {min(normal_scores):.4f} / {max(normal_scores):.4f}")
    print(f"Attack min/max: {min(attack_scores):.4f} / {max(attack_scores):.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
