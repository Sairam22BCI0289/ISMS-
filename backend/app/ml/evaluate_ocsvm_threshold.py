from __future__ import annotations

import json
import math
import numpy as np
from pathlib import Path
import joblib


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "val_sample.jsonl"
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
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    benign_total = 0
    benign_flagged = 0
    attack_total = 0
    attack_flagged = 0

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)
            raw = json.loads(event["raw"])
            label = str(raw.get("label", "BENIGN")).strip().upper()

            features = extract_features(event)
            features_scaled = scaler.transform(np.array([features], dtype=float))
            score = float(model.decision_function(features_scaled)[0])

            is_anomaly = score < 0

            if label == "BENIGN":
                benign_total += 1
                if is_anomaly:
                    benign_flagged += 1
            else:
                attack_total += 1
                if is_anomaly:
                    attack_flagged += 1

    benign_rate = (benign_flagged / benign_total * 100) if benign_total else 0.0
    attack_rate = (attack_flagged / attack_total * 100) if attack_total else 0.0

    print(f"[INFO] Benign total: {benign_total}")
    print(f"[INFO] Benign flagged anomalous: {benign_flagged} ({benign_rate:.2f}%)")
    print(f"[INFO] Attack total: {attack_total}")
    print(f"[INFO] Attack flagged anomalous: {attack_flagged} ({attack_rate:.2f}%)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
