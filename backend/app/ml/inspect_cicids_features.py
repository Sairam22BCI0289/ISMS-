from __future__ import annotations

import json
import math
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
INPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "train_sample.jsonl"


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
    count = 0
    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)
            features = extract_features(event)
            raw = json.loads(event["raw"])
            print(f"[{count}] label={raw.get('label')} features={features}")
            count += 1
            if count >= 10:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
