from __future__ import annotations

import json
import random
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "cicids2017_isms_network.jsonl"

TRAIN_OUT = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "train_sample.jsonl"
VAL_OUT = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "val_sample.jsonl"


TRAIN_BENIGN = 30000
TRAIN_ATTACK = 20000

VAL_BENIGN = 5000
VAL_ATTACK = 5000


def is_benign(line: str) -> bool:
    try:
        event = json.loads(line)
        raw = json.loads(event["raw"])
        label = str(raw.get("label", "BENIGN")).strip().upper()
        return label == "BENIGN"
    except Exception:
        return False


def main() -> int:
    print("[INFO] Loading dataset...")

    benign = []
    attack = []

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            if is_benign(line):
                benign.append(line)
            else:
                attack.append(line)

    print(f"[INFO] Benign rows available: {len(benign)}")
    print(f"[INFO] Attack rows available: {len(attack)}")

    random.shuffle(benign)
    random.shuffle(attack)

    if len(benign) < TRAIN_BENIGN + VAL_BENIGN:
        print("[ERROR] Not enough benign rows.")
        return 1

    if len(attack) < TRAIN_ATTACK + VAL_ATTACK:
        print("[ERROR] Not enough attack rows.")
        return 1

    train_lines = benign[:TRAIN_BENIGN] + attack[:TRAIN_ATTACK]
    val_lines = benign[TRAIN_BENIGN:TRAIN_BENIGN + VAL_BENIGN] + attack[TRAIN_ATTACK:TRAIN_ATTACK + VAL_ATTACK]

    random.shuffle(train_lines)
    random.shuffle(val_lines)

    with TRAIN_OUT.open("w", encoding="utf-8") as f:
        f.writelines(train_lines)

    with VAL_OUT.open("w", encoding="utf-8") as f:
        f.writelines(val_lines)

    print(f"[INFO] Training samples: {len(train_lines)}")
    print(f"[INFO] Validation samples: {len(val_lines)}")
    print(f"[INFO] Train file: {TRAIN_OUT}")
    print(f"[INFO] Val file: {VAL_OUT}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())