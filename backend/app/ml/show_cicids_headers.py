from __future__ import annotations

import csv
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_DIR = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "MachineLearningCSV" / "MachineLearningCVE"


def main() -> int:
    csv_files = sorted(DATASET_DIR.glob("*.csv"))
    if not csv_files:
        print("[ERROR] No CSV files found")
        return 1

    first_file = csv_files[0]
    print(f"[INFO] Inspecting headers from: {first_file.name}")

    with first_file.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []

    for i, h in enumerate(headers):
        print(f"[{i}] {repr(h)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())