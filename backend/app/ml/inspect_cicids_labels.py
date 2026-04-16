from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_DIR = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "MachineLearningCSV" / "MachineLearningCVE"


def extract_label(row: dict) -> str:
    candidates = ["Label", " Label", "label", "Label ", " Label "]

    for key in candidates:
        if key in row:
            return str(row.get(key, "")).strip()

    for key in row.keys():
        if "label" in str(key).strip().lower():
            return str(row.get(key, "")).strip()

    return "<MISSING>"


def main() -> int:
    if not DATASET_DIR.exists():
        print(f"[ERROR] Dataset folder not found: {DATASET_DIR}")
        return 1

    csv_files = sorted(DATASET_DIR.glob("*.csv"))
    if not csv_files:
        print(f"[ERROR] No CSV files found in: {DATASET_DIR}")
        return 1

    grand_total = Counter()

    for csv_file in csv_files:
        print(f"\n[INFO] Inspecting: {csv_file.name}")
        counts = Counter()

        with csv_file.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = extract_label(row)
                counts[label] += 1
                grand_total[label] += 1

        for label, count in counts.most_common():
            print(f"  {label!r}: {count}")

    print("\n[INFO] Grand totals:")
    for label, count in grand_total.most_common():
        print(f"  {label!r}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())