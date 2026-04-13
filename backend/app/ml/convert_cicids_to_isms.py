from __future__ import annotations

import csv
import json
import math
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_DIR = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "MachineLearningCSV" / "MachineLearningCVE"
OUTPUT_PATH = BASE_DIR / "data" / "public_datasets" / "cicids2017" / "cicids2017_isms_network.jsonl"


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        value = str(value).strip()
        if value == "" or value.lower() == "nan":
            return default
        result = float(value)
        if not math.isfinite(result):
            return default
        return result
    except Exception:
        return default


def safe_int(value: str, default: int = 0) -> int:
    try:
        if value is None:
            return default
        value = str(value).strip()
        if value == "" or value.lower() == "nan":
            return default
        return int(float(value))
    except Exception:
        return default


def map_label_to_event_type(label: str) -> str:
    label = (label or "").strip().lower()

    if label == "benign":
        return "net_conn_allowed"

    suspicious_keywords = [
        "portscan",
        "ddos",
        "dos",
        "infiltration",
        "bot",
        "bruteforce",
        "ftp-patator",
        "ssh-patator",
        "web attack",
        "sql injection",
        "xss",
    ]

    for keyword in suspicious_keywords:
        if keyword in label:
            return "net_conn_high_risk"

    return "net_conn_allowed"


def map_row_to_isms_event(row: dict) -> dict:
    dst_port = safe_int(row.get("Dst Port", 0))
    protocol = safe_int(row.get("Protocol", 0))
    flow_duration = safe_float(row.get("Flow Duration", 0.0))
    tot_fwd_pkts = safe_int(row.get("Tot Fwd Pkts", 0))
    tot_bwd_pkts = safe_int(row.get("Tot Bwd Pkts", 0))
    flow_bytes_s = safe_float(row.get("Flow Byts/s", 0.0))
    flow_pkts_s = safe_float(row.get("Flow Pkts/s", 0.0))
    label = str(row.get("Label", "BENIGN")).strip()

    event_type = map_label_to_event_type(label)

    return {
        "source": "network",
        "event_type": event_type,
        "actor": "cicids_flow",
        "ip": None,
        "resource": f"port_{dst_port}",
        "severity": None,
        "severity_reason": None,
        "rules_triggered": [],
        "raw": json.dumps(
            {
                "dataset": "CICIDS2017",
                "label": label,
                "dst_port": dst_port,
                "protocol": protocol,
                "flow_duration": flow_duration,
                "tot_fwd_pkts": tot_fwd_pkts,
                "tot_bwd_pkts": tot_bwd_pkts,
                "flow_bytes_s": flow_bytes_s,
                "flow_pkts_s": flow_pkts_s,
            }
        ),
    }


def main() -> int:
    if not DATASET_DIR.exists():
        print(f"[ERROR] Dataset folder not found: {DATASET_DIR}")
        return 1

    csv_files = sorted(DATASET_DIR.glob("*.csv"))
    if not csv_files:
        print(f"[ERROR] No CSV files found in: {DATASET_DIR}")
        return 1

    total_rows = 0
    written_rows = 0

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as out_f:
        for csv_file in csv_files:
            print(f"[INFO] Reading: {csv_file.name}")
            with csv_file.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total_rows += 1
                    try:
                        event = map_row_to_isms_event(row)
                        out_f.write(json.dumps(event) + "\n")
                        written_rows += 1
                    except Exception:
                        continue

    print(f"[INFO] Total rows read: {total_rows}")
    print(f"[INFO] Total ISMS events written: {written_rows}")
    print(f"[INFO] Output file: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())