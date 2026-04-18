from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.ml.anomaly_service import score_event

EVAL_PATH = BACKEND_DIR / "data" / "public_datasets" / "cloud_public" / "cloud_eval_labeled.jsonl"


def parse_raw(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def cloudtrail_event_from_raw(raw: dict) -> dict:
    cloudtrail = raw.get("CloudTrailEvent")
    if isinstance(cloudtrail, dict):
        return cloudtrail
    if isinstance(cloudtrail, str):
        try:
            parsed = json.loads(cloudtrail)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def cloudtrail_value(raw: dict, cloudtrail: dict, raw_key: str, cloudtrail_key: str) -> str:
    value = raw.get(raw_key)
    if value in (None, ""):
        value = cloudtrail.get(cloudtrail_key)
    return str(value or "").strip()


def safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def read_labeled_rows(path: Path) -> tuple[list[tuple[int, str, dict]], int]:
    rows: list[tuple[int, str, dict]] = []
    skipped = 0

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
            except Exception:
                skipped += 1
                continue

            if not isinstance(item, dict):
                skipped += 1
                continue

            label = str(item.get("label") or "").strip().lower()
            event = item.get("event")
            if label not in {"benign", "suspicious"} or not isinstance(event, dict):
                skipped += 1
                continue

            if str(event.get("source") or "").strip().lower() != "cloud":
                skipped += 1
                continue

            rows.append((line_number, label, event))

    return rows, skipped


def misclassification_summary(
    line_number: int,
    true_label: str,
    predicted_label: str,
    event: dict,
    result: dict,
) -> dict:
    raw = parse_raw(event.get("raw"))
    cloudtrail = cloudtrail_event_from_raw(raw)
    return {
        "line": line_number,
        "true": true_label,
        "predicted": predicted_label,
        "event_type": event.get("event_type"),
        "actor": event.get("actor"),
        "eventName": cloudtrail_value(raw, cloudtrail, "EventName", "eventName"),
        "eventSource": cloudtrail_value(raw, cloudtrail, "EventSource", "eventSource"),
        "anomaly_score": result.get("anomaly_score"),
        "anomaly_risk_10": result.get("anomaly_risk_10"),
        "anomaly_model": result.get("anomaly_model"),
    }


def evaluate(rows: list[tuple[int, str, dict]]) -> dict:
    tp = fp = tn = fn = 0
    benign_rows = 0
    suspicious_rows = 0
    misclassifications: list[dict] = []

    for line_number, true_label, event in rows:
        if true_label == "benign":
            benign_rows += 1
        else:
            suspicious_rows += 1

        try:
            result = score_event(event)
        except Exception:
            result = {}

        predicted_label = "suspicious" if result.get("anomaly_label") == "anomalous" else "benign"

        if true_label == "suspicious" and predicted_label == "suspicious":
            tp += 1
        elif true_label == "benign" and predicted_label == "suspicious":
            fp += 1
        elif true_label == "benign" and predicted_label == "benign":
            tn += 1
        elif true_label == "suspicious" and predicted_label == "benign":
            fn += 1

        if true_label != predicted_label and len(misclassifications) < 10:
            misclassifications.append(
                misclassification_summary(line_number, true_label, predicted_label, event, result)
            )

    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = safe_ratio(2 * precision * recall, precision + recall)
    accuracy = safe_ratio(tp + tn, tp + fp + tn + fn)
    fpr = safe_ratio(fp, fp + tn)
    fnr = safe_ratio(fn, fn + tp)

    return {
        "total": len(rows),
        "benign": benign_rows,
        "suspicious": suspicious_rows,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
        "fnr": fnr,
        "misclassifications": misclassifications,
    }


def print_summary(metrics: dict, skipped_rows: int) -> None:
    print("[INFO] Cloud live model evaluation complete")
    print(f"Input path: {EVAL_PATH}")
    print(f"Total evaluated rows: {metrics['total']}")
    print(f"Skipped malformed/non-cloud rows: {skipped_rows}")
    print(f"Benign rows: {metrics['benign']}")
    print(f"Suspicious rows: {metrics['suspicious']}")
    print(f"TP: {metrics['tp']}  FP: {metrics['fp']}  TN: {metrics['tn']}  FN: {metrics['fn']}")
    print(
        "Precision: {precision:.4f}  Recall: {recall:.4f}  F1: {f1:.4f}  "
        "Accuracy: {accuracy:.4f}  FPR: {fpr:.4f}  FNR: {fnr:.4f}".format(**metrics)
    )

    if metrics["misclassifications"]:
        print("Sample misclassifications:")
        for item in metrics["misclassifications"]:
            print(
                "  line={line} true={true} predicted={predicted} "
                "event_type={event_type} actor={actor} eventName={eventName} "
                "eventSource={eventSource} anomaly_score={anomaly_score} "
                "anomaly_risk_10={anomaly_risk_10} anomaly_model={anomaly_model}".format(**item)
            )
    else:
        print("Sample misclassifications: none")


def main() -> int:
    if not EVAL_PATH.exists():
        print(f"[ERROR] Labeled evaluation file not found: {EVAL_PATH}")
        print("Expected JSONL format:")
        print('{"label":"benign","event":{"source":"cloud","event_type":"...","timestamp":"...","actor":"...","ip":"...","resource":"...","raw":{},"rules_triggered":[]}}')
        print('{"label":"suspicious","event":{"source":"cloud","event_type":"...","timestamp":"...","actor":"...","ip":"...","resource":"...","raw":{},"rules_triggered":[]}}')
        return 1

    rows, skipped_rows = read_labeled_rows(EVAL_PATH)
    if not rows:
        print(f"[ERROR] No valid cloud evaluation rows found in: {EVAL_PATH}")
        print(f"Skipped rows: {skipped_rows}")
        return 1

    metrics = evaluate(rows)
    print_summary(metrics, skipped_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
