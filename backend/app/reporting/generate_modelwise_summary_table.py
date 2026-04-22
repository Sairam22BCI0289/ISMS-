from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Callable

from app.config import BACKEND_DIR
from app.reporting.report_queries import (
    event_risk,
    fetch_security_events,
    is_rule_positive,
    sqlite_path_from_database_url,
)


OUTPUT_DIR = BACKEND_DIR / "report_figures"
CSV_PATH = OUTPUT_DIR / "modelwise_summary_table.csv"
MD_PATH = OUTPUT_DIR / "modelwise_summary_table.md"

MODEL_COLUMNS = [
    ("IF Host Auth", "iforest_host_auth_v1"),
    ("IF Host Behavior", "iforest_host_behavior_v1"),
    ("IF Network", "iforest_network_v1"),
    ("IF+OCSVM Network", "iforest+ocsvm_network_v1"),
    ("AE Cloud", "autoencoder_cloud_v1"),
    ("AE+NS Cloud", "autoencoder_cloud_v1+noise_suppression"),
]

HEADERS = [
    "Aspect",
    "N",
    "Rule-Based",
    "Rule-Based %",
    "IF Host Auth",
    "IF Host Auth %",
    "IF Host Behavior",
    "IF Host Behavior %",
    "IF Network",
    "IF Network %",
    "IF+OCSVM Network",
    "IF+OCSVM Network %",
    "AE Cloud",
    "AE Cloud %",
    "AE+NS Cloud",
    "AE+NS Cloud %",
    "Avg Risk",
    "High-Risk %",
]

NETWORK_CONNECTION_EVENT_TYPES = {
    "net_conn_allowed",
    "net_conn_blocked",
    "net_conn_high_risk",
}


def text_value(value: Any) -> str:
    return str(value or "").strip()


def row_groups() -> list[tuple[str, Callable[[dict[str, Any]], bool]]]:
    return [
        (
            "Host Authentication",
            lambda event: text_value(event.get("source")) == "host"
            and text_value(event.get("anomaly_source_profile")) == "host_auth",
        ),
        (
            "Host Behavior",
            lambda event: text_value(event.get("source")) == "host"
            and text_value(event.get("anomaly_source_profile")) == "host_behavior",
        ),
        (
            "Network Connections",
            lambda event: text_value(event.get("source")) == "network"
            and text_value(event.get("event_type")) in NETWORK_CONNECTION_EVENT_TYPES,
        ),
        (
            "Network Listeners",
            lambda event: text_value(event.get("source")) == "network"
            and text_value(event.get("event_type")) == "net_listener_open",
        ),
        (
            "Cloud Audit",
            lambda event: text_value(event.get("source")) == "cloud",
        ),
        (
            "Overall",
            lambda event: text_value(event.get("source")) in {"host", "network", "cloud"},
        ),
    ]


def summarize_group(aspect: str, events: list[dict[str, Any]]) -> dict[str, str | int]:
    total = len(events)
    risks = [event_risk(event) for event in events]
    avg_risk = sum(risks) / total if total else 0.0
    high_risk_pct = (sum(1 for risk in risks if risk >= 7.0) / total * 100.0) if total else 0.0
    rule_based_count = sum(1 for event in events if is_rule_positive(event))
    rule_based_pct = (rule_based_count / total * 100.0) if total else 0.0

    row: dict[str, str | int] = {
        "Aspect": aspect,
        "N": total,
        "Rule-Based": rule_based_count,
        "Rule-Based %": f"{rule_based_pct:.2f}",
        "Avg Risk": f"{avg_risk:.3f}",
        "High-Risk %": f"{high_risk_pct:.2f}",
    }
    for label, model_name in MODEL_COLUMNS:
        count = sum(1 for event in events if text_value(event.get("anomaly_model")) == model_name)
        percentage = (count / total * 100.0) if total else 0.0
        row[label] = count
        row[f"{label} %"] = f"{percentage:.2f}"
    return row


def build_rows(events: list[dict[str, Any]]) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    for aspect, predicate in row_groups():
        group_events = [event for event in events if predicate(event)]
        rows.append(summarize_group(aspect, group_events))
    return rows


def write_csv(rows: list[dict[str, str | int]]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(rows: list[dict[str, str | int]]) -> str:
    lines = [
        "| " + " | ".join(HEADERS) + " |",
        "| " + " | ".join(["---"] * len(HEADERS)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(header, "")) for header in HEADERS) + " |")
    return "\n".join(lines) + "\n"


def write_markdown(rows: list[dict[str, str | int]]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MD_PATH.write_text(markdown_table(rows), encoding="utf-8")


def main() -> int:
    db_path = sqlite_path_from_database_url()
    events = fetch_security_events()
    rows = build_rows(events)
    write_csv(rows)
    write_markdown(rows)

    print("ISMS model-wise summary table generated")
    print(f"SQLite database: {db_path}")
    print(f"Events loaded: {len(events)}")
    print(f"Rows written: {len(rows)}")
    print(f"CSV: {CSV_PATH}")
    print(f"Markdown: {MD_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
