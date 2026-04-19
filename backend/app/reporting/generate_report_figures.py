from __future__ import annotations

import json
import math
import os
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from app.config import BACKEND_DIR

FIGURE_ROOT = BACKEND_DIR / "report_figures"
os.environ.setdefault("MPLCONFIGDIR", str(FIGURE_ROOT / ".matplotlib_cache"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

plt.rcParams.update(
    {
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": "#30343b",
        "axes.labelcolor": "#1f2933",
        "axes.titleweight": "bold",
        "font.size": 9,
        "axes.titlesize": 12,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "legend.title_fontsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
    }
)

from app.reporting.report_queries import (
    count_by_field,
    entity_keys,
    event_risk,
    fetch_schema_summary,
    fetch_security_events,
    is_ml_positive,
    is_rule_positive,
    numeric_value,
    parse_rules,
    parse_timestamp,
    sqlite_path_from_database_url,
)

CORE_DIR = FIGURE_ROOT / "core"
IMPLEMENTATION_DIR = FIGURE_ROOT / "implementation"
TESTING_DIR = FIGURE_ROOT / "testing"
RESULTS_DIR = FIGURE_ROOT / "results"
MANIFEST_PATH = FIGURE_ROOT / "figure_manifest.txt"
SOURCES = ["host", "network", "cloud"]
SOURCE_COLORS = {"host": "#56ccf2", "network": "#f2994a", "cloud": "#9b51e0"}

STALE_OUTPUTS = [
    "core/top_event_types.png",
    "core/severity_distribution.png",
    "core/event_volume_over_time.png",
    "implementation/anomaly_model_usage.png",
    "testing/latency_runtime_chart.png",
    "testing/confusion_matrix_cloud_or_network.png",
    "testing/roc_or_pr_curve_cloud_or_network.png",
    "results/rule_vs_ml_overlap.png",
    "results/multilayer_risk_distribution.png",
    "results/correlated_incident_timeline.png",
]


@dataclass
class ManifestEntry:
    filename: str
    section: str
    coverage: str
    data_source: str
    coverage_reason: str
    status: str
    explanation: str
    skipped_reason: str = ""


def ensure_output_dirs() -> None:
    for path in (CORE_DIR, IMPLEMENTATION_DIR, TESTING_DIR, RESULTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def remove_stale_outputs() -> None:
    for relative_path in STALE_OUTPUTS:
        path = FIGURE_ROOT / relative_path
        if path.exists():
            path.unlink()


def save_figure(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()


def skip(
    filename: str,
    section: str,
    coverage: str,
    data_source: str,
    coverage_reason: str,
    reason: str,
) -> ManifestEntry:
    return ManifestEntry(filename, section, coverage, data_source, coverage_reason, "skipped", "Figure not generated.", reason)


def generated(
    filename: str,
    section: str,
    coverage: str,
    data_source: str,
    coverage_reason: str,
    explanation: str,
) -> ManifestEntry:
    return ManifestEntry(filename, section, coverage, data_source, coverage_reason, "generated", explanation)


def source_of(event: dict[str, Any]) -> str:
    source = str(event.get("source") or "unknown").strip().lower()
    return source if source else "unknown"


def title_label(value: Any) -> str:
    text = str(value or "not recorded").strip()
    return text if len(text) <= 34 else text[:31] + "..."


def wrapped_label(value: Any, width: int = 24, max_lines: int = 2) -> str:
    text = str(value or "not recorded").strip()
    lines = textwrap.wrap(text, width=width) or ["not recorded"]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1].rstrip(".") + "..."
    return "\n".join(lines)


def legend_outside(ax, title: str | None = None) -> None:
    ax.legend(title=title, loc="upper left", bbox_to_anchor=(1.02, 1.0), borderaxespad=0)


def apply_log_scale_if_imbalanced(ax, values: list[int | float], axis: str, label_suffix: str = " (log scale)") -> bool:
    positive = [value for value in values if value > 0]
    if len(positive) < 2:
        return False
    if max(positive) / max(1e-9, min(positive)) < 50:
        return False
    if axis == "x":
        ax.set_xscale("log")
        ax.set_xlabel((ax.get_xlabel() or "Count") + label_suffix)
    else:
        ax.set_yscale("log")
        ax.set_ylabel((ax.get_ylabel() or "Count") + label_suffix)
    ax.grid(True, which="both", axis=axis, alpha=0.18)
    return True


def grouped_counts(events: list[dict[str, Any]], field: str, labels: list[str]) -> dict[str, Counter]:
    counters: dict[str, Counter] = {source: Counter() for source in SOURCES}
    for event in events:
        source = source_of(event)
        if source not in counters:
            continue
        value = event.get(field)
        label = str(value).strip() if value not in (None, "") else "not recorded"
        if label in labels:
            counters[source][label] += 1
    return counters


def source_counts(events: list[dict[str, Any]]) -> Counter:
    counter: Counter = Counter({source: 0 for source in SOURCES})
    for event in events:
        source = source_of(event)
        if source in SOURCES:
            counter[source] += 1
    return counter


def scored_event(event: dict[str, Any]) -> bool:
    fields = (
        "anomaly_model",
        "anomaly_source_profile",
        "anomaly_label",
        "anomaly_label_svm",
        "anomaly_score",
        "anomaly_score_svm",
        "anomaly_risk_10",
        "anomaly_risk_10_svm",
        "host_auth_risk",
        "host_behavior_risk",
        "host_multilayer_risk",
        "network_multilayer_risk",
    )
    return any(event.get(field) not in (None, "") for field in fields)


def source_risk_values(events: list[dict[str, Any]]) -> dict[str, list[float]]:
    values: dict[str, list[float]] = {source: [] for source in SOURCES}
    for event in events:
        source = source_of(event)
        if source not in values:
            continue
        risk = event_risk(event)
        if risk > 0 or is_ml_positive(event) or scored_event(event):
            values[source].append(risk)
    return values


def add_value_labels(ax, values: list[int | float], fmt: str = "{:.0f}") -> None:
    for idx, value in enumerate(values):
        if ax.get_yscale() == "log" and value <= 0:
            continue
        ax.text(idx, value, fmt.format(value), ha="center", va="bottom", fontsize=8)


def top_labels_by_total(events: list[dict[str, Any]], field: str, limit: int = 10) -> list[str]:
    counter = count_by_field(events, field)
    return [label for label, _ in counter.most_common(limit)]


def stacked_bar_by_source(
    labels: list[str],
    counters_by_source: dict[str, Counter],
    title: str,
    xlabel: str,
    ylabel: str,
    path: Path,
    horizontal: bool = False,
) -> None:
    plt.figure(figsize=(11, max(5, len(labels) * 0.45) if horizontal else 6))
    ax = plt.gca()
    bottoms = [0] * len(labels)
    positions = list(range(len(labels)))
    for source in SOURCES:
        values = [counters_by_source[source].get(label, 0) for label in labels]
        if horizontal:
            ax.barh(positions, values, left=bottoms, label=source, color=SOURCE_COLORS[source])
        else:
            ax.bar(positions, values, bottom=bottoms, label=source, color=SOURCE_COLORS[source])
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
    if horizontal:
        ax.set_yticks(positions, [title_label(label) for label in labels])
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
    else:
        ax.set_xticks(positions, [title_label(label) for label in labels], rotation=25, ha="right")
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
    ax.set_title(title)
    legend_outside(ax, "Source")
    save_figure(path)


def grouped_horizontal_by_source(
    labels: list[str],
    counters_by_source: dict[str, Counter],
    title: str,
    xlabel: str,
    ylabel: str,
    path: Path,
) -> None:
    positions = list(range(len(labels)))
    height = 0.23
    all_values: list[int] = []
    plt.figure(figsize=(12, max(5, len(labels) * 0.55)))
    ax = plt.gca()
    for idx, source in enumerate(SOURCES):
        offsets = [position + (idx - 1) * height for position in positions]
        values = [counters_by_source[source].get(label, 0) for label in labels]
        all_values.extend(values)
        ax.barh(offsets, values, height=height, label=source, color=SOURCE_COLORS[source])
    ax.set_yticks(positions, [wrapped_label(label, width=28) for label in labels])
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    apply_log_scale_if_imbalanced(ax, all_values, "x")
    legend_outside(ax, "Source")
    save_figure(path)


def grouped_vertical_by_source(
    labels: list[str],
    counters_by_source: dict[str, Counter],
    title: str,
    xlabel: str,
    ylabel: str,
    path: Path,
    log_if_imbalanced: bool = True,
) -> None:
    positions = list(range(len(labels)))
    width = 0.24
    all_values: list[int] = []
    plt.figure(figsize=(10, 5.5))
    ax = plt.gca()
    for idx, source in enumerate(SOURCES):
        offsets = [position + (idx - 1) * width for position in positions]
        values = [counters_by_source[source].get(label, 0) for label in labels]
        all_values.extend(values)
        ax.bar(offsets, values, width=width, label=source, color=SOURCE_COLORS[source])
    ax.set_xticks(positions, [wrapped_label(label, width=16) for label in labels])
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if log_if_imbalanced:
        apply_log_scale_if_imbalanced(ax, all_values, "y")
    legend_outside(ax, "Source")
    save_figure(path)


def heatmap_by_source(
    labels: list[str],
    values_by_label: list[list[int]],
    title: str,
    path: Path,
    colorbar_label: str = "Event count",
) -> None:
    plt.figure(figsize=(8.5, max(4.5, len(labels) * 0.48)))
    ax = plt.gca()
    im = ax.imshow(values_by_label, cmap="YlGnBu", aspect="auto")
    ax.set_title(title)
    ax.set_xticks(range(len(SOURCES)), SOURCES)
    ax.set_yticks(range(len(labels)), [wrapped_label(label, width=30) for label in labels])
    max_value = max([max(row) for row in values_by_label] or [0])
    for row_idx, row in enumerate(values_by_label):
        for col_idx, value in enumerate(row):
            color = "white" if max_value and value > max_value * 0.6 else "#111111"
            ax.text(col_idx, row_idx, str(value), ha="center", va="center", fontsize=8, color=color)
    plt.colorbar(im, ax=ax, fraction=0.04, pad=0.03, label=colorbar_label)
    save_figure(path)


def bucket_events_by_time_by_source(events: list[dict[str, Any]], max_buckets: int = 12) -> tuple[list[datetime], dict[str, list[int]], str]:
    timestamped = [
        (parse_timestamp(event.get("timestamp")), source_of(event))
        for event in events
        if source_of(event) in SOURCES
    ]
    timestamped = [(time_value, source) for time_value, source in timestamped if time_value is not None]
    timestamped.sort(key=lambda item: item[0])
    if not timestamped:
        return [], {}, ""

    start, end = timestamped[0][0], timestamped[-1][0]
    span_seconds = max(1.0, (end - start).total_seconds())
    bucket_seconds = max(60.0, span_seconds / max_buckets)
    bucket_count = max(1, int(math.ceil(span_seconds / bucket_seconds)) + 1)
    buckets = [start + timedelta(seconds=idx * bucket_seconds) for idx in range(bucket_count)]
    values = {source: [0] * bucket_count for source in SOURCES}

    for time_value, source in timestamped:
        index = min(bucket_count - 1, int((time_value - start).total_seconds() // bucket_seconds))
        values[source][index] += 1

    if bucket_seconds < 3600:
        label = f"{int(round(bucket_seconds / 60))}-minute bucket"
    elif bucket_seconds < 86400:
        label = f"{int(round(bucket_seconds / 3600))}-hour bucket"
    else:
        label = f"{int(round(bucket_seconds / 86400))}-day bucket"
    return buckets, values, label


def figure_event_source_distribution(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "core/event_source_distribution.png"
    if not events:
        return skip(filename, "core", "host/network/cloud", "security_events.source", "Uses source counts for all implemented telemetry streams.", "No events found in security_events.")

    counter = source_counts(events)
    values = [counter[source] for source in SOURCES]
    plt.figure(figsize=(8, 5))
    ax = plt.gca()
    ax.bar(SOURCES, values, color=[SOURCE_COLORS[source] for source in SOURCES])
    ax.set_title("Event Source Distribution Across ISMS Telemetry")
    ax.set_xlabel("Source")
    ax.set_ylabel("Event count")
    ax.margins(y=0.14)
    apply_log_scale_if_imbalanced(ax, values, "y")
    add_value_labels(ax, values)
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "core", "host/network/cloud", "security_events.source", "Directly compares event volume for host, network, and cloud.", "Counts stored events by project source.")


def figure_top_event_types_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "core/top_event_types_by_source.png"
    if not events:
        return skip(filename, "core", "host/network/cloud", "security_events.event_type grouped by source", "Stacked bars include all three sources.", "No events found in security_events.")

    labels = top_labels_by_total(events, "event_type", 12)
    counters = grouped_counts(events, "event_type", labels)
    grouped_horizontal_by_source(
        labels[::-1],
        counters,
        "Top Event Types by Source",
        "Event count",
        "Event type",
        FIGURE_ROOT / filename,
    )
    return generated(filename, "core", "host/network/cloud", "security_events.event_type and source", "Shows high-volume event types with host/network/cloud contribution visible.", "Displays the most frequent normalized event types as stacked source counts.")


def figure_severity_distribution_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "core/severity_distribution_by_source.png"
    if not events:
        return skip(filename, "core", "host/network/cloud", "security_events.severity grouped by source", "Grouped severity counts include all sources.", "No events found in security_events.")

    order = ["low", "medium", "high", "not recorded"]
    counter = count_by_field(events, "severity")
    labels = [label for label in order if counter.get(label, 0)] + [label for label in counter if label not in order]
    counters = grouped_counts(events, "severity", labels)
    grouped_vertical_by_source(
        labels,
        counters,
        "Rule-Based Severity Distribution by Source",
        "Severity",
        "Event count",
        FIGURE_ROOT / filename,
    )
    return generated(filename, "core", "host/network/cloud", "security_events.severity and source", "Shows severity distribution with each source represented in the stack.", "Compares stored severity outcomes across sources.")


def figure_event_volume_over_time_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "core/event_volume_over_time_by_source.png"
    buckets, values, bucket_label = bucket_events_by_time_by_source(events)
    if not buckets:
        return skip(filename, "core", "host/network/cloud", "security_events.timestamp and source", "Multi-line plot would include all available sources.", "No valid timestamps found in security_events.")

    plt.figure(figsize=(11, 5.5))
    ax = plt.gca()
    for source in SOURCES:
        ax.plot(buckets, values[source], marker="o", linewidth=2, label=source, color=SOURCE_COLORS[source])
    ax.set_title("Event Volume Over Time by Source")
    ax.set_xlabel(bucket_label)
    ax.set_ylabel("Event count")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d\n%H:%M"))
    legend_outside(ax, "Source")
    ax.grid(True, alpha=0.22)
    plt.xticks(rotation=0, ha="center")
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "core", "host/network/cloud", "security_events.timestamp and source", "Plots host, network, and cloud activity on the same time axis.", "Shows temporal event volume with automatic bucketing.")


def figure_database_schema_summary() -> ManifestEntry:
    filename = "implementation/database_schema_summary.png"
    schema = fetch_schema_summary()
    if not schema:
        return skip(filename, "implementation", "system-wide host/network/cloud", "PRAGMA table_info(security_events)", "All sources share the security_events persistence schema.", "security_events schema could not be inspected.")

    schema_by_name = {str(item.get("name") or ""): item for item in schema}
    key_columns = [
        "id",
        "timestamp",
        "source",
        "event_type",
        "actor",
        "ip",
        "resource",
        "severity",
        "rules_triggered",
        "anomaly_label",
        "anomaly_model",
        "anomaly_source_profile",
        "host_multilayer_risk",
        "network_multilayer_risk",
        "raw",
    ]
    rows = []
    for name in key_columns:
        item = schema_by_name.get(name)
        if item:
            rows.append([name, item.get("type", ""), "PK" if item.get("pk") else ""])

    plt.figure(figsize=(10.5, 6.2))
    ax = plt.gca()
    ax.axis("off")
    ax.text(0.02, 0.96, "Shared Event Storage Schema", fontsize=15, fontweight="bold", transform=ax.transAxes)
    ax.text(
        0.02,
        0.89,
        f"security_events table | {len(schema)} columns | unified host, network, and cloud event persistence",
        fontsize=10,
        color="#444444",
        transform=ax.transAxes,
    )
    summary_rows = [
        ["Identity fields", "id, timestamp, source, event_type"],
        ["Entity fields", "actor, ip, resource"],
        ["Rule fields", "severity, severity_reason, rules_triggered"],
        ["ML fields", "anomaly labels, model/profile, risk scores"],
        ["Context field", "raw JSON payload"],
    ]
    summary_table = ax.table(
        cellText=summary_rows,
        colLabels=["Schema area", "Report-relevant fields"],
        bbox=[0.02, 0.57, 0.96, 0.25],
        cellLoc="left",
        colLoc="left",
    )
    summary_table.auto_set_font_size(False)
    summary_table.set_fontsize(8.5)
    detail_table = ax.table(
        cellText=rows,
        colLabels=["Key column", "SQLite type", "Key"],
        bbox=[0.02, 0.05, 0.96, 0.46],
        cellLoc="left",
        colLoc="left",
    )
    detail_table.auto_set_font_size(False)
    detail_table.set_fontsize(8)
    for table in (summary_table, detail_table):
        for (row_idx, _), cell in table.get_celld().items():
            if row_idx == 0:
                cell.set_text_props(fontweight="bold")
                cell.set_facecolor("#e8eef7")
            else:
                cell.set_facecolor("#f8fafc")
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "implementation", "system-wide host/network/cloud", "SQLite PRAGMA table_info(security_events)", "Documents the shared storage layer used by host, network, and cloud events.", "Summarizes the real persisted event schema.")


def figure_source_profile_usage(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "implementation/source_profile_usage.png"
    if not events:
        return skip(filename, "implementation", "host/network/cloud", "security_events.anomaly_source_profile grouped by source", "Source profile usage is grouped across all sources.", "No events found in security_events.")

    labels = top_labels_by_total(events, "anomaly_source_profile", 12)
    counters = grouped_counts(events, "anomaly_source_profile", labels)
    matrix = [[counters[source].get(label, 0) for source in SOURCES] for label in labels]
    heatmap_by_source(
        labels,
        matrix,
        "Source Profile Usage by Telemetry Source",
        FIGURE_ROOT / filename,
    )
    return generated(filename, "implementation", "host/network/cloud", "security_events.anomaly_source_profile and source", "Uses a source-profile heatmap so smaller source profiles remain visible.", "Counts source profile usage while preserving source ownership.")


def figure_model_coverage_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "implementation/model_coverage_by_source.png"
    if not events:
        return skip(filename, "implementation", "host/network/cloud", "security_events.anomaly_model grouped by source", "Model coverage matrix includes all sources.", "No events found in security_events.")

    models = [
        label
        for label, _ in count_by_field(events, "anomaly_model").most_common(12)
        if label != "not recorded"
    ]
    if not models:
        return skip(filename, "implementation", "host/network/cloud", "security_events.anomaly_model grouped by source", "Would show source-to-model coverage if model fields existed.", "No stored anomaly_model values were found.")

    matrix = []
    for model in models:
        row = []
        for source in SOURCES:
            row.append(sum(1 for event in events if source_of(event) == source and str(event.get("anomaly_model") or "").strip() == model))
        matrix.append(row)

    heatmap_by_source(
        models,
        matrix,
        "Anomaly Model Coverage by Source",
        FIGURE_ROOT / filename,
    )
    return generated(filename, "implementation", "host/network/cloud", "security_events.anomaly_model and source", "Shows which implemented anomaly model paths are active for each source.", "Visualizes model coverage for host, network, and cloud.")


def figure_testing_coverage_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "testing/testing_coverage_by_source.png"
    if not events:
        return skip(filename, "testing", "host/network/cloud", "security_events source/scoring/anomaly fields", "Coverage summary is grouped by all sources.", "No events found in security_events.")

    metrics = ["total events", "scored events", "ML positive"]
    values_by_metric = {metric: [] for metric in metrics}
    for source in SOURCES:
        source_events = [event for event in events if source_of(event) == source]
        values_by_metric["total events"].append(len(source_events))
        values_by_metric["scored events"].append(sum(1 for event in source_events if scored_event(event)))
        values_by_metric["ML positive"].append(sum(1 for event in source_events if is_ml_positive(event)))

    x_positions = list(range(len(SOURCES)))
    width = 0.25
    plt.figure(figsize=(9, 5.5))
    ax = plt.gca()
    colors = ["#56ccf2", "#27ae60", "#eb5757"]
    all_values: list[int] = []
    for idx, metric in enumerate(metrics):
        offsets = [x + (idx - 1) * width for x in x_positions]
        metric_values = values_by_metric[metric]
        all_values.extend(metric_values)
        ax.bar(offsets, metric_values, width=width, label=metric, color=colors[idx])
    ax.set_title("Runtime Testing Coverage by Source")
    ax.set_xlabel("Source")
    ax.set_ylabel("Event count")
    ax.set_xticks(x_positions, SOURCES)
    apply_log_scale_if_imbalanced(ax, all_values, "y")
    legend_outside(ax, "Coverage")
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "testing", "host/network/cloud", "security_events source plus stored scoring outputs", "Uses real persisted runtime outputs to show that host, network, and cloud events were scored/tested.", "Compares total, scored, and ML-positive events by source.")


def source_score_summary(events: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    values = source_risk_values(events)
    summary: dict[str, dict[str, float]] = {}
    for source in SOURCES:
        source_values = sorted(values[source])
        if source_values:
            summary[source] = {
                "mean": sum(source_values) / len(source_values),
                "p90": percentile(source_values, 90),
                "max": max(source_values),
            }
        else:
            summary[source] = {"mean": 0.0, "p90": 0.0, "max": 0.0}
    return summary


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    rank = (len(values) - 1) * pct / 100.0
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return values[int(rank)]
    return values[low] + (values[high] - values[low]) * (rank - low)


def figure_score_or_threshold_analysis_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "testing/score_or_threshold_analysis_by_source.png"
    values = source_risk_values(events)
    if not any(values[source] for source in SOURCES):
        return skip(filename, "testing", "host/network/cloud", "stored anomaly and multilayer risk fields", "Would compare risk summaries across all sources.", "No stored risk values were available.")

    summary = source_score_summary(events)
    metrics = ["mean", "p90", "max"]
    x_positions = list(range(len(SOURCES)))
    width = 0.24
    plt.figure(figsize=(9, 5.5))
    ax = plt.gca()
    colors = ["#2d9cdb", "#f2c94c", "#eb5757"]
    for idx, metric in enumerate(metrics):
        offsets = [x + (idx - 1) * width for x in x_positions]
        ax.bar(offsets, [summary[source][metric] for source in SOURCES], width=width, label=metric, color=colors[idx])
    ax.axhline(7.0, color="#ffffff", linestyle="--", linewidth=1, alpha=0.55, label="high-risk reference")
    ax.set_title("Score and Threshold Analysis by Source")
    ax.set_xlabel("Source")
    ax.set_ylabel("Risk score (0-10)")
    ax.set_ylim(0, 10.5)
    ax.set_xticks(x_positions, SOURCES)
    legend_outside(ax, "Metric")
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "testing", "host/network/cloud", "host/network/cloud stored risk fields", "Compares source risk distributions against a shared high-risk reference without inventing labels.", "Uses real stored risk scores to summarize mean, p90, and maximum risk by source.")


def figure_evaluation_matrix_or_summary_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "testing/evaluation_matrix_or_summary_by_source.png"
    if not events:
        return skip(filename, "testing", "host/network/cloud", "security_events anomaly labels and scored-event fields", "Stacked summary includes all sources.", "No events found in security_events.")

    categories = ["normal/scored", "anomalous", "unlabeled"]
    values = {category: [] for category in categories}
    for source in SOURCES:
        source_events = [event for event in events if source_of(event) == source]
        anomalous = sum(1 for event in source_events if is_ml_positive(event))
        scored_normal = sum(1 for event in source_events if scored_event(event) and not is_ml_positive(event))
        unlabeled = max(0, len(source_events) - anomalous - scored_normal)
        values["normal/scored"].append(scored_normal)
        values["anomalous"].append(anomalous)
        values["unlabeled"].append(unlabeled)

    plt.figure(figsize=(10, 5.5))
    ax = plt.gca()
    colors = {"normal/scored": "#27ae60", "anomalous": "#eb5757", "unlabeled": "#828282"}
    x_positions = list(range(len(SOURCES)))
    width = 0.24
    all_values: list[int] = []
    for category in categories:
        idx = categories.index(category)
        offsets = [x + (idx - 1) * width for x in x_positions]
        all_values.extend(values[category])
        ax.bar(offsets, values[category], width=width, label=category, color=colors[category])
    ax.set_title("Evaluation Outcome Summary by Source")
    ax.set_xlabel("Source")
    ax.set_ylabel("Event count")
    ax.set_xticks(x_positions, SOURCES)
    apply_log_scale_if_imbalanced(ax, all_values, "y")
    legend_outside(ax, "Outcome")
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "testing", "host/network/cloud", "security_events anomaly labels and scoring fields", "Keeps the testing section cross-source when true confusion matrices are not available for every source.", "Summarizes stored scored-normal, anomalous, and unlabeled outcomes by source.")


def figure_rule_vs_ml_overlap_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "results/rule_vs_ml_overlap_by_source.png"
    if not events:
        return skip(filename, "results", "host/network/cloud", "rules_triggered plus anomaly/risk fields grouped by source", "Grouped overlap includes all sources.", "No events found in security_events.")

    categories = ["Rule + ML", "Rule only", "ML only", "Neither"]
    values = {category: [] for category in categories}
    for source in SOURCES:
        source_events = [event for event in events if source_of(event) == source]
        counts = Counter()
        for event in source_events:
            rule = is_rule_positive(event)
            ml = is_ml_positive(event)
            if rule and ml:
                counts["Rule + ML"] += 1
            elif rule:
                counts["Rule only"] += 1
            elif ml:
                counts["ML only"] += 1
            else:
                counts["Neither"] += 1
        for category in categories:
            values[category].append(counts[category])

    fig, axes = plt.subplots(1, 3, figsize=(12, 4.8), sharey=False)
    colors = {"Rule + ML": "#9b51e0", "Rule only": "#f2994a", "ML only": "#2d9cdb", "Neither": "#828282"}
    for source_idx, source in enumerate(SOURCES):
        ax = axes[source_idx]
        source_values = [values[category][source_idx] for category in categories]
        ax.bar(range(len(categories)), source_values, color=[colors[category] for category in categories])
        ax.set_title(source.title())
        ax.set_xticks(range(len(categories)), [wrapped_label(category, width=10) for category in categories], rotation=0)
        ax.set_ylabel("Event count" if source_idx == 0 else "")
        apply_log_scale_if_imbalanced(ax, source_values, "y")
        for idx, value in enumerate(source_values):
            if value:
                ax.text(idx, value, str(value), ha="center", va="bottom", fontsize=7)
    fig.suptitle("Rule-Based and ML Detection Overlap by Source", y=1.02)
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "results", "host/network/cloud", "rules_triggered, anomaly labels, host/network/cloud risk fields", "Directly compares rule and ML outcomes for each source.", "Shows rule-positive, ML-positive, overlapping, and neither categories by source.")


def figure_risk_distribution_by_source(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "results/risk_distribution_by_source.png"
    values = source_risk_values(events)
    if not any(values[source] for source in SOURCES):
        return skip(filename, "results", "host/network/cloud", "host/network/cloud stored risk fields", "Risk bins would compare all sources.", "No stored risk values were available.")

    bins = [("0-3 low", 0.0, 3.0), ("3-7 medium", 3.0, 7.0), ("7-10 high", 7.0, 10.01)]
    bin_values = {label: [] for label, _, _ in bins}
    for source in SOURCES:
        source_values = values[source]
        for label, low, high in bins:
            bin_values[label].append(sum(1 for value in source_values if low <= value < high))

    fig, axes = plt.subplots(1, 3, figsize=(12, 4.8), sharey=False)
    colors = {"0-3 low": "#27ae60", "3-7 medium": "#f2c94c", "7-10 high": "#eb5757"}
    for source_idx, source in enumerate(SOURCES):
        ax = axes[source_idx]
        source_values = [bin_values[label][source_idx] for label, _, _ in bins]
        labels = [label for label, _, _ in bins]
        ax.bar(range(len(labels)), source_values, color=[colors[label] for label in labels])
        ax.set_title(source.title())
        ax.set_xticks(range(len(labels)), [wrapped_label(label, width=10) for label in labels])
        ax.set_ylabel("Scored event count" if source_idx == 0 else "")
        apply_log_scale_if_imbalanced(ax, source_values, "y")
        for idx, value in enumerate(source_values):
            if value:
                ax.text(idx, value, str(value), ha="center", va="bottom", fontsize=7)
    fig.suptitle("Risk Distribution by Source", y=1.02)
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "results", "host/network/cloud", "anomaly_risk_10, host_multilayer_risk, network_multilayer_risk and related risk fields", "Normalizes differing source risk fields into common 0-10 risk bands.", "Compares low, medium, and high risk event populations by source.")


def select_cross_source_chain(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str, str]:
    candidates = [
        event
        for event in events
        if source_of(event) in SOURCES
        and parse_timestamp(event.get("timestamp")) is not None
        and (event_risk(event) >= 6 or is_ml_positive(event) or is_rule_positive(event) or str(event.get("severity") or "").lower() == "high")
    ]
    if len(candidates) < 2:
        return [], "", "Fewer than two notable timestamped events were available."

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in candidates:
        for key in entity_keys(event):
            groups[key].append(event)

    best_chain: list[dict[str, Any]] = []
    best_entity = ""
    best_score = -1.0
    for key, group in groups.items():
        group = sorted(group, key=lambda item: parse_timestamp(item.get("timestamp")) or datetime.min)
        for idx, start_event in enumerate(group):
            start_time = parse_timestamp(start_event.get("timestamp"))
            if start_time is None:
                continue
            window = [
                item
                for item in group[idx:]
                if (parse_timestamp(item.get("timestamp")) or start_time) - start_time <= timedelta(minutes=15)
            ]
            sources = {source_of(item) for item in window}
            if len(window) < 2 or len(sources) < 2:
                continue
            score = sum(event_risk(item) for item in window) + len(sources) * 10 + len(window)
            if score > best_score:
                best_score = score
                best_entity = f"{key[0]}={key[1]}"
                best_chain = window[:7]

    if best_chain:
        return best_chain, best_entity, ""

    sorted_candidates = sorted(candidates, key=lambda item: parse_timestamp(item.get("timestamp")) or datetime.min)
    best_chain = []
    best_score = -1.0
    for idx, start_event in enumerate(sorted_candidates):
        start_time = parse_timestamp(start_event.get("timestamp"))
        if start_time is None:
            continue
        window = [
            item
            for item in sorted_candidates[idx:]
            if (parse_timestamp(item.get("timestamp")) or start_time) - start_time <= timedelta(minutes=10)
        ]
        sources = {source_of(item) for item in window}
        if len(window) < 2 or len(sources) < 2:
            continue
        score = sum(event_risk(item) for item in window) + len(sources) * 6 + len(window)
        if score > best_score:
            best_score = score
            best_chain = window[:7]
    if best_chain:
        return best_chain, "risk convergence window", ""
    return [], "", "No cross-source same-entity or short-window convergence chain was available."


def figure_correlated_activity_cross_source_timeline(events: list[dict[str, Any]]) -> ManifestEntry:
    filename = "results/correlated_activity_cross_source_timeline.png"
    chain, entity, reason = select_cross_source_chain(events)
    if not chain:
        return skip(filename, "results", "best available cross-source context", "security_events timestamp/entity/risk fields", "Would use a real multi-source chain if available.", reason)

    chain = sorted(chain, key=lambda event: parse_timestamp(event.get("timestamp")) or datetime.min)
    times = [parse_timestamp(event.get("timestamp")) for event in chain]
    risks = [event_risk(event) for event in chain]
    colors = [SOURCE_COLORS[source_of(event)] for event in chain]

    plt.figure(figsize=(11.5, 5.2))
    ax = plt.gca()
    ax.plot(times, risks, color="#555555", linewidth=1.2, alpha=0.45)
    for idx, (event, event_time, risk, color) in enumerate(zip(chain, times, risks, colors)):
        label = f"{source_of(event)}\n{wrapped_label(event.get('event_type') or 'event', width=18, max_lines=2)}"
        ax.scatter([event_time], [risk], color=color, s=80, edgecolors="#222222", linewidths=0.6)
        offset = 12 if idx % 2 == 0 else -34
        ax.annotate(label, (event_time, risk), textcoords="offset points", xytext=(0, offset), ha="center", fontsize=7)
    ax.set_title(f"Correlated Cross-Source Activity Timeline ({entity})")
    ax.set_xlabel("Event timestamp")
    ax.set_ylabel("Risk score")
    ax.set_ylim(0, 10.5)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    for source in SOURCES:
        ax.scatter([], [], color=SOURCE_COLORS[source], label=source)
    legend_outside(ax, "Source")
    ax.grid(True, alpha=0.22)
    plt.xticks(rotation=20, ha="right")
    save_figure(FIGURE_ROOT / filename)
    return generated(filename, "results", "cross-source chain where available", "security_events same actor/IP/resource or short-window convergence", "Selects a real high-value timeline involving more than one source when available.", "Plots the strongest real cross-source correlated chain or convergence window.")


def write_manifest(entries: list[ManifestEntry]) -> None:
    FIGURE_ROOT.mkdir(parents=True, exist_ok=True)
    lines = ["ISMS Report Figure Manifest", ""]
    for entry in entries:
        lines.extend(
            [
                f"filename: {entry.filename}",
                f"section: {entry.section}",
                f"covers host/network/cloud: {entry.coverage}",
                f"actual data source used: {entry.data_source}",
                f"why this satisfies the section coverage rule: {entry.coverage_reason}",
                f"generated or skipped: {entry.status}",
                f"explanation: {entry.explanation}",
                f"skipped reason: {entry.skipped_reason}" if entry.skipped_reason else "skipped reason:",
                "",
            ]
        )
    MANIFEST_PATH.write_text("\n".join(lines), encoding="utf-8")


def run_figure(name: str, fn: Callable[[], ManifestEntry]) -> ManifestEntry:
    try:
        entry = fn()
    except Exception as exc:
        entry = ManifestEntry(
            name,
            "unknown",
            "unknown",
            "unknown",
            "Figure failed before coverage could be established.",
            "skipped",
            "Figure not generated.",
            f"Unexpected error: {exc}",
        )
        plt.close("all")
    print(f"[{entry.status.upper()}] {entry.filename}" + (f" - {entry.skipped_reason}" if entry.skipped_reason else ""))
    return entry


def main() -> int:
    ensure_output_dirs()
    remove_stale_outputs()
    entries: list[ManifestEntry] = []
    db_path = sqlite_path_from_database_url()
    print("[INFO] ISMS report figure generation started")
    print(f"[INFO] SQLite database path from config: {db_path}")

    try:
        events = fetch_security_events()
        schema_available = True
        print(f"[INFO] Loaded {len(events)} security_events rows")
    except Exception as exc:
        events = []
        schema_available = False
        print(f"[WARN] Could not load security_events: {exc}")

    figure_specs: list[tuple[str, Callable[[], ManifestEntry]]] = [
        ("core/event_source_distribution.png", lambda: figure_event_source_distribution(events)),
        ("core/top_event_types_by_source.png", lambda: figure_top_event_types_by_source(events)),
        ("core/severity_distribution_by_source.png", lambda: figure_severity_distribution_by_source(events)),
        ("core/event_volume_over_time_by_source.png", lambda: figure_event_volume_over_time_by_source(events)),
        (
            "implementation/database_schema_summary.png",
            figure_database_schema_summary if schema_available else lambda: skip("implementation/database_schema_summary.png", "implementation", "system-wide host/network/cloud", "PRAGMA table_info(security_events)", "All sources share this table when the DB is available.", "Database schema is unavailable."),
        ),
        ("implementation/source_profile_usage.png", lambda: figure_source_profile_usage(events)),
        ("implementation/model_coverage_by_source.png", lambda: figure_model_coverage_by_source(events)),
        ("testing/testing_coverage_by_source.png", lambda: figure_testing_coverage_by_source(events)),
        ("testing/score_or_threshold_analysis_by_source.png", lambda: figure_score_or_threshold_analysis_by_source(events)),
        ("testing/evaluation_matrix_or_summary_by_source.png", lambda: figure_evaluation_matrix_or_summary_by_source(events)),
        ("results/rule_vs_ml_overlap_by_source.png", lambda: figure_rule_vs_ml_overlap_by_source(events)),
        ("results/risk_distribution_by_source.png", lambda: figure_risk_distribution_by_source(events)),
        ("results/correlated_activity_cross_source_timeline.png", lambda: figure_correlated_activity_cross_source_timeline(events)),
    ]

    for name, fn in figure_specs:
        entries.append(run_figure(name, fn))

    write_manifest(entries)
    generated_count = sum(1 for entry in entries if entry.status == "generated")
    skipped_count = sum(1 for entry in entries if entry.status == "skipped")
    print("[INFO] Figure generation complete")
    print(f"[INFO] Generated: {generated_count}")
    print(f"[INFO] Skipped: {skipped_count}")
    print(f"[INFO] Manifest: {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
