from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from app.config import DATABASE_URL


NETWORK_RULES_BY_EVENT_TYPE = {
    "net_conn_high_risk": "NET_CONN_HIGH_RISK",
    "net_listener_open": "NET_LISTENER_OPEN",
    "net_conn_allowed": "NET_CONN_ALLOWED",
    "net_conn_blocked": "NET_CONN_BLOCKED",
}


def sqlite_path_from_database_url(database_url: str = DATABASE_URL) -> Path:
    if not database_url.startswith("sqlite:///"):
        raise RuntimeError(f"Only sqlite DATABASE_URL values are supported: {DATABASE_URL}")
    raw_path = database_url.replace("sqlite:///", "", 1)
    return Path(unquote(raw_path))


def connect_database() -> sqlite3.Connection:
    db_path = sqlite_path_from_database_url()
    if not db_path.exists():
        raise FileNotFoundError(f"SQLite database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def parse_rules(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except Exception:
            return [text]
        if isinstance(parsed, list):
            return [str(item) for item in parsed if str(item).strip()]
        return [text]
    return [str(value)]


def has_empty_rules(value: Any) -> bool:
    return not parse_rules(value)


def infer_network_rule(row: sqlite3.Row) -> str | None:
    event_type = str(row["event_type"] or "").strip()
    return NETWORK_RULES_BY_EVENT_TYPE.get(event_type)


def fetch_candidate_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT id, event_type, severity, severity_reason, rules_triggered
        FROM security_events
        WHERE source = 'network'
        ORDER BY id ASC
        """
    ).fetchall()


def backfill_network_rules(apply: bool) -> int:
    with connect_database() as conn:
        rows = fetch_candidate_rows(conn)
        examined = len(rows)
        empty_rules = 0
        eligible = 0
        updated = 0
        skipped_existing_rules = 0
        skipped_no_supported_rule = 0
        by_rule = {rule: 0 for rule in NETWORK_RULES_BY_EVENT_TYPE.values()}

        for row in rows:
            if not has_empty_rules(row["rules_triggered"]):
                skipped_existing_rules += 1
                continue

            empty_rules += 1
            rule_name = infer_network_rule(row)
            if not rule_name:
                skipped_no_supported_rule += 1
                continue

            eligible += 1
            by_rule[rule_name] += 1
            if apply:
                conn.execute(
                    "UPDATE security_events SET rules_triggered = ? WHERE id = ?",
                    (json.dumps([rule_name], ensure_ascii=False), row["id"]),
                )
                updated += 1

        if apply:
            conn.commit()

    mode = "APPLY" if apply else "DRY-RUN"
    print(f"[{mode}] Network rules_triggered backfill")
    print(f"Database: {sqlite_path_from_database_url()}")
    print(f"Network rows examined: {examined}")
    print(f"Rows skipped because rules_triggered already populated: {skipped_existing_rules}")
    print(f"Rows with empty rules_triggered: {empty_rules}")
    print(f"Eligible rows with supported network event_type: {eligible}")
    print(f"Rows skipped because event_type has no supported network rule: {skipped_no_supported_rule}")
    print(f"Rows updated: {updated if apply else 0}")
    print("Eligible rows by rule:")
    for rule_name, count in by_rule.items():
        print(f"  {rule_name}: {count}")

    if not apply:
        print("Dry-run only. Re-run with --apply to update eligible rows.")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-time backfill for historical network rules_triggered values."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually update eligible network rows. Omit this flag for dry-run mode.",
    )
    args = parser.parse_args()
    return backfill_network_rules(apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
