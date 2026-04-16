from __future__ import annotations

import json
import math
import random
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

BACKEND_DIR = Path(__file__).resolve().parents[2]
RAW_DIR = BACKEND_DIR / "data" / "public_datasets" / "host_public_raw"
MORDOR_DIR = RAW_DIR / "mordor"
EVTX_ATTACK_SAMPLES_DIR = RAW_DIR / "evtx_attack_samples"
OUTPUT_DIR = BACKEND_DIR / "data" / "public_datasets" / "host_public"
TRAIN_PATH = OUTPUT_DIR / "train_host_public.jsonl"
VAL_PATH = OUTPUT_DIR / "val_host_public.jsonl"
TRAIN_RATIO = 0.8
RANDOM_SEED = 42
MAX_STRING_INSERTS = 24
MAX_INSERT_LENGTH = 300
SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson"}

AUTH_EVENT_IDS = {4624, 4625, 4648, 4672}
BASELINE_ACTORS = {
    "system",
    "local service",
    "network service",
    "administrator",
    "admin",
    "secadmin",
    "domainadmin",
    "backupadmin",
    "trustedinstaller",
}
COMMON_4648_LOGON_TYPES = {2, 3, 9, 10}


def safe_text(value: Any, max_length: int = MAX_INSERT_LENGTH) -> str | None:
    if value is None:
        return None

    if isinstance(value, dict):
        for key in ("#text", "text", "Value", "value", "@Value"):
            if key in value:
                return safe_text(value.get(key), max_length=max_length)
        return None

    if isinstance(value, list):
        if len(value) == 1:
            return safe_text(value[0], max_length=max_length)
        return None

    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        return text[:max_length]
    return text


def safe_int(value: Any) -> int | None:
    text = safe_text(value)
    if text is None:
        return None
    try:
        return int(text)
    except Exception:
        try:
            return int(float(text))
        except Exception:
            return None


def stable_hash(value: Any) -> float:
    text = str(value or "").lower()
    return float(sum(ord(ch) for ch in text) % 1000)


def numeric_or_default(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        if math.isfinite(result):
            return result
    except Exception:
        pass
    return default


def event_type_from_id(event_id: int) -> str:
    if event_id == 4624:
        return "win_login_success"
    if event_id == 4625:
        return "win_login_failed"
    if event_id == 4672:
        return "win_event_4672"
    if event_id == 4648:
        return "win_event_4648"
    return f"win_event_{event_id}"


def auth_outcome_code(event_type: str) -> float:
    if event_type == "win_login_success":
        return 1.0
    if event_type == "win_login_failed":
        return 2.0
    return 0.0


def source_ip_scope_code(ip_text: str) -> float:
    if not ip_text:
        return 0.0

    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return 0.0

    if ip_obj.is_loopback:
        return 1.0
    if ip_obj.is_private:
        return 2.0
    return 3.0


def off_hours_flag(hour_of_day: float) -> float:
    return 1.0 if hour_of_day < 6 or hour_of_day > 22 else 0.0


def collect_text_values(obj: Any, values: list[str] | None = None) -> list[str]:
    if values is None:
        values = []

    if isinstance(obj, dict):
        for key in ("#text", "text", "Value", "value", "@Value"):
            if key in obj:
                text = safe_text(obj.get(key), max_length=512)
                if text:
                    values.append(text)
        for value in obj.values():
            if isinstance(value, (dict, list)):
                collect_text_values(value, values)
            else:
                text = safe_text(value, max_length=512)
                if text:
                    values.append(text)
    elif isinstance(obj, list):
        for item in obj:
            collect_text_values(item, values)
    else:
        text = safe_text(obj, max_length=512)
        if text:
            values.append(text)

    return values


def event_root(record: dict) -> dict:
    event_obj = record.get("Event")
    if isinstance(event_obj, dict):
        return event_obj
    return record


def system_section(record: dict) -> dict:
    root = event_root(record)
    section = root.get("System")
    return section if isinstance(section, dict) else {}


def event_data_section(record: dict) -> Any:
    root = event_root(record)
    for key in ("EventData", "UserData"):
        value = root.get(key)
        if value is not None:
            return value
    return {}


def normalize_timestamp(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except Exception:
            return None

    if isinstance(value, dict):
        for key in ("SystemTime", "@SystemTime", "systemtime"):
            if key in value:
                return normalize_timestamp(value.get(key))
        return None

    text = safe_text(value, max_length=128)
    if text is None:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    known_formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    )
    for fmt in known_formats:
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            continue

    return None


def extract_scalar_map(obj: Any, result: dict[str, str] | None = None) -> dict[str, str]:
    if result is None:
        result = {}

    if isinstance(obj, dict):
        name_value = None
        for key in ("Name", "@Name", "name"):
            if key in obj:
                name_value = safe_text(obj.get(key), max_length=128)
                break

        if name_value:
            for key in ("#text", "text", "Value", "value", "@Value"):
                if key in obj:
                    value_text = safe_text(obj.get(key))
                    if value_text is not None:
                        result.setdefault(name_value.lower(), value_text)
                        break

        for key, value in obj.items():
            text = safe_text(value)
            key_text = str(key).strip().lower()
            if text is not None and key_text:
                result.setdefault(key_text, text)
            if isinstance(value, (dict, list)):
                extract_scalar_map(value, result)

    elif isinstance(obj, list):
        for item in obj:
            extract_scalar_map(item, result)

    return result


def extract_string_inserts(record: dict) -> list[str]:
    existing = record.get("string_inserts")
    if isinstance(existing, list):
        safe_existing = []
        for value in existing[:MAX_STRING_INSERTS]:
            text = safe_text(value)
            safe_existing.append(text or "")
        return safe_existing

    inserts: list[str] = []
    section = event_data_section(record)

    def visit(obj: Any) -> None:
        if len(inserts) >= MAX_STRING_INSERTS:
            return

        if isinstance(obj, dict):
            if "Data" in obj:
                visit(obj.get("Data"))
            for key in ("#text", "text", "Value", "value", "@Value"):
                if key in obj:
                    text = safe_text(obj.get(key))
                    if text is not None:
                        inserts.append(text)
                        return
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    visit(value)
        elif isinstance(obj, list):
            for item in obj:
                visit(item)
                if len(inserts) >= MAX_STRING_INSERTS:
                    return
        else:
            text = safe_text(obj)
            if text is not None:
                inserts.append(text)

    visit(section)
    return inserts[:MAX_STRING_INSERTS]


def extract_event_id(record: dict) -> int | None:
    system = system_section(record)

    for candidate in (
        system.get("EventID"),
        system.get("@EventID"),
        record.get("event_id"),
        record.get("EventID"),
        record.get("eventID"),
        record.get("@EventID"),
    ):
        value = safe_int(candidate)
        if value is not None:
            return value

    scalar_map = extract_scalar_map(record)
    for key in ("event_id", "eventid", "@eventid"):
        value = safe_int(scalar_map.get(key))
        if value is not None:
            return value

    for key, value in scalar_map.items():
        if "eventid" in key:
            parsed = safe_int(value)
            if parsed is not None:
                return parsed

    return None


def extract_timestamp(record: dict) -> str | None:
    system = system_section(record)

    for candidate in (
        record.get("timestamp"),
        record.get("Timestamp"),
        record.get("EventTime"),
        record.get("@timestamp"),
        system.get("TimeCreated"),
        record.get("TimeCreated"),
    ):
        value = normalize_timestamp(candidate)
        if value is not None:
            return value

    scalar_map = extract_scalar_map(record)
    for key in ("timestamp", "eventtime", "@timestamp", "systemtime"):
        value = normalize_timestamp(scalar_map.get(key))
        if value is not None:
            return value

    return None


def extract_channel(record: dict) -> str | None:
    system = system_section(record)
    for candidate in (
        record.get("channel"),
        record.get("Channel"),
        system.get("Channel"),
    ):
        text = safe_text(candidate, max_length=128)
        if text is not None:
            return text
    return None


def extract_provider(record: dict) -> str | None:
    system = system_section(record)
    provider = system.get("Provider")

    if isinstance(provider, dict):
        for candidate in (
            provider.get("Name"),
            provider.get("@Name"),
            (provider.get("#attributes") or {}).get("Name") if isinstance(provider.get("#attributes"), dict) else None,
        ):
            text = safe_text(candidate, max_length=256)
            if text is not None:
                return text

    for candidate in (
        record.get("source"),
        record.get("Source"),
        record.get("provider"),
        record.get("ProviderName"),
    ):
        text = safe_text(candidate, max_length=256)
        if text is not None:
            return text

    scalar_map = extract_scalar_map(record)
    for key in ("source", "providername", "provider", "name"):
        text = safe_text(scalar_map.get(key), max_length=256)
        if text is not None and text not in {"Event", "System"}:
            return text

    return None


def extract_event_category(record: dict) -> int | None:
    system = system_section(record)
    for candidate in (
        record.get("event_category"),
        record.get("EventCategory"),
        system.get("EventCategory"),
        record.get("Category"),
    ):
        value = safe_int(candidate)
        if value is not None:
            return value
    return None


def extract_computer_name(record: dict) -> str | None:
    system = system_section(record)
    for candidate in (
        record.get("computer_name"),
        record.get("Computer"),
        record.get("ComputerName"),
        system.get("Computer"),
    ):
        text = safe_text(candidate, max_length=256)
        if text is not None:
            return text
    return None


def extract_actor(record: dict) -> str | None:
    for candidate in (
        record.get("actor"),
        record.get("Actor"),
        record.get("user"),
        record.get("User"),
        record.get("Username"),
    ):
        text = safe_text(candidate, max_length=256)
        if text is not None:
            return text

    scalar_map = extract_scalar_map(record)
    for key in (
        "targetusername",
        "subjectusername",
        "accountname",
        "username",
        "user",
        "targetuser",
        "subjectuser",
        "user_name",
        "userprincipalname",
        "samaccountname",
    ):
        text = safe_text(scalar_map.get(key), max_length=256)
        if text is not None and text != "-":
            return text

    return None


def extract_source_ip(record: dict) -> str | None:
    for candidate in (
        record.get("ip"),
        record.get("source_ip"),
        record.get("SourceIp"),
        record.get("SourceIP"),
    ):
        text = safe_text(candidate, max_length=128)
        if text:
            try:
                ipaddress.ip_address(text)
                return text
            except ValueError:
                pass

    scalar_map = extract_scalar_map(record)
    for key in (
        "source_ip",
        "sourceip",
        "ipaddress",
        "sourcenetworkaddress",
        "clientaddress",
        "ip",
    ):
        text = safe_text(scalar_map.get(key), max_length=128)
        if not text or text == "-":
            continue
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            continue

    return None


def extract_logon_type(record: dict) -> int | None:
    for candidate in (
        record.get("logon_type"),
        record.get("LogonType"),
    ):
        value = safe_int(candidate)
        if value is not None:
            return value

    scalar_map = extract_scalar_map(record)
    for key in ("logontype", "logon_type"):
        value = safe_int(scalar_map.get(key))
        if value is not None:
            return value

    return None


def extract_process_name(record: dict) -> str | None:
    for candidate in (
        record.get("process_name"),
        record.get("ProcessName"),
    ):
        text = safe_text(candidate, max_length=300)
        if text is not None:
            return text

    scalar_map = extract_scalar_map(record)
    for key in (
        "processname",
        "newprocessname",
        "callerprocessname",
        "image",
        "process",
        "process_path",
    ):
        text = safe_text(scalar_map.get(key), max_length=300)
        if text is not None:
            return text

    return None


def extract_message(record: dict) -> str:
    root = event_root(record)
    rendering_info = root.get("RenderingInfo")
    if isinstance(rendering_info, dict):
        message = safe_text(rendering_info.get("Message"), max_length=4000)
        if message:
            return message

    section = event_data_section(record)
    if isinstance(section, dict) and "Data" in section:
        parts = collect_text_values(section.get("Data"))
        if parts:
            return " | ".join(parts[:32])

    parts = collect_text_values(section)
    if parts:
        return " | ".join(parts[:32])

    return ""


def looks_like_event_record(record: dict) -> bool:
    event_id = extract_event_id(record)
    if event_id is None:
        return False

    if extract_timestamp(record) is not None:
        return True

    if extract_channel(record) is not None:
        return True

    if extract_provider(record) is not None:
        return True

    return False


def iter_event_records(obj: Any) -> Iterator[dict]:
    if isinstance(obj, dict):
        if looks_like_event_record(obj):
            yield obj
            return
        for value in obj.values():
            yield from iter_event_records(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_event_records(item)


def iter_loaded_items(obj: Any) -> Iterator[Any]:
    if isinstance(obj, list):
        for item in obj:
            yield item
        return

    if isinstance(obj, dict):
        for key in ("events", "records", "data"):
            value = obj.get(key)
            if isinstance(value, list):
                for item in value:
                    yield item
                return

    yield obj


def extract_records_from_loaded_json(obj: Any) -> list[dict]:
    records: list[dict] = []
    for item in iter_loaded_items(obj):
        try:
            records.extend(iter_event_records(item))
        except Exception:
            continue
    return records


def read_records_from_file(path: Path) -> tuple[list[dict], int]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return [], 1

    jsonl_records: list[dict] = []
    jsonl_parse_failures = 0
    nonempty_lines = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        nonempty_lines += 1
        try:
            parsed = json.loads(stripped)
        except Exception:
            jsonl_parse_failures += 1
            continue

        try:
            jsonl_records.extend(extract_records_from_loaded_json(parsed))
        except Exception:
            jsonl_parse_failures += 1

    if jsonl_records:
        return jsonl_records, jsonl_parse_failures

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            parsed = json.load(f)
    except Exception:
        fallback_failures = jsonl_parse_failures if jsonl_parse_failures > 0 else max(1, nonempty_lines)
        return [], fallback_failures

    records = extract_records_from_loaded_json(parsed)
    return records, 0


def input_paths() -> Iterator[Path]:
    for base_dir in (MORDOR_DIR, EVTX_ATTACK_SAMPLES_DIR):
        if not base_dir.exists():
            continue
        for path in base_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
                yield path


def is_baseline_actor(actor: str | None) -> bool:
    text = str(actor or "").strip().lower()
    if not text:
        return False
    if text in BASELINE_ACTORS:
        return True
    if text.endswith("$"):
        return True
    if "admin" in text or "administrator" in text:
        return True
    if "service" in text or text == "system":
        return True
    return False


def normalize_record(record: dict) -> dict | None:
    event_id = extract_event_id(record)
    if event_id is None:
        return None

    timestamp = extract_timestamp(record)
    if timestamp is None:
        return None

    channel = extract_channel(record) or ""
    source_provider = extract_provider(record) or ""
    actor = extract_actor(record)
    source_ip = extract_source_ip(record)
    logon_type = extract_logon_type(record)
    process_name = extract_process_name(record)
    computer_name = extract_computer_name(record)
    event_category = extract_event_category(record)
    string_inserts = extract_string_inserts(record)
    message = extract_message(record)
    event_type = event_type_from_id(event_id)

    return {
        "source": "host",
        "event_type": event_type,
        "timestamp": timestamp,
        "actor": actor,
        "ip": source_ip,
        "resource": f"{channel}:{source_provider}",
        "rules_triggered": [f"HOST_EVENT_{event_id}"],
        "raw": {
            "channel": channel or None,
            "source": source_provider or None,
            "event_id": event_id,
            "record_number": None,
            "event_category": event_category,
            "source_ip": source_ip,
            "logon_type": logon_type,
            "process_name": process_name,
            "string_inserts": string_inserts,
            "computer_name": computer_name,
            "message": message,
        },
    }


def failed_login_key(row: dict) -> tuple[str, str, str, str]:
    actor = str(row.get("actor") or "unknown").strip().lower()
    raw = row.get("raw") or {}
    computer_name = str(raw.get("computer_name") or "").strip().lower()
    source_ip = str((row.get("ip") or raw.get("source_ip") or "")).strip().lower()
    timestamp = str(row.get("timestamp") or "")
    hour_bucket = timestamp[:13] if len(timestamp) >= 13 else timestamp
    return actor, computer_name, source_ip, hour_bucket


def label_row(
    row: dict,
    actor_counter: Counter,
    failed_login_counter: Counter,
) -> tuple[str | None, str | None]:
    raw = row.get("raw") or {}
    event_id = safe_int(raw.get("event_id"))
    if event_id is None:
        return None, "missing event_id"

    if event_id not in AUTH_EVENT_IDS:
        return None, "non-auth event"

    actor_value = str(row.get("actor") or "").strip()
    actor = actor_value or "unknown"
    source_ip = str(row.get("ip") or raw.get("source_ip") or "").strip()
    source_ip_scope = source_ip_scope_code(source_ip)
    logon_type = safe_int(raw.get("logon_type"))

    timestamp_text = str(row.get("timestamp") or "")
    try:
        hour_of_day = float(datetime.fromisoformat(timestamp_text).hour)
    except Exception:
        hour_of_day = 0.0
    is_off_hours = off_hours_flag(hour_of_day) == 1.0

    if event_id == 4625:
        return "anomaly", None

    if event_id == 4672:
        if (actor_value and not is_baseline_actor(actor)) or is_off_hours or source_ip_scope == 3.0:
            return "anomaly", None
        return "benign", None

    if event_id == 4648:
        unusual_actor = actor_counter.get(actor, 0) <= 2
        unusual_logon_type = logon_type is not None and logon_type not in COMMON_4648_LOGON_TYPES
        if is_off_hours or unusual_actor or unusual_logon_type or source_ip_scope == 3.0:
            return "anomaly", None
        return "benign", None

    if event_id == 4624:
        return "benign", None

    return None, "ambiguous auth event"


def build_feature_vector(
    row: dict,
    actor_frequency: Counter,
    event_type_frequency: Counter,
    total_rows: int,
) -> list[float]:
    raw = row.get("raw") or {}
    event_type = str(row.get("event_type") or "")
    actor_value = str(row.get("actor") or "").strip()
    actor = actor_value or "unknown"
    event_id = safe_int(raw.get("event_id")) or 0
    channel = str(raw.get("channel") or "")
    timestamp_text = str(row.get("timestamp") or "")

    try:
        hour_of_day = float(datetime.fromisoformat(timestamp_text).hour)
    except Exception:
        hour_of_day = 0.0

    actor_frequency_norm = (actor_frequency.get(actor, 0) / total_rows) if total_rows else 0.0
    event_type_frequency_norm = (event_type_frequency.get(event_type, 0) / total_rows) if total_rows else 0.0
    off_hours = off_hours_flag(hour_of_day)
    failed_login_intensity = 1.0 if event_type == "win_login_failed" else 0.0
    privileged_off_hours_combo = 1.0 if event_id == 4672 and off_hours == 1.0 else 0.0
    source_ip = str(row.get("ip") or raw.get("source_ip") or "").strip()
    process_value = str(raw.get("process_name") or "").strip()
    process_name = process_value or "unknown"
    source_provider = str(raw.get("source") or "")
    computer_name = str(raw.get("computer_name") or "")

    return [
        float(event_id),
        stable_hash(event_type),
        stable_hash(actor),
        1.0 if actor_value else 0.0,
        hour_of_day,
        stable_hash(channel),
        1.0 if event_id == 4672 else 0.0,
        auth_outcome_code(event_type),
        numeric_or_default(raw.get("event_category"), 0.0),
        float(actor_frequency_norm),
        float(event_type_frequency_norm),
        off_hours,
        failed_login_intensity,
        privileged_off_hours_combo,
        1.0 if source_ip else 0.0,
        source_ip_scope_code(source_ip),
        numeric_or_default(raw.get("logon_type"), 0.0),
        stable_hash(process_name),
        1.0 if process_value else 0.0,
        stable_hash(source_provider),
        stable_hash(computer_name),
    ]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def print_event_distribution(rows: list[dict]) -> None:
    event_counts = Counter(row.get("event_type") for row in rows)
    for event_type, count in event_counts.most_common():
        print(f"[INFO] event_type={event_type}: {count}")


def main() -> int:
    total_rows_read = 0
    skipped_rows = 0
    parse_failures = 0
    file_read_failures = 0
    file_rows: list[tuple[Path, int, list[dict]]] = []
    normalized_rows: list[dict] = []

    for path in input_paths():
        records, file_parse_failures = read_records_from_file(path)
        total_rows_read += len(records)
        parse_failures += file_parse_failures

        if not records and file_parse_failures > 0:
            file_read_failures += 1

        file_normalized_rows: list[dict] = []
        file_normalize_skips = 0
        for record in records:
            try:
                normalized = normalize_record(record)
            except Exception:
                normalized = None
            if normalized is None:
                file_normalize_skips += 1
                continue
            file_normalized_rows.append(normalized)

        skipped_rows += file_normalize_skips
        normalized_rows.extend(file_normalized_rows)
        file_rows.append((path, len(records), file_normalized_rows))

    actor_counter = Counter(str(row.get("actor") or "unknown").strip() for row in normalized_rows)
    failed_login_counter = Counter(
        failed_login_key(row)
        for row in normalized_rows
        if safe_int((row.get("raw") or {}).get("event_id")) == 4625
    )

    event_id_counts = Counter(
        safe_int((row.get("raw") or {}).get("event_id"))
        for row in normalized_rows
        if safe_int((row.get("raw") or {}).get("event_id")) is not None
    )
    normalized_event_type_counts = Counter(str(row.get("event_type") or "") for row in normalized_rows)
    auth_extracted_counts = Counter(
        safe_int((row.get("raw") or {}).get("event_id"))
        for row in normalized_rows
        if safe_int((row.get("raw") or {}).get("event_id")) in AUTH_EVENT_IDS
    )

    labeled_rows: list[dict] = []
    excluded_rows = 0
    file_usable_counts: dict[Path, int] = {}
    auth_excluded_counts = Counter()
    auth_benign_counts = Counter()
    auth_anomaly_counts = Counter()
    auth_excluded_reason_counts: dict[int, Counter] = {
        4624: Counter(),
        4625: Counter(),
        4648: Counter(),
        4672: Counter(),
    }
    auth_candidate_file_counts = Counter()

    for path, _extracted_count, rows in file_rows:
        file_used = 0
        for row in rows:
            event_id = safe_int((row.get("raw") or {}).get("event_id"))
            if event_id in AUTH_EVENT_IDS:
                auth_candidate_file_counts[path.name] += 1
            try:
                label, reason = label_row(row, actor_counter, failed_login_counter)
            except Exception:
                label, reason = None, "labeling error"
            if label is None:
                excluded_rows += 1
                if event_id in AUTH_EVENT_IDS:
                    auth_excluded_counts[event_id] += 1
                    auth_excluded_reason_counts[event_id][reason or "unknown"] += 1
                continue
            row["label"] = label
            if event_id in AUTH_EVENT_IDS:
                if label == "benign":
                    auth_benign_counts[event_id] += 1
                elif label == "anomaly":
                    auth_anomaly_counts[event_id] += 1
            labeled_rows.append(row)
            file_used += 1
        file_usable_counts[path] = file_used

    total_used = len(labeled_rows)
    actor_frequency = Counter((str(row.get("actor") or "").strip() or "unknown") for row in labeled_rows)
    event_type_frequency = Counter(str(row.get("event_type") or "") for row in labeled_rows)

    for row in labeled_rows:
        row["features"] = build_feature_vector(row, actor_frequency, event_type_frequency, total_used)

    benign_rows = [row for row in labeled_rows if row["label"] == "benign"]
    anomaly_rows = [row for row in labeled_rows if row["label"] == "anomaly"]

    rng = random.Random(RANDOM_SEED)
    rng.shuffle(benign_rows)
    rng.shuffle(anomaly_rows)

    benign_cut = max(1, int(len(benign_rows) * TRAIN_RATIO)) if benign_rows else 0
    train_rows = benign_rows[:benign_cut]
    val_rows = benign_rows[benign_cut:] + anomaly_rows
    rng.shuffle(train_rows)
    rng.shuffle(val_rows)

    write_jsonl(TRAIN_PATH, train_rows)
    write_jsonl(VAL_PATH, val_rows)

    val_label_counts = Counter(row["label"] for row in val_rows)

    for path, extracted_count, rows in file_rows:
        auth_accepted = sum(
            1
            for row in rows
            if safe_int((row.get("raw") or {}).get("event_id")) in AUTH_EVENT_IDS
        )
        print(f"[INFO] File {path.name}: extracted={extracted_count} accepted={len(rows)} auth_accepted={auth_accepted} usable={file_usable_counts.get(path, 0)}")

    print("[INFO] Auth-only mode active: event_ids=4624,4625,4648,4672")
    print(f"[INFO] Total rows read: {total_rows_read}")
    print(f"[INFO] Rows used: {total_used}")
    print(f"[INFO] Skipped rows: {skipped_rows + excluded_rows}")
    print(f"[INFO] File read failures: {file_read_failures}")
    print(f"[INFO] Parse failures: {parse_failures}")
    print(f"[INFO] Train benign rows: {len(train_rows)}")
    print(f"[INFO] Val benign rows: {val_label_counts.get('benign', 0)}")
    print(f"[INFO] Val anomaly rows: {val_label_counts.get('anomaly', 0)}")
    for event_id, count in event_id_counts.most_common():
        print(f"[INFO] raw event_id={event_id}: {count}")
    for event_type, count in normalized_event_type_counts.most_common():
        print(f"[INFO] normalized event_type={event_type}: {count}")
    for event_id in (4624, 4625, 4648, 4672):
        print(
            f"[INFO] auth event_id={event_id} "
            f"extracted={auth_extracted_counts.get(event_id, 0)} "
            f"benign={auth_benign_counts.get(event_id, 0)} "
            f"anomaly={auth_anomaly_counts.get(event_id, 0)} "
            f"excluded={auth_excluded_counts.get(event_id, 0)}"
        )
        for reason, count in auth_excluded_reason_counts[event_id].most_common():
            print(f"[INFO] auth event_id={event_id} excluded_reason={reason}: {count}")
    for file_name, count in auth_candidate_file_counts.most_common():
        print(f"[INFO] auth_candidate_file={file_name}: {count}")
    print_event_distribution(labeled_rows)
    print(f"[INFO] Train file: {TRAIN_PATH}")
    print(f"[INFO] Validation file: {VAL_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
