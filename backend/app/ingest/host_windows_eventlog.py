# Duplicate host_windows_eventlog.py files found:
# - C:\Users\chini\Documents\isms\backend\app\ingest\host_windows_eventlog.py
# - C:\Users\chini\Documents\isms\backend\_codex_backups\20260412_rollback_snapshot\backend\app\ingest\host_windows_eventlog.py

print("[DEBUG] HOST_AGENT_BOOT_MARKER = V3_EXEC_CHECK")
import os
print(f"[DEBUG] RUNNING FILE PATH = {os.path.abspath(__file__)}")

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import json
import time
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Iterable

import requests
import win32evtlog  # type: ignore
import win32api  # type: ignore
import win32con  # type: ignore
import win32security  # type: ignore

from app.config import API_BASE_URL

POST_URL = f"{API_BASE_URL}/events"
HOST_AGENT_BUILD = "POST_TRACE_V2"
STATE_FILE = BACKEND_DIR / "data" / "host_logs" / "host_event_state.json"
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
STARTUP_GRACE_SECONDS = 2

HOST_EVENT_TYPE_MAP = {
    4624: "win_login_success",
    4625: "win_login_failed",
    4634: "win_event_4634",
    4648: "win_event_4648",
    4672: "win_event_4672",
    4688: "win_event_4688",
    4656: "win_event_4656",
    4663: "win_event_4663",
    10: "win_event_10",
    5156: "win_event_5156",
    6416: "win_usb_inserted",
    20001: "win_usb_inserted",
    20003: "win_usb_inserted",
    2100: "win_usb_inserted",
}

AUTH_EVENT_IDS: set[int] = {4624, 4625, 4648, 4672}
BEHAVIOR_EVENT_IDS: set[int] = {4688, 4656, 4663, 10, 5156}
USB_EVENT_IDS: set[int] = {6416, 20001, 20003, 2100}
HOST_EVENT_ALLOWLIST: set[int] = AUTH_EVENT_IDS | BEHAVIOR_EVENT_IDS | USB_EVENT_IDS

CHANNELS: tuple[str, ...] = (
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
)
PRIVILEGES_TO_ENABLE: tuple[str, ...] = (
    win32con.SE_SECURITY_NAME,
    win32con.SE_BACKUP_NAME,
)
MAX_STRING_INSERTS = 24
MAX_INSERT_LENGTH = 300
ACTOR_INSERT_INDEXES: dict[int, tuple[int, ...]] = {
    4624: (5, 1),
    4625: (5, 1),
    4634: (1,),
    4648: (5, 1),
    4672: (1,),
}
LOGON_TYPE_INSERT_INDEXES: dict[int, int] = {
    4624: 8,
    4625: 10,
    4634: 4,
}


def load_state() -> Dict[str, Any]:
    if not STATE_FILE.exists():
        return {"last_record": {}}
    try:
        raw = STATE_FILE.read_bytes()
        if not raw:
            return {"last_record": {}}
        if b"\x00" in raw:
            raise ValueError("state file contains NUL bytes")
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {"last_record": {}}


def save_state(state: Dict[str, Any]) -> None:
    tmp_path = STATE_FILE.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp_path, STATE_FILE)


def enable_privileges(privilege_names: Iterable[str]) -> None:
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
    )

    privileges = []
    for name in privilege_names:
        try:
            luid = win32security.LookupPrivilegeValue(None, name)
            privileges.append((luid, win32con.SE_PRIVILEGE_ENABLED))
        except Exception:
            continue

    if privileges:
        win32security.AdjustTokenPrivileges(token, False, privileges)


def _to_utc_iso(pytime_obj) -> str | None:
    if pytime_obj is None:
        return None

    try:
        if isinstance(pytime_obj, datetime):
            dt = pytime_obj.astimezone(timezone.utc) if pytime_obj.tzinfo else datetime.fromtimestamp(pytime_obj.timestamp(), tz=timezone.utc)
            return dt.isoformat()
    except Exception:
        pass

    try:
        if hasattr(pytime_obj, "timestamp"):
            dt = datetime.fromtimestamp(pytime_obj.timestamp(), tz=timezone.utc)
            return dt.isoformat()
    except Exception:
        pass

    try:
        dt = pytime_obj.Format()
        parsed = datetime.strptime(dt, "%a %b %d %H:%M:%S %Y")
        local_dt = parsed.astimezone()
        return local_dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def _is_before_startup(event_time_iso: str | None, startup_cutoff: datetime) -> bool:
    if not event_time_iso:
        return False
    try:
        event_dt = datetime.fromisoformat(event_time_iso)
        if event_dt.tzinfo is not None:
            event_dt = event_dt.astimezone(timezone.utc).replace(tzinfo=None)
        cutoff = startup_cutoff
        if cutoff.tzinfo is not None:
            cutoff = cutoff.astimezone(timezone.utc).replace(tzinfo=None)
        return event_dt < cutoff
    except Exception:
        return False


def _safe_text(value: Any, max_length: int = MAX_INSERT_LENGTH) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        return text[:max_length]
    return text


def _get_string_inserts(ev) -> list[str]:
    inserts = getattr(ev, "StringInserts", None) or []
    safe_inserts: list[str] = []
    for value in list(inserts)[:MAX_STRING_INSERTS]:
        text = _safe_text(value)
        if text is None:
            safe_inserts.append("")
        else:
            safe_inserts.append(text)
    return safe_inserts


def _looks_like_sid(text: str) -> bool:
    return text.upper().startswith("S-1-")


def _extract_actor(event_id: int, string_inserts: list[str]) -> str | None:
    preferred_indexes = ACTOR_INSERT_INDEXES.get(event_id, ())
    for index in preferred_indexes:
        if index < len(string_inserts):
            candidate = _safe_text(string_inserts[index])
            if candidate and not _looks_like_sid(candidate) and candidate != "-":
                return candidate

    for candidate in string_inserts:
        text = _safe_text(candidate)
        if text and not _looks_like_sid(text) and text != "-":
            return text

    return None


def _extract_source_ip(string_inserts: list[str]) -> str | None:
    for candidate in string_inserts:
        text = _safe_text(candidate)
        if not text or text in {"-", "::1", "127.0.0.1", "localhost"}:
            continue
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            continue
    return None


def _extract_logon_type(event_id: int, string_inserts: list[str]) -> int | None:
    index = LOGON_TYPE_INSERT_INDEXES.get(event_id)
    if index is not None and index < len(string_inserts):
        try:
            return int(str(string_inserts[index]).strip())
        except Exception:
            pass
    return None


def _extract_process_name(string_inserts: list[str]) -> str | None:
    for candidate in string_inserts:
        text = _safe_text(candidate)
        if not text:
            continue
        lowered = text.lower()
        if lowered.endswith((".exe", ".com", ".bat", ".cmd", ".ps1")):
            return text
    return None


def _is_usb_device_event(event_id: int, string_inserts: list[str], source_name: str | None) -> bool:
    if event_id == 6416:
        return True

    haystack = " ".join(
        text
        for text in [source_name or "", *string_inserts]
        if text
    ).lower()
    return any(token in haystack for token in ("usb", "usbstor", "vid_", "pid_", "removable"))


def map_event_type(event_id: int) -> str:
    return HOST_EVENT_TYPE_MAP.get(event_id, f"win_event_{event_id}")


def get_latest_record_number(channel: str) -> int:
    hand = win32evtlog.OpenEventLog(None, channel)
    oldest_record = win32evtlog.GetOldestEventLogRecord(hand)
    record_count = win32evtlog.GetNumberOfEventLogRecords(hand)
    if record_count <= 0:
        return 0
    return int(oldest_record + record_count - 1)


def read_new_events(channel: str, last_record_number: int, startup_cutoff: datetime):
    hand = win32evtlog.OpenEventLog(None, channel)
    collected = []
    newest_record = last_record_number
    skipped_low_value = 0
    skipped_before_startup = 0
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0) or []
        if not events:
            break

        reached_known_record = False

        for ev in events:
            record_number = int(getattr(ev, "RecordNumber", 0) or 0)
            if record_number <= last_record_number:
                reached_known_record = True
                break

            event_time = _to_utc_iso(getattr(ev, "TimeGenerated", None))
            if _is_before_startup(event_time, startup_cutoff):
                skipped_before_startup += 1
                if record_number > newest_record:
                    newest_record = record_number
                continue

            src = getattr(ev, "SourceName", None) or channel
            eid = getattr(ev, "EventID", 0) & 0xFFFF
            if eid not in HOST_EVENT_ALLOWLIST:
                skipped_low_value += 1
                if record_number > newest_record:
                    newest_record = record_number
                continue

            string_inserts = _get_string_inserts(ev)
            if eid in USB_EVENT_IDS and not _is_usb_device_event(eid, string_inserts, src):
                skipped_low_value += 1
                if record_number > newest_record:
                    newest_record = record_number
                continue

            event_type = map_event_type(eid)
            user = _extract_actor(eid, string_inserts)
            source_ip = _extract_source_ip(string_inserts)
            logon_type = _extract_logon_type(eid, string_inserts)
            process_name = _extract_process_name(string_inserts)
            computer_name = _safe_text(getattr(ev, "ComputerName", None))

            print(f"[DEBUG] Captured Windows event channel={channel} record={record_number} event_id={eid}")
            print(f"[DEBUG] Transforming host event event_id={eid} event_type={event_type}")

            collected.append(
                {
                    "source": "host",
                    "event_type": event_type,
                    "timestamp": event_time,
                    "actor": user,
                    "ip": source_ip,
                    "resource": f"{channel}:{src}",
                    "rules_triggered": [f"HOST_EVENT_{eid}"],
                    "raw": {
                        "channel": channel,
                        "source": src,
                        "event_id": eid,
                        "record_number": record_number,
                        "event_category": getattr(ev, "EventCategory", None),
                        "source_ip": source_ip,
                        "logon_type": logon_type,
                        "process_name": process_name,
                        "string_inserts": string_inserts,
                        "computer_name": computer_name,
                    },
                }
            )

            if record_number > newest_record:
                newest_record = record_number

        if reached_known_record:
            break

    collected.reverse()
    if skipped_before_startup:
        print(f"[DEBUG] Skipped {skipped_before_startup} pre-startup host event(s) from channel={channel}")
    if skipped_low_value:
        print(f"[DEBUG] Skipped {skipped_low_value} low-value host event(s) from channel={channel}")
    return collected, newest_record


def post_event(evt: dict):
    print("[DEBUG] post_event() CALLED")
    event_id = (evt.get("raw") or {}).get("event_id") if isinstance(evt.get("raw"), dict) else None
    event_type = evt.get("event_type")
    print(f"[DEBUG] post_event() entered event_id={event_id} event_type={event_type} url={POST_URL}", flush=True)
    try:
        r = requests.post(POST_URL, json=evt, timeout=10)
    except Exception as ex:
        print(f"[ERROR] POST exception event_id={event_id} event_type={event_type}: {ex}", flush=True)
        raise

    response_text = (r.text or "").replace("\n", " ")[:300]
    print(f"[DEBUG] POST response event_id={event_id} event_type={event_type} status={r.status_code}", flush=True)
    if r.status_code >= 300:
        print(f"[ERROR] POST failed event_id={event_id} event_type={event_type} status={r.status_code} body={response_text}", flush=True)
        raise RuntimeError(f"POST failed {r.status_code}: {r.text}")
    print(f"[DEBUG] POST succeeded event_id={event_id} event_type={event_type} status={r.status_code}", flush=True)


def main():
    print("[DEBUG] ENTERED MAIN() OF HOST AGENT")
    print("[INFO] Host log streamer starting (Windows Event Log -> ISMS API)")
    print(f"[DEBUG] HOST_AGENT_BUILD={HOST_AGENT_BUILD}", flush=True)
    print(f"[DEBUG] HOST_AGENT_FILE={Path(__file__).resolve()}", flush=True)
    print(f"[INFO] Posting to: {POST_URL}")
    print("[INFO] Stop anytime with CTRL+C")
    startup_cutoff = datetime.now(timezone.utc) - timedelta(seconds=STARTUP_GRACE_SECONDS)
    print(f"[INFO] Host startup cutoff: only posting events at or after {startup_cutoff.isoformat()}", flush=True)

    try:
        enable_privileges(PRIVILEGES_TO_ENABLE)
        print("[INFO] Enabled Windows event log privileges for host ingestion")
    except Exception as ex:
        print(f"[WARN] Could not enable all event log privileges: {ex}")

    channels: list[str] = []
    state = load_state()
    state.setdefault("last_record", {})

    for ch in CHANNELS:
        if int(state["last_record"].get(ch, 0) or 0) > 0:
            channels.append(ch)
            continue
        try:
            state["last_record"][ch] = get_latest_record_number(ch)
            channels.append(ch)
            print(f"[INFO] Primed {ch} channel at record {state['last_record'][ch]} to avoid historical backlog")
        except Exception as ex:
            print(f"[WARN] Could not prime {ch} channel: {ex}")

    save_state(state)

    while True:
        try:
            print("[DEBUG] ENTERING EVENT POLL LOOP")
            posted = 0

            for ch in channels:
                last_record = int(state["last_record"].get(ch, 0) or 0)

                try:
                    evs, newest_record = read_new_events(ch, last_record, startup_cutoff)
                    print(f"[DEBUG] POST_LOOP channel={ch} ready_count={len(evs)}", flush=True)
                    for e in evs:
                        event_id = (e.get("raw") or {}).get("event_id") if isinstance(e.get("raw"), dict) else None
                        event_type = e.get("event_type")
                        print(f"[DEBUG] About to POST event_id={event_id} event_type={event_type} channel={ch}", flush=True)
                        post_event(e)
                        posted += 1

                    if newest_record > last_record:
                        state["last_record"][ch] = newest_record

                except Exception as ex:
                    print(f"[WARN] Channel {ch} read/post failed: {ex}")

            save_state(state)

            if posted:
                print(f"[OK] Sent {posted} new host event(s)")
            else:
                print("[INFO] No new host events in this cycle")

            time.sleep(5)

        except KeyboardInterrupt:
            print("\n[INFO] Stopped.")
            return


if __name__ == "__main__":
    main()
