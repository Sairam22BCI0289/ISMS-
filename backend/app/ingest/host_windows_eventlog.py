from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Iterable

import requests
import win32evtlog  # type: ignore
import win32api  # type: ignore
import win32con  # type: ignore
import win32security  # type: ignore

from app.config import API_BASE_URL

POST_URL = f"{API_BASE_URL}/events"
STATE_FILE = BACKEND_DIR / "data" / "host_logs" / "host_event_state.json"
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

HOST_EVENT_TYPE_MAP = {
    4624: "win_login_success",
    4625: "win_login_failed",
    4634: "win_event_4634",
    4648: "win_event_4648",
    4672: "win_event_4672",
}

CHANNELS: tuple[str, ...] = ("Security", "System")
PRIVILEGES_TO_ENABLE: tuple[str, ...] = (
    win32con.SE_SECURITY_NAME,
    win32con.SE_BACKUP_NAME,
)


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


def map_event_type(event_id: int) -> str:
    return HOST_EVENT_TYPE_MAP.get(event_id, f"win_event_{event_id}")


def get_latest_record_number(channel: str) -> int:
    hand = win32evtlog.OpenEventLog(None, channel)
    oldest_record = win32evtlog.GetOldestEventLogRecord(hand)
    record_count = win32evtlog.GetNumberOfEventLogRecords(hand)
    if record_count <= 0:
        return 0
    return int(oldest_record + record_count - 1)


def read_new_events(channel: str, last_record_number: int):
    hand = win32evtlog.OpenEventLog(None, channel)
    collected = []
    newest_record = last_record_number
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

            src = getattr(ev, "SourceName", None) or channel
            eid = getattr(ev, "EventID", 0) & 0xFFFF

            user = None
            try:
                if ev.StringInserts and len(ev.StringInserts) > 0:
                    user = str(ev.StringInserts[0])
            except Exception:
                pass

            event_time = _to_utc_iso(getattr(ev, "TimeGenerated", None))

            collected.append(
                {
                    "source": "host",
                    "event_type": map_event_type(eid),
                    "timestamp": event_time,
                    "actor": user,
                    "ip": None,
                    "resource": f"{channel}:{src}",
                    "rules_triggered": [f"HOST_EVENT_{eid}"],
                    "raw": {
                        "channel": channel,
                        "source": src,
                        "event_id": eid,
                        "record_number": record_number,
                        "event_category": getattr(ev, "EventCategory", None),
                    },
                }
            )

            if record_number > newest_record:
                newest_record = record_number

        if reached_known_record:
            break

    collected.reverse()
    return collected, newest_record


def post_event(evt: dict):
    r = requests.post(POST_URL, json=evt, timeout=10)
    if r.status_code >= 300:
        raise RuntimeError(f"POST failed {r.status_code}: {r.text}")


def main():
    print("[INFO] Host log streamer starting (Windows Event Log -> ISMS API)")
    print(f"[INFO] Posting to: {POST_URL}")
    print("[INFO] Stop anytime with CTRL+C")

    try:
        enable_privileges(PRIVILEGES_TO_ENABLE)
        print("[INFO] Enabled Windows event log privileges for host ingestion")
    except Exception as ex:
        print(f"[WARN] Could not enable all event log privileges: {ex}")

    channels = list(CHANNELS)
    state = load_state()
    state.setdefault("last_record", {})

    for ch in channels:
        if int(state["last_record"].get(ch, 0) or 0) > 0:
            continue
        try:
            state["last_record"][ch] = get_latest_record_number(ch)
            print(f"[INFO] Primed {ch} channel at record {state['last_record'][ch]} to avoid historical backlog")
        except Exception as ex:
            print(f"[WARN] Could not prime {ch} channel: {ex}")

    save_state(state)

    while True:
        try:
            posted = 0

            for ch in channels:
                last_record = int(state["last_record"].get(ch, 0) or 0)

                try:
                    evs, newest_record = read_new_events(ch, last_record)
                    for e in evs:
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
