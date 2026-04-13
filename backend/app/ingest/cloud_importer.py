import json
from pathlib import Path
import urllib.request

API_URL = "http://127.0.0.1:8000/events"

def post_event(event: dict):
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8")

def main():
    logs_dir = Path(__file__).resolve().parents[3] / "data" / "cloud_logs"
    files = sorted(logs_dir.glob("cloudtrail_like_*.json"))

    if not files:
        print("[ERROR] No cloud log files found. Run cloud_generator.py first.")
        return

    latest = files[-1]
    events = json.loads(latest.read_text(encoding="utf-8"))

    ok = 0
    for e in events:
        try:
            post_event(e)
            ok += 1
        except Exception as ex:
            print(f"[WARN] Failed: {e.get('event_type')} - {ex}")

    print(f"[OK] Imported {ok}/{len(events)} events from {latest.name}")

if __name__ == "__main__":
    main()
