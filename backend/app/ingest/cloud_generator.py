import json
import random
from datetime import datetime, timedelta
from pathlib import Path

# CloudTrail-like event names (realistic-ish)
EVENT_TYPES = [
    "iam_policy_change",
    "iam_user_created",
    "bucket_public_enabled",
    "security_group_open_all",
    "login_fail",
    "new_location_login",
    "normal_activity",
]

USERS = ["admin", "dev-user", "intern", "ops", "auditor"]
IPS = ["203.0.113.10", "198.51.100.22", "192.0.2.44", "10.0.0.15", "172.16.1.9"]
RESOURCES = [
    "policy/AllowAll",
    "iam/user/new-user",
    "s3://project-logs-bucket",
    "sg-0000openall",
    "console-login",
]

def generate_events(n: int = 40):
    base_time = datetime.utcnow() - timedelta(hours=2)
    events = []

    for i in range(n):
        et = random.choice(EVENT_TYPES)
        actor = random.choice(USERS)
        ip = random.choice(IPS)
        resource = random.choice(RESOURCES)

        # increasing timestamps
        ts = base_time + timedelta(minutes=i * random.randint(1, 3))

        events.append(
            {
                "source": "cloud",
                "event_type": et,
                "actor": actor,
                "ip": ip,
                "resource": resource,
                # keep as ISO time; your DB uses its own timestamp too
                "timestamp": ts.isoformat() + "Z",
            }
        )
    return events

def main():
    # points to: .../isms/data/cloud_logs
    out_dir = Path(__file__).resolve().parents[3] / "data" / "cloud_logs"
    out_dir.mkdir(parents=True, exist_ok=True)

    events = generate_events(40)

    out_file = out_dir / f"cloudtrail_like_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(events, indent=2), encoding="utf-8")

    print(f"[OK] Generated {len(events)} events")
    print(f"[OK] Saved to: {out_file}")

if __name__ == "__main__":
    main()
