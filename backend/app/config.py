from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
APP_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")

db_file = BACKEND_DIR / "isms.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")

FIREWALL_LOG = os.getenv(
    "FIREWALL_LOG",
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
CLOUD_POLL_INTERVAL_SECONDS = int(os.getenv("CLOUD_POLL_INTERVAL_SECONDS", "45"))

DATA_DIR = BACKEND_DIR / "data"
CLOUD_DATA_DIR = DATA_DIR / "cloud_logs"
CLOUD_DATA_DIR.mkdir(parents=True, exist_ok=True)

CLOUD_STATE_FILE = Path(
    os.getenv("CLOUD_STATE_FILE", str(CLOUD_DATA_DIR / "cloudtrail_state.json"))
)
