from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import ipaddress
import time
from datetime import datetime, timezone
from typing import Dict, Set, Tuple

import psutil
import requests

from app.config import API_BASE_URL

POST_URL = f"{API_BASE_URL}/events"

SUSPICIOUS_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 6379, 9200}
LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost"}
NOISY_ALLOWED_PROCESSES = {"code.exe", "codex.exe", "python.exe", "pwsh.exe", "powershell.exe"}


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except Exception:
        return None


def is_loopback(ip: str | None) -> bool:
    if ip in LOOPBACK_IPS:
        return True
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def is_same_endpoint(local_ip: str | None, remote_ip: str | None) -> bool:
    if not local_ip or not remote_ip:
        return False
    return local_ip == remote_ip


def is_local_only_connection(local_ip: str | None, remote_ip: str | None) -> bool:
    if is_loopback(local_ip) or is_loopback(remote_ip):
        return True
    return is_same_endpoint(local_ip, remote_ip)


def is_noisy_process(proc_name: str | None) -> bool:
    return bool(proc_name and proc_name.lower() in NOISY_ALLOWED_PROCESSES)


def is_ignored_connection(local_ip, local_port, remote_ip, remote_port, proc_name, status) -> bool:
    status_norm = status.upper()

    if status_norm not in {"ESTABLISHED", "LISTEN"}:
        return True

    if status_norm == "LISTEN" and is_loopback(local_ip):
        return True

    if is_local_only_connection(local_ip, remote_ip):
        return True

    if remote_port == 8000 and (is_loopback(remote_ip) or remote_ip == local_ip):
        return True

    if local_port == 8000 and (is_loopback(local_ip) or remote_ip == local_ip):
        return True

    if status_norm == "ESTABLISHED" and remote_ip and is_noisy_process(proc_name) and remote_port in {80, 443}:
        return True

    return False


def classify_event(remote_port: int | None, status: str) -> str:
    if status.upper() == "LISTEN":
        return "net_listener_open"
    if isinstance(remote_port, int) and remote_port in SUSPICIOUS_PORTS:
        return "net_conn_high_risk"
    return "net_conn_allowed"


def build_event(conn) -> dict | None:
    try:
        laddr = conn.laddr if conn.laddr else None
        raddr = conn.raddr if conn.raddr else None
        status = str(conn.status or "UNKNOWN")

        local_ip = getattr(laddr, "ip", None) if laddr else None
        local_port = getattr(laddr, "port", None) if laddr else None
        remote_ip = getattr(raddr, "ip", None) if raddr else None
        remote_port = getattr(raddr, "port", None) if raddr else None

        pid = getattr(conn, "pid", None)
        proc_name = safe_name(pid)

        if is_ignored_connection(local_ip, local_port, remote_ip, remote_port, proc_name, status):
            return None

        event_type = classify_event(remote_port, status)

        resource = f"{local_ip}:{local_port}"
        if remote_ip or remote_port:
            resource += f" -> {remote_ip}:{remote_port}"

        raw = {
            "status": status,
            "pid": pid,
            "process_name": proc_name,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "high_risk_port": bool(isinstance(remote_port, int) and remote_port in SUSPICIOUS_PORTS),
        }

        return {
            "source": "network",
            "event_type": event_type,
            "timestamp": now_utc_iso(),
            "actor": proc_name,
            "ip": remote_ip or local_ip,
            "resource": resource,
            "rules_triggered": (
                ["NET_HIGH_RISK_PORT"]
                if isinstance(remote_port, int) and remote_port in SUSPICIOUS_PORTS
                else []
            ),
            "raw": raw,
        }
    except Exception:
        return None


def connection_key(conn) -> Tuple:
    try:
        laddr = conn.laddr if conn.laddr else None
        raddr = conn.raddr if conn.raddr else None
        status = str(conn.status or "").upper()
        pid = getattr(conn, "pid", None)
        proc_name = (safe_name(pid) or "").lower()

        if status == "LISTEN":
            return (
                "listen",
                getattr(laddr, "ip", None),
                getattr(laddr, "port", None),
                pid,
            )

        return (
            "conn",
            proc_name,
            getattr(raddr, "ip", None),
            getattr(raddr, "port", None),
            status,
        )
    except Exception:
        return ("unknown",)


def post_event(evt: dict):
    r = requests.post(POST_URL, json=evt, timeout=10)
    if r.status_code >= 300:
        raise RuntimeError(f"POST failed {r.status_code}: {r.text}")


def main():
    print("[INFO] Network agent starting (psutil connections -> ISMS API)")
    print(f"[INFO] Posting to: {POST_URL}")
    print("[INFO] Monitoring live TCP connections")
    print("[INFO] Ignoring localhost/backend self-traffic")
    print("[INFO] Stop with CTRL+C")

    seen: Set[Tuple] = set()

    while True:
        try:
            current: Dict[Tuple, dict] = {}

            for conn in psutil.net_connections(kind="tcp"):
                key = connection_key(conn)
                evt = build_event(conn)
                if evt:
                    current[key] = evt

            new_keys = [k for k in current.keys() if k not in seen]

            sent = 0
            for key in new_keys:
                evt = current[key]
                try:
                    post_event(evt)
                    sent += 1
                    print(
                        f"[OK] Sent network event: "
                        f"{evt['event_type']} | "
                        f"{evt.get('actor')} | "
                        f"{evt.get('resource')}"
                    )
                except Exception as ex:
                    print(f"[WARN] Failed to send network event: {ex}")

            seen = set(current.keys())

            if sent == 0:
                print("[INFO] No new relevant network connections in this cycle")

            time.sleep(5)

        except KeyboardInterrupt:
            print("\n[INFO] Stopped.")
            return
        except Exception as ex:
            print(f"[ERR] Unexpected network agent error: {ex}")
            time.sleep(3)


if __name__ == "__main__":
    main()
