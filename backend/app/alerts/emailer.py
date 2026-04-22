from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Any


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _field(event: Any, name: str, default: str = "") -> str:
    value = getattr(event, name, default)
    if value is None:
        return default
    return str(value)


def _smtp_port() -> int | None:
    value = os.getenv("SMTP_PORT")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _email_config() -> dict[str, Any] | None:
    if not _env_bool("ALERT_EMAIL_ENABLED"):
        return None

    config = {
        "to": os.getenv("ALERT_EMAIL_TO"),
        "from": os.getenv("ALERT_EMAIL_FROM"),
        "host": os.getenv("SMTP_HOST"),
        "port": _smtp_port(),
        "username": os.getenv("SMTP_USERNAME"),
        "password": os.getenv("SMTP_PASSWORD"),
        "use_tls": _env_bool("SMTP_USE_TLS", default=True),
    }
    required = ("to", "from", "host", "port")
    if any(not config.get(key) for key in required):
        return None
    return config


def _is_email_alert_event(event: Any) -> bool:
    severity = _field(event, "severity").strip().lower()
    if severity != "high":
        return False

    anomaly_label = _field(event, "anomaly_label").strip().lower()
    anomaly_label_svm = _field(event, "anomaly_label_svm").strip().lower()
    return anomaly_label == "anomalous" or anomaly_label_svm == "anomalous"


def _message_body(event: Any) -> str:
    fields = [
        ("Event ID", _field(event, "id")),
        ("Source", _field(event, "source")),
        ("Event type", _field(event, "event_type")),
        ("Severity", _field(event, "severity")),
        ("anomaly_label", _field(event, "anomaly_label")),
        ("anomaly_label_svm", _field(event, "anomaly_label_svm")),
        ("anomaly_model", _field(event, "anomaly_model")),
        ("timestamp", _field(event, "timestamp")),
        ("actor", _field(event, "actor")),
        ("ip", _field(event, "ip")),
        ("resource", _field(event, "resource")),
        ("severity_reason", _field(event, "severity_reason")),
        ("rules_triggered", _field(event, "rules_triggered")),
    ]
    return "\n".join(f"{label}: {value or '-'}" for label, value in fields)


def maybe_send_event_alert(event: Any) -> bool:
    if not _is_email_alert_event(event):
        return False

    config = _email_config()
    if not config:
        return False

    try:
        message = EmailMessage()
        message["Subject"] = "[ISMS ALERT] High + Anomalous Event Detected"
        message["From"] = config["from"]
        message["To"] = config["to"]
        message.set_content(_message_body(event))

        with smtplib.SMTP(config["host"], config["port"], timeout=10) as smtp:
            if config["use_tls"]:
                smtp.starttls()
            if config.get("username") and config.get("password"):
                smtp.login(config["username"], config["password"])
            smtp.send_message(message)
        return True
    except Exception:
        return False
