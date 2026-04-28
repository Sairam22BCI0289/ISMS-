import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, Any

from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.alerts.emailer import maybe_send_event_alert
from app.db.models import SecurityEvent
from app.ml.anomaly_service import score_event

HIGH_RISK_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 6379, 9200}
HOST_FUTURE_SKEW_THRESHOLD = timedelta(minutes=30)
HOST_FAILED_LOGIN_WINDOW = timedelta(seconds=10)
HOST_FAILED_LOGIN_THRESHOLD = 5
USB_EVENT_IDS = {6416, 20001, 20003, 2100}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
CLOUD_IAM_HIGH_SEVERITY_EVENTS = {"CreateUser", "DeleteUser"}
CLOUD_IAM_MEDIUM_SEVERITY_EVENTS = {"CreateRole", "DeleteRole"}
NETWORK_RULES_BY_EVENT_TYPE = {
    "net_conn_high_risk": (
        "NET_CONN_HIGH_RISK",
        "high",
        "NET_CONN_HIGH_RISK: high-risk remote port detected",
    ),
    "net_listener_open": (
        "NET_LISTENER_OPEN",
        "medium",
        "NET_LISTENER_OPEN: listening port detected",
    ),
    "net_conn_allowed": (
        "NET_CONN_ALLOWED",
        "low",
        "NET_CONN_ALLOWED: allowed network connection observed",
    ),
    "net_conn_blocked": (
        "NET_CONN_BLOCKED",
        "low",
        "NET_CONN_BLOCKED: blocked network connection observed",
    ),
}


def _as_dict(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                return json.loads(s)
            except Exception:
                return {}
    return {}


def _coerce_rules(rt: Any) -> List[str]:
    if rt is None:
        return []
    if isinstance(rt, list):
        return [str(x) for x in rt]
    if isinstance(rt, str):
        st = rt.strip()
        if st.startswith("[") and st.endswith("]"):
            try:
                arr = json.loads(st)
                if isinstance(arr, list):
                    return [str(x) for x in arr]
            except Exception:
                pass
        return [rt]
    return [str(rt)]


def _event_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text) if text else datetime.now(timezone.utc)
    except Exception:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _identity_text(value: Any) -> Optional[str]:
    text = str(value or "").strip().lower()
    if not text or text in {"-", ":", "unknown", "none", "null", "n/a"}:
        return None
    return text


def _same_actor_or_ip(row: SecurityEvent, actor: Any, ip: Any) -> bool:
    actor_text = _identity_text(actor)
    ip_text = _identity_text(ip)
    return (
        bool(actor_text and _identity_text(row.actor) == actor_text)
        or bool(ip_text and _identity_text(row.ip) == ip_text)
    )


def _append_rule(rules: List[str], rule: str) -> None:
    if rule not in rules:
        rules.append(rule)


def _severity_at_least(current: Optional[str], minimum: str) -> str:
    current_text = (current or "low").lower().strip()
    minimum_text = minimum.lower().strip()
    if SEVERITY_RANK.get(current_text, 0) >= SEVERITY_RANK.get(minimum_text, 0):
        return current_text
    return minimum_text


def _append_reason(reason: Optional[str], addition: str) -> str:
    reason_text = str(reason or "").strip()
    if not reason_text:
        return addition
    if addition in reason_text:
        return reason_text
    return f"{reason_text}; {addition}"


def _host_event_id(event: dict, raw_obj: dict) -> int:
    try:
        return int(raw_obj.get("event_id"))
    except Exception:
        pass

    event_type = str(event.get("event_type") or "").strip().lower()
    if event_type == "win_login_success":
        return 4624
    if event_type == "win_login_failed":
        return 4625
    if event_type.startswith("win_event_"):
        try:
            return int(event_type.replace("win_event_", "", 1))
        except Exception:
            return 0
    return 0


def _cloudtrail_event_name(raw_obj: dict) -> str:
    event_name = raw_obj.get("EventName") or raw_obj.get("eventName")
    if event_name:
        return str(event_name).strip()

    cloudtrail_obj = raw_obj.get("CloudTrailEvent")
    if isinstance(cloudtrail_obj, str):
        cloudtrail_obj = _as_dict(cloudtrail_obj)
    if isinstance(cloudtrail_obj, dict):
        event_name = cloudtrail_obj.get("eventName") or cloudtrail_obj.get("EventName")
        if event_name:
            return str(event_name).strip()

    return ""


def _recent_failed_login_count(db: Session, event: dict, ts: datetime) -> int:
    actor = event.get("actor")
    ip = event.get("ip")
    if not _identity_text(actor) and not _identity_text(ip):
        return 0

    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.source == "host")
        .filter(SecurityEvent.event_type == "win_login_failed")
        .filter(SecurityEvent.timestamp >= ts - HOST_FAILED_LOGIN_WINDOW)
        .filter(SecurityEvent.timestamp <= ts)
        .all()
    )
    return sum(1 for row in rows if _same_actor_or_ip(row, actor, ip))


def _raw_text_contains(raw_obj: dict, needles: tuple[str, ...]) -> bool:
    values: List[str] = []
    for key in (
        "process_name",
        "ProcessName",
        "NewProcessName",
        "CommandLine",
        "ProcessCommandLine",
        "command_line",
    ):
        value = raw_obj.get(key)
        if value not in (None, ""):
            values.append(str(value))

    inserts = raw_obj.get("string_inserts")
    if isinstance(inserts, list):
        values.extend(str(value) for value in inserts if value not in (None, ""))

    haystack = " ".join(values).lower()
    return any(needle in haystack for needle in needles)


def _is_whoami_execution(raw_obj: dict) -> bool:
    return _raw_text_contains(raw_obj, ("whoami",))


def _is_usb_insert_event(event: dict, raw_obj: dict) -> bool:
    event_type = str(event.get("event_type") or "").strip().lower()
    event_id = _host_event_id(event, raw_obj)
    if event_type == "win_usb_inserted" or event_id == 6416:
        return True
    if event_id not in USB_EVENT_IDS:
        return False
    return _raw_text_contains(raw_obj, ("usb", "usbstor", "vid_", "pid_", "removable"))


def apply_rule_enrichment(
    db: Session,
    event: dict,
    severity: Optional[str],
    reason: Optional[str],
    rules_list: List[str],
) -> Tuple[Optional[str], Optional[str], List[str]]:
    src = (event.get("source") or "").lower().strip()
    event_type = str(event.get("event_type") or "").strip()

    if src == "network":
        rule_info = NETWORK_RULES_BY_EVENT_TYPE.get(event_type)
        if rule_info:
            rule_name, minimum_severity, reason_text = rule_info
            _append_rule(rules_list, rule_name)
            severity = _severity_at_least(severity, minimum_severity)
            reason = _append_reason(reason, reason_text)
        return severity, reason, rules_list

    if src != "host":
        return severity, reason, rules_list

    raw_obj = _as_dict(event.get("raw"))
    event_id = _host_event_id(event, raw_obj)
    ts = _event_timestamp(event.get("timestamp"))

    if event_type == "win_login_failed":
        failed_count = _recent_failed_login_count(db, event, ts) + 1
        if failed_count >= HOST_FAILED_LOGIN_THRESHOLD:
            _append_rule(rules_list, "HOST_MULTIPLE_FAILED_LOGIN_ATTEMPTS")
            severity = _severity_at_least(severity, "high")
            reason = _append_reason(
                reason,
                f"HOST_MULTIPLE_FAILED_LOGIN_ATTEMPTS: {failed_count} failed logins within 10 seconds",
            )

    if event_type == "win_login_success":
        failed_count = _recent_failed_login_count(db, event, ts)
        if failed_count >= HOST_FAILED_LOGIN_THRESHOLD:
            _append_rule(rules_list, "HOST_SUCCESSFUL_LOGIN_AFTER_MULTIPLE_FAILURES")
            severity = _severity_at_least(severity, "high")
            reason = _append_reason(
                reason,
                f"HOST_SUCCESSFUL_LOGIN_AFTER_MULTIPLE_FAILURES: success after {failed_count} recent failed logins",
            )

    if event_id == 4688 and _is_whoami_execution(raw_obj):
        _append_rule(rules_list, "HOST_WHOAMI_EXECUTION")
        severity = _severity_at_least(severity, "medium")
        reason = _append_reason(
            reason,
            "HOST_WHOAMI_EXECUTION: whoami command execution detected",
        )

    if _is_usb_insert_event(event, raw_obj):
        _append_rule(rules_list, "HOST_USB_INSERTED")
        severity = _severity_at_least(severity, "medium")
        reason = _append_reason(
            reason,
            "HOST_USB_INSERTED: USB or external device insertion event detected",
        )

    return severity, reason, rules_list


def infer_severity_and_reason(event: dict) -> Tuple[str, str]:
    src = (event.get("source") or "").lower().strip()
    et = (event.get("event_type") or "").strip()

    raw_obj = _as_dict(event.get("raw"))

    if src == "cloud":
        if et == "cloud_iam_change":
            event_name = _cloudtrail_event_name(raw_obj)
            if event_name in CLOUD_IAM_HIGH_SEVERITY_EVENTS:
                return "high", f"CLOUD_RULE: {event_name} -> high"
            if event_name in CLOUD_IAM_MEDIUM_SEVERITY_EVENTS:
                return "medium", f"CLOUD_RULE: {event_name} -> medium"

        if et in {
            "cloud_policy_change",
            "cloud_key_management",
            "cloud_network_change",
        }:
            return "high", f"CLOUD_RULE: {et} -> high"

        if et in {
            "cloud_auth_failed",
            "cloud_role_assumption",
            "cloud_resource_delete",
            "cloud_identity_activity",
            "cloud_audit_activity",
        }:
            return "medium", f"CLOUD_RULE: {et} -> medium"

        if et in {
            "cloud_auth_success",
            "cloud_iam_change",
            "cloud_resource_create",
            "cloud_storage_access",
            "cloud_compute_activity",
            "cloud_notification_activity",
            "cloud_service_activity",
        }:
            return "low", f"CLOUD_RULE: {et} -> low"

        if et == "cloud_other":
            event_source = ""
            try:
                event_source = (
                    raw_obj.get("CloudTrailEvent", {})
                    .get("eventSource", "")
                    .lower()
                )
            except Exception:
                event_source = ""

            if event_source in {
                "iam.amazonaws.com",
                "signin.amazonaws.com",
                "sts.amazonaws.com",
                "cloudtrail.amazonaws.com",
                "config.amazonaws.com",
            }:
                return "medium", f"CLOUD_RULE: {et} with sensitive source {event_source} -> medium"

            return "low", "CLOUD_RULE: cloud_other default -> low"

        return "low", "CLOUD_RULE: default -> low"

    if src == "host":
        if et == "win_login_failed":
            return "high", "HOST_RULE: win_login_failed -> high"

        if et in {"win_event_4672", "win_event_4648"}:
            return "medium", f"HOST_RULE: {et} -> medium"

        if et in {"win_login_success", "win_event_4634"}:
            return "low", f"HOST_RULE: {et} -> low"

        return "low", "HOST_RULE: default -> low"

    if src == "network":
        if et == "net_conn_high_risk":
            return "high", "NET_RULE: high-risk remote port -> high"

        if et == "net_listener_open":
            return "medium", "NET_RULE: listener open -> medium"

        if et in {"net_conn_allowed", "net_conn_blocked"}:
            return "low", f"NET_RULE: {et} -> low"

        return "low", "NET_RULE: default -> low"

    return "low", "DEFAULT_RULE: unknown source -> low"


def find_existing_event(db: Session, event: dict):
    source = (event.get("source") or "").strip().lower()
    raw_obj = _as_dict(event.get("raw"))
    timestamp = event.get("timestamp")

    if source == "host":
        channel = raw_obj.get("channel")
        record_number = raw_obj.get("record_number")
        if channel and record_number is not None and timestamp is not None:
            return (
                db.query(SecurityEvent)
                .filter(SecurityEvent.source == "host")
                .filter(SecurityEvent.timestamp == timestamp)
                .filter(SecurityEvent.resource == event.get("resource"))
                .filter(SecurityEvent.raw.contains(f'"record_number": {record_number}'))
                .first()
            )

    if source == "cloud":
        event_id = raw_obj.get("EventId")
        if event_id:
            return (
                db.query(SecurityEvent)
                .filter(SecurityEvent.source == "cloud")
                .filter(SecurityEvent.raw.contains(f'"EventId": "{event_id}"'))
                .first()
            )

    return None


def fix_future_host_timestamps(db: Session) -> int:
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold = now_utc + HOST_FUTURE_SKEW_THRESHOLD
    local_offset = datetime.now().astimezone().utcoffset()

    if not local_offset:
        return 0

    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.source == "host")
        .filter(SecurityEvent.timestamp > threshold)
        .all()
    )

    for row in rows:
        row.timestamp = row.timestamp - local_offset

    if rows:
        db.commit()

    return len(rows)


def create_event(db: Session, event: dict):
    severity = event.get("severity")
    reason = event.get("severity_reason")

    if not severity or not reason:
        sev, why = infer_severity_and_reason(event)
        severity = severity or sev
        reason = reason or why

    rules_list = _coerce_rules(event.get("rules_triggered"))
    severity, reason, rules_list = apply_rule_enrichment(db, event, severity, reason, rules_list)
    rules_json = json.dumps(rules_list, ensure_ascii=False)

    raw_val = event.get("raw")
    if isinstance(raw_val, str):
        raw_str = raw_val
    else:
        raw_str = json.dumps(
            raw_val if raw_val is not None else event,
            ensure_ascii=False,
            default=str
        )

    existing = find_existing_event(db, {**event, "raw": raw_val})
    if existing is not None:
        return existing

    anomaly_result = score_event({
        "source": event.get("source"),
        "event_type": event.get("event_type"),
        "timestamp": event.get("timestamp"),
        "actor": event.get("actor"),
        "ip": event.get("ip"),
        "resource": event.get("resource"),
        "raw": raw_str,
    })

    obj = SecurityEvent(
        source=event.get("source") or "unknown",
        event_type=event.get("event_type") or "unknown",
        timestamp=event.get("timestamp"),
        actor=event.get("actor"),
        ip=event.get("ip"),
        resource=event.get("resource"),
        severity=(severity or "").lower().strip() if severity else None,
        anomaly_score=anomaly_result["anomaly_score"],
        anomaly_score_svm=anomaly_result["anomaly_score_svm"],
        anomaly_risk_10=anomaly_result["anomaly_risk_10"],
        anomaly_risk_10_svm=anomaly_result["anomaly_risk_10_svm"],
        host_auth_risk=anomaly_result.get("host_auth_risk"),
        host_behavior_risk=anomaly_result.get("host_behavior_risk"),
        host_multilayer_risk=anomaly_result.get("host_multilayer_risk"),
        network_multilayer_risk=anomaly_result.get("network_multilayer_risk"),
        anomaly_label=anomaly_result["anomaly_label"],
        anomaly_label_svm=anomaly_result["anomaly_label_svm"],
        anomaly_model=anomaly_result["anomaly_model"],
        anomaly_source_profile=anomaly_result["anomaly_source_profile"],
        severity_reason=reason,
        rules_triggered=rules_json,
        raw=raw_str,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    maybe_send_event_alert(obj)
    return obj


def get_events(
    db: Session,
    limit: int = 80,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
):
    query = db.query(SecurityEvent)

    if source:
        query = query.filter(SecurityEvent.source == source)

    if severity:
        query = query.filter(SecurityEvent.severity == severity)

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                SecurityEvent.actor.ilike(like),
                SecurityEvent.event_type.ilike(like),
                SecurityEvent.resource.ilike(like),
                SecurityEvent.ip.ilike(like),
            )
        )

    return query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(limit).all()
