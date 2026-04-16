import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, Any

from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.models import SecurityEvent
from app.ml.anomaly_service import score_event

HIGH_RISK_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 6379, 9200}
HOST_FUTURE_SKEW_THRESHOLD = timedelta(minutes=30)


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


def infer_severity_and_reason(event: dict) -> Tuple[str, str]:
    src = (event.get("source") or "").lower().strip()
    et = (event.get("event_type") or "").strip()

    raw_obj = _as_dict(event.get("raw"))

    if src == "cloud":
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
