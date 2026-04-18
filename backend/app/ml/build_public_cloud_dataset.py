from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from app.ingest.cloud_aws_cloudtrail import (
        extract_actor as _project_extract_actor,
        extract_resource as _project_extract_resource,
        map_event_type as _project_map_event_type,
        rules_for_event_type as _project_rules_for_event_type,
    )
except Exception:
    _project_extract_actor = None
    _project_extract_resource = None
    _project_map_event_type = None
    _project_rules_for_event_type = None


BACKEND_DIR = Path(__file__).resolve().parents[2]
INPUT_DIR = BACKEND_DIR / "data" / "public_datasets" / "cloud_public" / "invictus_aws_dataset" / "CloudTrail"
OUTPUT_PATH = BACKEND_DIR / "data" / "public_datasets" / "cloud_public" / "public_cloud_normalized.jsonl"


IAM_CHANGE_EVENTS = {
    "CreateUser", "DeleteUser", "UpdateUser",
    "CreateRole", "DeleteRole", "UpdateRole",
    "AddUserToGroup", "RemoveUserFromGroup",
}
POLICY_CHANGE_EVENTS = {
    "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "DeleteUserPolicy",
    "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy", "DeleteRolePolicy",
    "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
    "SetDefaultPolicyVersion",
}
ROLE_ASSUMPTION_EVENTS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}
NETWORK_CHANGE_EVENTS = {
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
    "CreateSecurityGroup", "DeleteSecurityGroup",
}
KEY_MANAGEMENT_EVENTS = {"CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey"}
STORAGE_EVENTS = {"GetObject", "PutObject", "DeleteObject", "ListBucket", "CreateBucket", "DeleteBucket"}


def _safe_get(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _shorten_arn(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    for marker in (":assumed-role/", ":user/", ":role/"):
        if marker in value:
            return value.split(marker, 1)[1]
    return value


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except Exception:
            return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso_time(value: Any) -> str:
    dt = _parse_time(value)
    if dt is not None:
        return dt.isoformat()
    text = str(value or "").strip()
    if text:
        return text
    return datetime.now(timezone.utc).isoformat()


def _fallback_extract_actor(cloudtrail_event: dict[str, Any], wrapper_event: dict[str, Any]) -> str:
    user_identity = cloudtrail_event.get("userIdentity") or {}
    if not isinstance(user_identity, dict):
        user_identity = {}

    session_issuer = _safe_get(user_identity, "sessionContext", "sessionIssuer") or {}
    if not isinstance(session_issuer, dict):
        session_issuer = {}

    identity_type = str(user_identity.get("type") or "").strip()
    invoked_by = user_identity.get("invokedBy")
    actor = _first_non_empty(
        user_identity.get("userName"),
        session_issuer.get("userName"),
        _shorten_arn(user_identity.get("arn")),
        _shorten_arn(session_issuer.get("arn")),
        wrapper_event.get("Username"),
        invoked_by,
        user_identity.get("principalId"),
        identity_type,
        "unknown",
    )

    if identity_type == "AssumedRole" and session_issuer.get("userName"):
        return f"{session_issuer.get('userName')} (assumed-role)"
    if identity_type == "AWSService" and invoked_by:
        return f"{invoked_by} (service)"
    return str(actor)


def _fallback_extract_resource(
    wrapper_event: dict[str, Any],
    cloudtrail_event: dict[str, Any],
    event_name: str,
) -> str:
    request_parameters = cloudtrail_event.get("requestParameters") or {}
    if not isinstance(request_parameters, dict):
        request_parameters = {}

    event_source = cloudtrail_event.get("eventSource") or wrapper_event.get("EventSource") or "unknown"
    resources = wrapper_event.get("Resources") or []
    resource_names = [
        item.get("ResourceName")
        for item in resources
        if isinstance(item, dict) and item.get("ResourceName")
    ]
    resource_types = [
        item.get("ResourceType")
        for item in resources
        if isinstance(item, dict) and item.get("ResourceType")
    ]

    specific_resource = _first_non_empty(
        request_parameters.get("userName"),
        request_parameters.get("roleName"),
        request_parameters.get("groupName"),
        request_parameters.get("policyArn"),
        request_parameters.get("policyName"),
        request_parameters.get("instanceId"),
        request_parameters.get("bucketName"),
        request_parameters.get("accessKeyId"),
        request_parameters.get("securityGroupId"),
        request_parameters.get("functionName"),
        request_parameters.get("trailName"),
    )
    if isinstance(specific_resource, list):
        specific_resource = ", ".join(str(item) for item in specific_resource)
    if specific_resource:
        return f"{event_source} :: {specific_resource}"
    if resource_types and resource_names:
        return f"{', '.join(resource_types)} :: {', '.join(resource_names)}"
    if resource_names:
        return ", ".join(str(item) for item in resource_names)
    if resource_types:
        return ", ".join(str(item) for item in resource_types)
    if event_name in STORAGE_EVENTS and request_parameters.get("bucketName"):
        return f"{event_source} :: {request_parameters.get('bucketName')}"
    return str(event_source)


def _fallback_map_event_type(event_name: str, cloudtrail_event: dict[str, Any]) -> str:
    event_source = str(cloudtrail_event.get("eventSource") or "").strip().lower()
    error_code = str(cloudtrail_event.get("errorCode") or "").strip().lower()
    response_elements = cloudtrail_event.get("responseElements") or {}
    if not isinstance(response_elements, dict):
        response_elements = {}

    if event_name == "ConsoleLogin":
        result = str(response_elements.get("ConsoleLogin") or "").strip().lower()
        return "cloud_auth_success" if result == "success" else "cloud_auth_failed"
    if "accessdenied" in error_code or "unauthorized" in error_code:
        return "cloud_auth_failed"
    if event_name in IAM_CHANGE_EVENTS:
        return "cloud_iam_change"
    if event_name in POLICY_CHANGE_EVENTS:
        return "cloud_policy_change"
    if event_name in ROLE_ASSUMPTION_EVENTS:
        return "cloud_role_assumption"
    if event_name in NETWORK_CHANGE_EVENTS:
        return "cloud_network_change"
    if event_name in KEY_MANAGEMENT_EVENTS:
        return "cloud_key_management"
    if event_name in STORAGE_EVENTS or event_source == "s3.amazonaws.com":
        return "cloud_storage_access"
    if event_source == "cloudtrail.amazonaws.com":
        return "cloud_audit_activity"
    if event_source in {"iam.amazonaws.com", "sts.amazonaws.com", "signin.amazonaws.com"}:
        return "cloud_identity_activity"
    if event_source == "ec2.amazonaws.com":
        return "cloud_compute_activity"
    if event_name.startswith(("Create", "Run", "Launch", "Start", "Put")):
        return "cloud_resource_create"
    if event_name.startswith(("Delete", "Terminate", "Stop", "Detach", "Revoke")):
        return "cloud_resource_delete"
    return "cloud_other"


def _fallback_rules_for_event_type(
    event_type: str,
    event_name: str,
    cloudtrail_event: dict[str, Any],
) -> list[str]:
    rules: list[str] = []
    if event_type == "cloud_auth_failed":
        rules.append("CLOUD_AUTH_FAILURE")
    if event_type == "cloud_auth_success":
        rules.append("CLOUD_AUTH_ACTIVITY")
    if event_type == "cloud_policy_change":
        rules.append("CLOUD_POLICY_CHANGE")
    if event_type == "cloud_key_management":
        rules.append("CLOUD_KEY_ACTIVITY")
    if event_type == "cloud_network_change":
        rules.append("CLOUD_NETWORK_CHANGE")
    if event_type == "cloud_role_assumption":
        rules.append("CLOUD_ROLE_ASSUMPTION")
    if event_type == "cloud_iam_change":
        rules.append("CLOUD_IAM_CHANGE")
    if event_type == "cloud_resource_delete":
        rules.append("CLOUD_RESOURCE_DELETE")
    if event_type == "cloud_storage_access":
        rules.append("CLOUD_STORAGE_ACTIVITY")

    event_source = str(cloudtrail_event.get("eventSource") or "").strip().lower()
    error_code = str(cloudtrail_event.get("errorCode") or "").strip()
    if event_source == "signin.amazonaws.com":
        rules.append("CLOUD_SIGNIN_ACTIVITY")
    if event_source == "iam.amazonaws.com":
        rules.append("CLOUD_IAM_API_ACTIVITY")
    if event_source == "cloudtrail.amazonaws.com":
        rules.append("CLOUD_AUDIT_API_ACTIVITY")
    if error_code:
        rules.append("CLOUD_API_ERROR")
    if event_name in {"CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey"}:
        rules.append("CLOUD_SENSITIVE_CREDENTIAL_EVENT")
    return sorted(set(rules))


def _normalize_resources(raw_resources: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_resources, list):
        return []

    resources: list[dict[str, Any]] = []
    for item in raw_resources:
        if not isinstance(item, dict):
            continue
        resource_name = _first_non_empty(
            item.get("ResourceName"),
            item.get("resourceName"),
            item.get("ARN"),
            item.get("arn"),
        )
        resource_type = _first_non_empty(
            item.get("ResourceType"),
            item.get("resourceType"),
            item.get("type"),
        )
        if resource_name or resource_type:
            resources.append({
                "ResourceName": resource_name,
                "ResourceType": resource_type,
            })
    return resources


def _wrapper_for_record(record: dict[str, Any]) -> dict[str, Any]:
    user_identity = record.get("userIdentity") or {}
    if not isinstance(user_identity, dict):
        user_identity = {}

    session_issuer = _safe_get(user_identity, "sessionContext", "sessionIssuer") or {}
    if not isinstance(session_issuer, dict):
        session_issuer = {}

    username = _first_non_empty(
        user_identity.get("userName"),
        session_issuer.get("userName"),
        _shorten_arn(user_identity.get("arn")),
        user_identity.get("principalId"),
    )
    event_time = _parse_time(record.get("eventTime")) or record.get("eventTime")

    return {
        "EventId": record.get("eventID") or record.get("eventId") or record.get("event_id"),
        "EventName": record.get("eventName") or "Unknown",
        "EventSource": record.get("eventSource"),
        "EventTime": event_time,
        "Username": username,
        "Resources": _normalize_resources(record.get("resources")),
        "CloudTrailEvent": record,
    }


def _normalize_record(record: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None

    wrapper_event = _wrapper_for_record(record)
    cloudtrail_event = wrapper_event["CloudTrailEvent"]
    event_name = str(wrapper_event.get("EventName") or cloudtrail_event.get("eventName") or "Unknown")

    map_event_type = _project_map_event_type or _fallback_map_event_type
    extract_actor = _project_extract_actor or _fallback_extract_actor
    extract_resource = _project_extract_resource or _fallback_extract_resource
    rules_for_event_type = _project_rules_for_event_type or _fallback_rules_for_event_type

    event_type = map_event_type(event_name, cloudtrail_event)
    timestamp = _iso_time(wrapper_event.get("EventTime") or cloudtrail_event.get("eventTime"))
    actor = extract_actor(cloudtrail_event, wrapper_event)
    ip = cloudtrail_event.get("sourceIPAddress") or "unknown"
    resource = extract_resource(wrapper_event, cloudtrail_event, event_name)
    rules_triggered = rules_for_event_type(event_type, event_name, cloudtrail_event)

    raw_payload = {
        "EventId": wrapper_event.get("EventId"),
        "EventName": event_name,
        "EventTime": timestamp,
        "Username": wrapper_event.get("Username"),
        "EventSource": wrapper_event.get("EventSource"),
        "CloudTrailEvent": cloudtrail_event,
        "Resources": wrapper_event.get("Resources") or [],
    }

    return {
        "source": "cloud",
        "event_type": event_type,
        "timestamp": timestamp,
        "actor": actor,
        "ip": ip,
        "resource": resource,
        "rules_triggered": rules_triggered,
        "raw": raw_payload,
    }


def _records_from_file(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return []

    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        return [record for record in payload["Records"] if isinstance(record, dict)]
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]
    return []


def build_dataset() -> dict[str, Any]:
    files = sorted(INPUT_DIR.rglob("*.json")) if INPUT_DIR.exists() else []
    total_records = 0
    written_records = 0
    event_type_counts: Counter[str] = Counter()

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as out:
        for path in files:
            records = _records_from_file(path)
            total_records += len(records)

            for record in records:
                try:
                    normalized = _normalize_record(record)
                except Exception:
                    normalized = None
                if not normalized:
                    continue

                out.write(json.dumps(normalized, ensure_ascii=False, default=str) + "\n")
                event_type_counts[normalized["event_type"]] += 1
                written_records += 1

    return {
        "files_scanned": len(files),
        "total_records": total_records,
        "written_records": written_records,
        "event_type_counts": event_type_counts,
    }


def main() -> None:
    summary = build_dataset()

    print("[INFO] Public cloud dataset build complete")
    print(f"Input path: {INPUT_DIR}")
    print(f"Total files scanned: {summary['files_scanned']}")
    print(f"Total raw records seen: {summary['total_records']}")
    print(f"Total normalized records written: {summary['written_records']}")
    print(f"Output path: {OUTPUT_PATH}")
    print("Top 20 normalized event_type counts:")
    for event_type, count in summary["event_type_counts"].most_common(20):
        print(f"  {event_type}: {count}")


if __name__ == "__main__":
    main()
