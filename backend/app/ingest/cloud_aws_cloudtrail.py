from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

os.environ.pop("SSLKEYLOGFILE", None)

import boto3
import requests

from app.config import (
    API_BASE_URL,
    AWS_REGION,
    CLOUD_POLL_INTERVAL_SECONDS,
    CLOUD_STATE_FILE,
)


IAM_CHANGE_EVENTS = {
    "CreateUser", "DeleteUser", "UpdateUser",
    "CreateRole", "DeleteRole", "UpdateRole",
    "CreateGroup", "DeleteGroup", "UpdateGroup",
    "AddUserToGroup", "RemoveUserFromGroup",
    "CreateLoginProfile", "DeleteLoginProfile", "UpdateLoginProfile",
    "CreateInstanceProfile", "DeleteInstanceProfile", "AddRoleToInstanceProfile",
    "RemoveRoleFromInstanceProfile",
}

POLICY_CHANGE_EVENTS = {
    "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "DeleteUserPolicy",
    "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy", "DeleteRolePolicy",
    "AttachGroupPolicy", "DetachGroupPolicy", "PutGroupPolicy", "DeleteGroupPolicy",
    "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
    "SetDefaultPolicyVersion",
}

ROLE_ASSUMPTION_EVENTS = {
    "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "GetFederationToken", "GetSessionToken",
}

NETWORK_CHANGE_EVENTS = {
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
    "CreateSecurityGroup", "DeleteSecurityGroup",
    "ModifySecurityGroupRules", "UpdateSecurityGroupRuleDescriptionsIngress",
    "UpdateSecurityGroupRuleDescriptionsEgress",
    "CreateNetworkAcl", "DeleteNetworkAcl", "ReplaceNetworkAclAssociation",
    "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry",
    "CreateRouteTable", "DeleteRouteTable", "CreateRoute", "DeleteRoute",
    "ReplaceRoute", "ReplaceRouteTableAssociation",
}

KEY_MANAGEMENT_EVENTS = {
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "CreateKeyPair", "DeleteKeyPair",
    "CreateAlias", "DeleteAlias", "ScheduleKeyDeletion", "CancelKeyDeletion",
    "DisableKey", "EnableKey",
}

STORAGE_EVENTS = {
    "GetObject", "PutObject", "DeleteObject", "ListBucket",
    "CreateBucket", "DeleteBucket", "PutBucketAcl", "PutBucketPolicy",
    "DeleteBucketPolicy", "PutBucketPublicAccessBlock",
    "DeleteBucketPublicAccessBlock", "PutBucketEncryption",
}

AUTH_RELATED_EVENTS = {
    "ConsoleLogin", "CheckMfa", "ChangePassword", "CreateLoginProfile",
    "UpdateLoginProfile", "DeleteLoginProfile",
}

RESOURCE_CREATE_PREFIXES = (
    "Create", "Run", "Launch", "Start", "Put",
)

RESOURCE_DELETE_PREFIXES = (
    "Delete", "Terminate", "Stop", "Detach", "Revoke",
)

AUDIT_SERVICE_SOURCES = {
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
}

NOTIFICATION_SERVICE_SOURCES = {
    "notifications.amazonaws.com",
    "sns.amazonaws.com",
    "events.amazonaws.com",
    "eventbridge.amazonaws.com",
}

SERVICE_ACTIVITY_SOURCES = {
    "resource-explorer-2.amazonaws.com",
    "resiliencehub.amazonaws.com",
    "tagging.amazonaws.com",
    "support.amazonaws.com",
    "health.amazonaws.com",
    "trustedadvisor.amazonaws.com",
    "inspector2.amazonaws.com",
    "refactor-spaces.amazonaws.com",
    "pinpoint.amazonaws.com",
    "emr-containers.amazonaws.com",
    "kafka.amazonaws.com",
}

COMPUTE_ACTIVITY_SOURCES = {
    "ec2.amazonaws.com",
    "elasticloadbalancing.amazonaws.com",
    "autoscaling.amazonaws.com",
    "lambda.amazonaws.com",
    "ecs.amazonaws.com",
    "eks.amazonaws.com",
}

IDENTITY_ACTIVITY_SOURCES = {
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "signin.amazonaws.com",
    "sso.amazonaws.com",
    "identitystore.amazonaws.com",
}


def sanitize_sslkeylogfile() -> None:
    ssl_key_log = os.getenv("SSLKEYLOGFILE")
    if not ssl_key_log:
        return

    try:
        ssl_path = Path(ssl_key_log)
        parent = ssl_path.parent
        if parent and not parent.exists():
            os.environ.pop("SSLKEYLOGFILE", None)
            return

        with open(ssl_path, "a", encoding="utf-8"):
            pass
    except Exception:
        os.environ.pop("SSLKEYLOGFILE", None)


def load_state() -> Dict[str, Any]:
    path = Path(CLOUD_STATE_FILE)
    if not path.exists():
        return {"seen_event_ids": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"seen_event_ids": []}


def save_state(state: Dict[str, Any]) -> None:
    path = Path(CLOUD_STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def get_seen_event_ids(state: Dict[str, Any]) -> Set[str]:
    return set(str(x) for x in state.get("seen_event_ids", []))


def update_seen_event_ids(state: Dict[str, Any], seen_ids: Set[str], keep_last: int = 500) -> Dict[str, Any]:
    trimmed = list(sorted(seen_ids))[-keep_last:]
    state["seen_event_ids"] = trimmed
    return state


def safe_get(d: Dict[str, Any], *keys: str) -> Any:
    cur: Any = d
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def shorten_arn(value: str | None) -> str | None:
    if not value or not isinstance(value, str):
        return value
    if ":assumed-role/" in value:
        try:
            return value.split(":assumed-role/", 1)[1]
        except Exception:
            return value
    if ":user/" in value:
        try:
            return value.split(":user/", 1)[1]
        except Exception:
            return value
    if ":role/" in value:
        try:
            return value.split(":role/", 1)[1]
        except Exception:
            return value
    return value


def extract_actor(cloudtrail_event: Dict[str, Any], wrapper_event: Dict[str, Any]) -> str:
    user_identity = cloudtrail_event.get("userIdentity") or {}
    identity_type = (user_identity.get("type") or "").strip()

    session_issuer = safe_get(user_identity, "sessionContext", "sessionIssuer") or {}
    invoked_by = user_identity.get("invokedBy")
    principal_id = user_identity.get("principalId")
    username = wrapper_event.get("Username")

    actor = first_non_empty(
        user_identity.get("userName"),
        session_issuer.get("userName"),
        shorten_arn(user_identity.get("arn")),
        shorten_arn(session_issuer.get("arn")),
        username,
        invoked_by,
        principal_id,
        identity_type,
        "unknown",
    )

    actor_str = str(actor)

    if identity_type == "AssumedRole" and session_issuer.get("userName"):
        role_name = session_issuer.get("userName")
        return f"{role_name} (assumed-role)"

    if identity_type == "AWSService" and invoked_by:
        return f"{invoked_by} (service)"

    return actor_str


def extract_resource(wrapper_event: Dict[str, Any], cloudtrail_event: Dict[str, Any], event_name: str) -> str:
    resources = wrapper_event.get("Resources") or []
    request_parameters = cloudtrail_event.get("requestParameters") or {}
    response_elements = cloudtrail_event.get("responseElements") or {}
    event_source = cloudtrail_event.get("eventSource") or wrapper_event.get("EventSource") or "unknown"

    resource_names = [
        r.get("ResourceName")
        for r in resources
        if isinstance(r, dict) and r.get("ResourceName")
    ]
    resource_types = [
        r.get("ResourceType")
        for r in resources
        if isinstance(r, dict) and r.get("ResourceType")
    ]

    specific_resource = first_non_empty(
        request_parameters.get("userName"),
        request_parameters.get("roleName"),
        request_parameters.get("groupName"),
        request_parameters.get("policyArn"),
        request_parameters.get("policyName"),
        request_parameters.get("instanceId"),
        request_parameters.get("instanceIds"),
        request_parameters.get("bucketName"),
        request_parameters.get("keyId"),
        request_parameters.get("accessKeyId"),
        request_parameters.get("securityGroupId"),
        request_parameters.get("groupId"),
        request_parameters.get("groupName"),
        request_parameters.get("functionName"),
        request_parameters.get("trailName"),
        request_parameters.get("dbInstanceIdentifier"),
        request_parameters.get("loadBalancerName"),
        request_parameters.get("targetGroupArn"),
        request_parameters.get("vpcId"),
        request_parameters.get("subnetId"),
        request_parameters.get("volumeId"),
        request_parameters.get("snapshotId"),
        request_parameters.get("imageId"),
        safe_get(response_elements, "user", "userName"),
        safe_get(response_elements, "role", "roleName"),
        safe_get(response_elements, "accessKey", "accessKeyId"),
    )

    if isinstance(specific_resource, list):
        specific_resource = ", ".join(str(x) for x in specific_resource)

    if specific_resource:
        return f"{event_source} :: {specific_resource}"

    if resource_types and resource_names:
        return f"{', '.join(resource_types)} :: {', '.join(resource_names)}"

    if resource_names:
        return ", ".join(resource_names)

    if resource_types:
        return ", ".join(resource_types)

    if event_name in STORAGE_EVENTS and request_parameters.get("bucketName"):
        return f"{event_source} :: {request_parameters.get('bucketName')}"

    return event_source


def map_event_type(event_name: str, cloudtrail_event: Dict[str, Any]) -> str:
    response_elements = cloudtrail_event.get("responseElements") or {}
    error_code = str(cloudtrail_event.get("errorCode") or "").strip().lower()
    event_source = str(cloudtrail_event.get("eventSource") or "").strip().lower()
    read_only = cloudtrail_event.get("readOnly")
    source_ip = str(cloudtrail_event.get("sourceIPAddress") or "").strip().lower()
    user_agent = str(cloudtrail_event.get("userAgent") or "").strip().lower()
    invoked_by = str(safe_get(cloudtrail_event, "userIdentity", "invokedBy") or "").strip().lower()

    if event_name == "ConsoleLogin":
        login_result = str(response_elements.get("ConsoleLogin") or "").strip().lower()
        if login_result == "success":
            return "cloud_auth_success"
        return "cloud_auth_failed"

    if "accessdenied" in error_code or "failedauthentication" in error_code or "unauthorized" in error_code:
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

    if event_name in AUTH_RELATED_EVENTS:
        return "cloud_auth_success"

    if event_source in AUDIT_SERVICE_SOURCES:
        return "cloud_audit_activity"

    if event_source in NOTIFICATION_SERVICE_SOURCES:
        return "cloud_notification_activity"

    if event_source in SERVICE_ACTIVITY_SOURCES:
        return "cloud_service_activity"

    if event_source in IDENTITY_ACTIVITY_SOURCES:
        return "cloud_identity_activity"

    if event_source in COMPUTE_ACTIVITY_SOURCES:
        return "cloud_compute_activity"

    if isinstance(read_only, bool) and not read_only and event_name.startswith(RESOURCE_CREATE_PREFIXES):
        return "cloud_resource_create"

    if isinstance(read_only, bool) and not read_only and event_name.startswith(RESOURCE_DELETE_PREFIXES):
        return "cloud_resource_delete"

    if event_name.startswith(RESOURCE_CREATE_PREFIXES):
        return "cloud_resource_create"

    if event_name.startswith(RESOURCE_DELETE_PREFIXES):
        return "cloud_resource_delete"

    if event_source.endswith(".amazonaws.com"):
        if (
            invoked_by.endswith(".amazonaws.com")
            or source_ip.endswith(".amazonaws.com")
            or user_agent.endswith(".amazonaws.com")
        ):
            return "cloud_service_activity"

    return "cloud_other"


def rules_for_event_type(event_type: str, event_name: str, cloudtrail_event: Dict[str, Any]) -> List[str]:
    rules: List[str] = []

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

    if event_type == "cloud_audit_activity":
        rules.append("CLOUD_AUDIT_ACTIVITY")

    if event_type == "cloud_notification_activity":
        rules.append("CLOUD_NOTIFICATION_ACTIVITY")

    if event_type == "cloud_service_activity":
        rules.append("CLOUD_SERVICE_ACTIVITY")

    if event_type == "cloud_identity_activity":
        rules.append("CLOUD_IDENTITY_ACTIVITY")

    if event_type == "cloud_compute_activity":
        rules.append("CLOUD_COMPUTE_ACTIVITY")

    event_source = str(cloudtrail_event.get("eventSource") or "").strip().lower()
    error_code = str(cloudtrail_event.get("errorCode") or "").strip()

    if event_source == "signin.amazonaws.com":
        rules.append("CLOUD_SIGNIN_ACTIVITY")

    if event_source == "iam.amazonaws.com":
        rules.append("CLOUD_IAM_API_ACTIVITY")

    if event_source == "cloudtrail.amazonaws.com":
        rules.append("CLOUD_AUDIT_API_ACTIVITY")

    if event_source == "config.amazonaws.com":
        rules.append("CLOUD_CONFIG_ACTIVITY")

    if error_code:
        rules.append("CLOUD_API_ERROR")

    if event_name in {"CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey"}:
        rules.append("CLOUD_SENSITIVE_CREDENTIAL_EVENT")

    if event_name in {
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
    }:
        rules.append("CLOUD_SECURITY_GROUP_CHANGE")

    return sorted(set(rules))


def parse_cloudtrail_event(wrapper_event: Dict[str, Any]) -> Dict[str, Any]:
    cloudtrail_event_raw = wrapper_event.get("CloudTrailEvent", "{}")
    try:
        cloudtrail_event = json.loads(cloudtrail_event_raw)
    except Exception:
        cloudtrail_event = {}

    event_name = wrapper_event.get("EventName") or cloudtrail_event.get("eventName") or "Unknown"
    event_time = wrapper_event.get("EventTime")
    event_id = wrapper_event.get("EventId")
    username = wrapper_event.get("Username")

    actor = extract_actor(cloudtrail_event, wrapper_event)
    source_ip = cloudtrail_event.get("sourceIPAddress") or "unknown"
    resource = extract_resource(wrapper_event, cloudtrail_event, event_name)

    event_type = map_event_type(event_name, cloudtrail_event)
    rules_triggered = rules_for_event_type(event_type, event_name, cloudtrail_event)

    raw_payload = {
        "EventId": event_id,
        "EventName": wrapper_event.get("EventName"),
        "EventTime": event_time.isoformat() if hasattr(event_time, "isoformat") else str(event_time),
        "Username": username,
        "CloudTrailEvent": cloudtrail_event,
        "Resources": wrapper_event.get("Resources") or [],
    }

    return {
        "event_id": event_id,
        "source": "cloud",
        "event_type": event_type,
        "timestamp": event_time.isoformat() if hasattr(event_time, "isoformat") else datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "ip": source_ip,
        "resource": resource,
        "rules_triggered": rules_triggered,
        "raw": raw_payload,
    }


def fetch_recent_cloudtrail_events(minutes_back: int = 20, max_results: int = 50) -> List[Dict[str, Any]]:
    sanitize_sslkeylogfile()
    client = boto3.client("cloudtrail", region_name=AWS_REGION)
    start_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_back)

    response = client.lookup_events(
        StartTime=start_time,
        MaxResults=max_results,
    )
    return response.get("Events", [])


def post_event_to_backend(event_payload: Dict[str, Any]) -> bool:
    url = f"{API_BASE_URL}/events"
    try:
        response = requests.post(url, json=event_payload, timeout=15)
        if response.status_code == 200:
            print(
                f"[OK] Sent cloud event: "
                f"{event_payload.get('event_type')} | "
                f"{event_payload.get('actor')} | "
                f"{event_payload.get('resource')}"
            )
            return True
        print(f"[WARN] Backend rejected event ({response.status_code}): {response.text}")
        return False
    except Exception as exc:
        print(f"[ERROR] Could not send event to backend: {exc}")
        return False


def run_once() -> None:
    state = load_state()
    seen_ids = get_seen_event_ids(state)

    raw_events = fetch_recent_cloudtrail_events()
    print(f"[INFO] CloudTrail returned {len(raw_events)} events")

    new_count = 0
    for wrapper_event in raw_events:
        event_id = str(wrapper_event.get("EventId") or "").strip()
        if not event_id:
            continue
        if event_id in seen_ids:
            continue

        try:
            normalized = parse_cloudtrail_event(wrapper_event)
            ok = post_event_to_backend(normalized)
            if ok:
                seen_ids.add(event_id)
                new_count += 1
        except Exception as exc:
            print(f"[ERROR] Failed to process CloudTrail event {event_id}: {exc}")

    state = update_seen_event_ids(state, seen_ids)
    save_state(state)
    print(f"[INFO] New cloud events ingested: {new_count}")


def main() -> None:
    print("[INFO] ISMS CloudTrail agent started")
    print(f"[INFO] Region: {AWS_REGION}")
    print(f"[INFO] Poll interval: {CLOUD_POLL_INTERVAL_SECONDS} seconds")
    print(f"[INFO] Backend API: {API_BASE_URL}")

    while True:
        try:
            run_once()
        except Exception as exc:
            print(f"[ERROR] Cloud agent loop failed: {exc}")
        time.sleep(CLOUD_POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
