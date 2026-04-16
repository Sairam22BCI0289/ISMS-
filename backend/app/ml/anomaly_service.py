"""Anomaly scoring service for network and host events."""

import json
from collections import deque
from datetime import datetime, timedelta, timezone

from app.ml.features import (
    BEHAVIOR_EVENT_IDS,
    extract_host_behavior_features,
    extract_host_features,
    extract_network_features,
)
from app.ml.model_registry import (
    get_host_auth_model,
    get_host_behavior_model,
    get_live_ocsvm_network_model,
    load_network_iforest,
    load_network_iforest_meta,
)

HOST_AUTH_EVENT_IDS = {4624, 4625, 4648, 4672}
HOST_FUSION_WINDOW = timedelta(minutes=5)
HOST_FUSION_MAX_EVENTS = 500
HOST_FUSION_PROFILES = {"host_auth", "host_behavior"}
HOST_AUTH_FUSION_WEIGHT = 0.7
HOST_BEHAVIOR_FUSION_WEIGHT = 0.3
NETWORK_IFOREST_FUSION_WEIGHT = 0.7
NETWORK_OCSVM_FUSION_WEIGHT = 0.3
_HOST_RISK_WINDOW = deque(maxlen=HOST_FUSION_MAX_EVENTS)


def _default_result() -> dict:
    return {
        "anomaly_score": None,
        "anomaly_risk_10": None,
        "anomaly_risk_10_svm": None,
        "anomaly_label": None,
        "anomaly_score_svm": None,
        "anomaly_label_svm": None,
        "anomaly_model": None,
        "anomaly_source_profile": None,
        "host_auth_risk": None,
        "host_behavior_risk": None,
        "host_multilayer_risk": None,
        "network_multilayer_risk": None,
    }


def _valid_features(features: object) -> bool:
    if not isinstance(features, list) or not features:
        return False
    return all(isinstance(value, (int, float)) for value in features)


def _as_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_raw(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        value = raw.strip()
        if value.startswith("{") and value.endswith("}"):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
    return {}


def _parse_event_time(value: object) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text) if text else datetime.now(timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)

    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _safe_identity(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if not text or text in {"-", ":", "unknown", "none", "null", "n/a"}:
        return None
    return text


def _host_context(event: dict) -> dict:
    raw = _parse_raw(event.get("raw"))
    actor = _safe_identity(event.get("actor"))
    host = (
        _safe_identity(raw.get("computer_name"))
        or _safe_identity(raw.get("ComputerName"))
        or _safe_identity(raw.get("computer"))
        or _safe_identity(event.get("resource"))
        or _safe_identity(event.get("ip"))
    )
    return {"actor": actor, "host": host}


def _same_host_context(left: dict, right: dict) -> bool:
    if left.get("actor") and left.get("actor") == right.get("actor"):
        return True
    if left.get("host") and left.get("host") == right.get("host"):
        return True
    return False


def _prune_host_risk_window(now: datetime) -> None:
    cutoff = now - HOST_FUSION_WINDOW
    while _HOST_RISK_WINDOW and _HOST_RISK_WINDOW[0]["timestamp"] < cutoff:
        _HOST_RISK_WINDOW.popleft()


def _latest_host_layer_risk(
    event_time: datetime,
    context: dict,
    profile: str,
) -> float | None:
    for record in reversed(_HOST_RISK_WINDOW):
        if record.get("profile") != profile:
            continue
        if not _same_host_context(context, record):
            continue
        delta = abs(event_time - record["timestamp"])
        if delta <= HOST_FUSION_WINDOW:
            return record.get("risk")
    return None


def _remember_host_layer_risk(
    event_time: datetime,
    context: dict,
    profile: str,
    risk: float,
) -> None:
    _HOST_RISK_WINDOW.append({
        "timestamp": event_time,
        "profile": profile,
        "risk": risk,
        "actor": context.get("actor"),
        "host": context.get("host"),
    })


def _normalize_host_fusion_weights(auth_weight: float, behavior_weight: float) -> tuple[float, float]:
    total = auth_weight + behavior_weight
    if total <= 0:
        return HOST_AUTH_FUSION_WEIGHT, HOST_BEHAVIOR_FUSION_WEIGHT
    return auth_weight / total, behavior_weight / total


def _host_fusion_weights(event: dict, auth_risk: float, behavior_risk: float) -> tuple[float, float]:
    auth_weight = HOST_AUTH_FUSION_WEIGHT
    behavior_weight = HOST_BEHAVIOR_FUSION_WEIGHT
    event_id = _event_id_from_event(event)

    if event_id == 4672:
        auth_weight, behavior_weight = 0.8, 0.2
    elif event_id in BEHAVIOR_EVENT_IDS and behavior_risk >= 8.0 and behavior_risk > auth_risk:
        auth_weight, behavior_weight = 0.45, 0.55
    elif event_id in HOST_AUTH_EVENT_IDS and auth_risk >= 8.0 and auth_risk > behavior_risk:
        auth_weight, behavior_weight = 0.8, 0.2

    return _normalize_host_fusion_weights(auth_weight, behavior_weight)


def _weighted_host_multilayer_risk(auth_risk: float, behavior_risk: float, event: dict) -> float:
    auth_weight, behavior_weight = _host_fusion_weights(event, auth_risk, behavior_risk)
    return round((auth_weight * auth_risk) + (behavior_weight * behavior_risk), 1)


def _weighted_network_multilayer_risk(iforest_risk: float | None, svm_risk: float | None) -> float | None:
    if iforest_risk is None and svm_risk is None:
        return None
    if iforest_risk is None:
        return svm_risk
    if svm_risk is None:
        return iforest_risk
    return round(
        (NETWORK_IFOREST_FUSION_WEIGHT * iforest_risk)
        + (NETWORK_OCSVM_FUSION_WEIGHT * svm_risk),
        1,
    )


def _apply_host_multilayer_fusion(event: dict, result: dict) -> dict:
    profile = result.get("anomaly_source_profile")
    risk = _as_float(result.get("anomaly_risk_10"))

    if profile not in HOST_FUSION_PROFILES or risk is None:
        result["host_multilayer_risk"] = None
        return result

    event_time = _parse_event_time(event.get("timestamp"))
    context = _host_context(event)
    _prune_host_risk_window(event_time)

    counterpart_profile = "host_behavior" if profile == "host_auth" else "host_auth"
    counterpart_risk = _latest_host_layer_risk(event_time, context, counterpart_profile)
    if profile == "host_auth":
        result["host_auth_risk"] = risk
        result["host_behavior_risk"] = counterpart_risk
    else:
        result["host_auth_risk"] = counterpart_risk
        result["host_behavior_risk"] = risk

    if counterpart_risk is not None:
        if profile == "host_auth":
            auth_risk, behavior_risk = risk, counterpart_risk
        else:
            auth_risk, behavior_risk = counterpart_risk, risk
        result["host_multilayer_risk"] = _weighted_host_multilayer_risk(
            auth_risk=auth_risk,
            behavior_risk=behavior_risk,
            event=event,
        )
    else:
        result["host_multilayer_risk"] = None

    _remember_host_layer_risk(event_time, context, profile, risk)
    return result


def _interpolate(
    score: float,
    lower_score: float,
    upper_score: float,
    lower_risk: float,
    upper_risk: float,
) -> float:
    if upper_score <= lower_score:
        return upper_risk
    ratio = (score - lower_score) / (upper_score - lower_score)
    return lower_risk + ((upper_risk - lower_risk) * ratio)


def _score_to_risk_10(score: float, metadata: dict | None) -> float | None:
    if not isinstance(metadata, dict):
        return None

    min_score = _as_float(metadata.get("min"))
    q01 = _as_float(metadata.get("q01"))
    q05 = _as_float(metadata.get("q05"))
    q10 = _as_float(metadata.get("q10"))
    q50 = _as_float(metadata.get("q50"))

    if None in {min_score, q01, q05, q10, q50}:
        return None

    if score >= q50:
        risk = 0.0
    elif score >= q10:
        risk = _interpolate(score, q10, q50, 5.0, 2.0)
    elif score >= q05:
        risk = _interpolate(score, q05, q10, 7.0, 5.0)
    elif score >= q01:
        risk = _interpolate(score, q01, q05, 9.0, 7.0)
    elif score <= min_score:
        risk = 10.0
    else:
        risk = _interpolate(score, min_score, q01, 10.0, 9.0)

    return round(max(0.0, min(10.0, risk)), 1)


def _event_id_from_event(event: dict) -> int:
    raw = event.get("raw")
    if isinstance(raw, dict):
        try:
            return int(raw.get("event_id"))
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


def _score_iforest_event(
    event: dict,
    model,
    metadata: dict | None,
    features: list[float],
    model_name: str,
    source_profile: str,
) -> dict:
    default = _default_result()

    if model is None:
        return default

    if not _valid_features(features):
        return default

    score_values = model.decision_function([features])
    score = float(score_values[0])
    return {
        "anomaly_score": score,
        "anomaly_risk_10": _score_to_risk_10(score, metadata),
        "anomaly_risk_10_svm": None,
        "anomaly_label": "anomalous" if score < 0 else "normal",
        "anomaly_score_svm": None,
        "anomaly_label_svm": None,
        "anomaly_model": model_name,
        "anomaly_source_profile": source_profile,
        "host_auth_risk": None,
        "host_behavior_risk": None,
        "host_multilayer_risk": None,
        "network_multilayer_risk": None,
    }


def _score_host_event(event: dict) -> dict:
    event_id = _event_id_from_event(event)

    if event_id in BEHAVIOR_EVENT_IDS:
        assets = get_host_behavior_model()
        result = _score_iforest_event(
            event=event,
            model=assets.get("model"),
            metadata=assets.get("meta"),
            features=extract_host_behavior_features(event),
            model_name="iforest_host_behavior_v1",
            source_profile="host_behavior",
        )
        return _apply_host_multilayer_fusion(event, result)

    if event_id in HOST_AUTH_EVENT_IDS:
        assets = get_host_auth_model()
        result = _score_iforest_event(
            event=event,
            model=assets.get("model"),
            metadata=assets.get("meta"),
            features=extract_host_features(event),
            model_name="iforest_host_auth_v1",
            source_profile="host_auth",
        )
        return _apply_host_multilayer_fusion(event, result)

    return _default_result()


def _score_network_event(event: dict) -> dict:
    default = _default_result()

    model = load_network_iforest()
    metadata = load_network_iforest_meta()
    svm_assets = get_live_ocsvm_network_model()
    svm_model = svm_assets.get("model")
    svm_scaler = svm_assets.get("scaler")
    svm_metadata = svm_assets.get("meta")
    if model is None:
        return default

    features = extract_network_features(event)
    if not _valid_features(features):
        return default

    score_values = model.decision_function([features])
    score = float(score_values[0])
    anomaly_risk_10 = _score_to_risk_10(score, metadata)
    if_label = "anomalous" if score < 0 else "normal"
    svm_score = None
    anomaly_risk_10_svm = None
    svm_label = None
    final_label = if_label
    anomaly_model = "iforest_network_v1"

    if svm_model is not None and svm_scaler is not None:
        svm_features = svm_scaler.transform([features])
        svm_score_values = svm_model.decision_function(svm_features)
        svm_score = float(svm_score_values[0])
        anomaly_risk_10_svm = _score_to_risk_10(svm_score, svm_metadata)
        svm_prediction = int(svm_model.predict(svm_features)[0])
        svm_label = "anomalous" if svm_prediction == -1 else "normal"
        final_label = "anomalous" if (if_label == "anomalous" or svm_label == "anomalous") else "normal"
        anomaly_model = "iforest+ocsvm_network_v1"

    return {
        "anomaly_score": score,
        "anomaly_risk_10": anomaly_risk_10,
        "anomaly_risk_10_svm": anomaly_risk_10_svm,
        "anomaly_label": final_label,
        "anomaly_score_svm": svm_score,
        "anomaly_label_svm": svm_label,
        "anomaly_model": anomaly_model,
        "anomaly_source_profile": "network",
        "host_auth_risk": None,
        "host_behavior_risk": None,
        "host_multilayer_risk": None,
        "network_multilayer_risk": _weighted_network_multilayer_risk(
            anomaly_risk_10,
            anomaly_risk_10_svm,
        ),
    }


def score_event(event: dict) -> dict:
    """Score supported events with the trained anomaly models when available."""
    default = _default_result()

    try:
        if not isinstance(event, dict):
            return default

        source = str(event.get("source") or "").strip().lower()
        if source == "network":
            return _score_network_event(event)
        if source == "host":
            return _score_host_event(event)
        return default
    except Exception:
        return default
