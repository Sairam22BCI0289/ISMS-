"""Anomaly scoring service for Phase 2 network events."""

from app.ml.features import extract_network_features
from app.ml.model_registry import (
    load_network_iforest,
    load_network_iforest_meta,
    load_network_ocsvm,
)


def _default_result() -> dict:
    return {
        "anomaly_score": None,
        "anomaly_risk_10": None,
        "anomaly_label": None,
        "anomaly_score_svm": None,
        "anomaly_label_svm": None,
        "anomaly_model": None,
        "anomaly_source_profile": None,
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


def score_event(event: dict) -> dict:
    """Score network events with the trained Isolation Forest model when available."""
    default = _default_result()

    try:
        if not isinstance(event, dict):
            return default

        if str(event.get("source") or "").strip().lower() != "network":
            return default

        model = load_network_iforest()
        metadata = load_network_iforest_meta()
        svm_model = load_network_ocsvm()
        if model is None:
            return default

        features = extract_network_features(event)
        if not _valid_features(features):
            return default

        score_values = model.decision_function([features])
        score = float(score_values[0])
        anomaly_risk_10 = _score_to_risk_10(score, metadata)
        svm_score = None
        svm_label = None

        if svm_model is not None:
            svm_score_values = svm_model.decision_function([features])
            svm_score = float(svm_score_values[0])
            svm_prediction = int(svm_model.predict([features])[0])
            svm_label = "anomalous" if svm_prediction == -1 else "normal"

        return {
            "anomaly_score": score,
            "anomaly_risk_10": anomaly_risk_10,
            "anomaly_label": "anomalous" if score < 0 else "normal",
            "anomaly_score_svm": svm_score,
            "anomaly_label_svm": svm_label,
            "anomaly_model": "iforest_network_v1",
            "anomaly_source_profile": "network",
        }
    except Exception:
        return default
