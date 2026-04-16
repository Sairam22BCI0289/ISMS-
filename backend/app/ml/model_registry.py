"""Lightweight model and metadata loaders for anomaly detection."""

import json
from pathlib import Path

import joblib

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
NETWORK_IFOREST_PATH = MODELS_DIR / "network_isolation_forest.joblib"
NETWORK_IFOREST_META_PATH = MODELS_DIR / "network_isolation_forest_meta.json"
NETWORK_OCSVM_PATH = MODELS_DIR / "network_ocsvm.joblib"
NETWORK_OCSVM_SCALER_PATH = MODELS_DIR / "network_ocsvm_scaler.joblib"
NETWORK_OCSVM_META_PATH = MODELS_DIR / "network_ocsvm_meta.json"
NETWORK_OCSVM_CICIDS_PATH = MODELS_DIR / "network_ocsvm_cicids.joblib"
NETWORK_OCSVM_CICIDS_SCALER_PATH = MODELS_DIR / "network_ocsvm_cicids_scaler.joblib"
HOST_IFOREST_PATH = MODELS_DIR / "host_isolation_forest.joblib"
HOST_IFOREST_META_PATH = MODELS_DIR / "host_isolation_forest_meta.json"
HOST_BEHAVIOR_IFOREST_PATH = MODELS_DIR / "host_behavior_iforest.joblib"
HOST_BEHAVIOR_IFOREST_META_PATH = MODELS_DIR / "host_behavior_iforest_meta.json"
_NETWORK_IFOREST_MODEL = None
_NETWORK_IFOREST_LOAD_ATTEMPTED = False
_NETWORK_IFOREST_META = None
_NETWORK_IFOREST_META_LOAD_ATTEMPTED = False
_NETWORK_OCSVM_MODEL = None
_NETWORK_OCSVM_LOAD_ATTEMPTED = False
_NETWORK_OCSVM_SCALER = None
_NETWORK_OCSVM_SCALER_LOAD_ATTEMPTED = False
_NETWORK_OCSVM_META = None
_NETWORK_OCSVM_META_LOAD_ATTEMPTED = False
_NETWORK_OCSVM_CICIDS_MODEL = None
_NETWORK_OCSVM_CICIDS_SCALER = None
_NETWORK_OCSVM_CICIDS_LOAD_ATTEMPTED = False
_HOST_IFOREST_MODEL = None
_HOST_IFOREST_LOAD_ATTEMPTED = False
_HOST_IFOREST_META = None
_HOST_IFOREST_META_LOAD_ATTEMPTED = False
_HOST_BEHAVIOR_IFOREST_MODEL = None
_HOST_BEHAVIOR_IFOREST_LOAD_ATTEMPTED = False
_HOST_BEHAVIOR_IFOREST_META = None
_HOST_BEHAVIOR_IFOREST_META_LOAD_ATTEMPTED = False


def load_network_iforest():
    """Load and cache the trained network Isolation Forest model."""
    global _NETWORK_IFOREST_MODEL, _NETWORK_IFOREST_LOAD_ATTEMPTED

    if _NETWORK_IFOREST_LOAD_ATTEMPTED:
        return _NETWORK_IFOREST_MODEL

    _NETWORK_IFOREST_LOAD_ATTEMPTED = True

    if not NETWORK_IFOREST_PATH.exists():
        return None

    try:
        _NETWORK_IFOREST_MODEL = joblib.load(NETWORK_IFOREST_PATH)
    except Exception:
        _NETWORK_IFOREST_MODEL = None

    return _NETWORK_IFOREST_MODEL


def load_network_iforest_meta():
    """Load and cache the trained network Isolation Forest metadata."""
    global _NETWORK_IFOREST_META, _NETWORK_IFOREST_META_LOAD_ATTEMPTED

    if _NETWORK_IFOREST_META_LOAD_ATTEMPTED:
        return _NETWORK_IFOREST_META

    _NETWORK_IFOREST_META_LOAD_ATTEMPTED = True

    if not NETWORK_IFOREST_META_PATH.exists():
        return None

    try:
        with NETWORK_IFOREST_META_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        _NETWORK_IFOREST_META = data if isinstance(data, dict) else None
    except Exception:
        _NETWORK_IFOREST_META = None

    return _NETWORK_IFOREST_META


def load_network_ocsvm():
    """Load and cache the trained network One-Class SVM model."""
    global _NETWORK_OCSVM_MODEL, _NETWORK_OCSVM_LOAD_ATTEMPTED

    if _NETWORK_OCSVM_LOAD_ATTEMPTED:
        return _NETWORK_OCSVM_MODEL

    _NETWORK_OCSVM_LOAD_ATTEMPTED = True

    if not NETWORK_OCSVM_PATH.exists():
        return None

    try:
        _NETWORK_OCSVM_MODEL = joblib.load(NETWORK_OCSVM_PATH)
    except Exception:
        _NETWORK_OCSVM_MODEL = None

    return _NETWORK_OCSVM_MODEL


def load_network_ocsvm_scaler():
    """Load and cache the trained network One-Class SVM scaler."""
    global _NETWORK_OCSVM_SCALER, _NETWORK_OCSVM_SCALER_LOAD_ATTEMPTED

    if _NETWORK_OCSVM_SCALER_LOAD_ATTEMPTED:
        return _NETWORK_OCSVM_SCALER

    _NETWORK_OCSVM_SCALER_LOAD_ATTEMPTED = True

    if not NETWORK_OCSVM_SCALER_PATH.exists():
        return None

    try:
        _NETWORK_OCSVM_SCALER = joblib.load(NETWORK_OCSVM_SCALER_PATH)
    except Exception:
        _NETWORK_OCSVM_SCALER = None

    return _NETWORK_OCSVM_SCALER


def load_network_ocsvm_meta():
    """Load and cache the trained network One-Class SVM metadata."""
    global _NETWORK_OCSVM_META, _NETWORK_OCSVM_META_LOAD_ATTEMPTED

    if _NETWORK_OCSVM_META_LOAD_ATTEMPTED:
        return _NETWORK_OCSVM_META

    _NETWORK_OCSVM_META_LOAD_ATTEMPTED = True

    if not NETWORK_OCSVM_META_PATH.exists():
        return None

    try:
        with NETWORK_OCSVM_META_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        _NETWORK_OCSVM_META = data if isinstance(data, dict) else None
    except Exception:
        _NETWORK_OCSVM_META = None

    return _NETWORK_OCSVM_META


def get_live_ocsvm_network_model():
    """Load and cache the live runtime network One-Class SVM model and scaler."""
    return {
        "model": load_network_ocsvm(),
        "scaler": load_network_ocsvm_scaler(),
        "meta": load_network_ocsvm_meta(),
    }


def load_host_iforest():
    """Load and cache the trained host auth Isolation Forest model."""
    global _HOST_IFOREST_MODEL, _HOST_IFOREST_LOAD_ATTEMPTED

    if _HOST_IFOREST_LOAD_ATTEMPTED:
        return _HOST_IFOREST_MODEL

    _HOST_IFOREST_LOAD_ATTEMPTED = True

    if not HOST_IFOREST_PATH.exists():
        return None

    try:
        _HOST_IFOREST_MODEL = joblib.load(HOST_IFOREST_PATH)
    except Exception:
        _HOST_IFOREST_MODEL = None

    return _HOST_IFOREST_MODEL


def load_host_iforest_meta():
    """Load and cache the trained host auth Isolation Forest metadata."""
    global _HOST_IFOREST_META, _HOST_IFOREST_META_LOAD_ATTEMPTED

    if _HOST_IFOREST_META_LOAD_ATTEMPTED:
        return _HOST_IFOREST_META

    _HOST_IFOREST_META_LOAD_ATTEMPTED = True

    if not HOST_IFOREST_META_PATH.exists():
        return None

    try:
        with HOST_IFOREST_META_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        _HOST_IFOREST_META = data if isinstance(data, dict) else None
    except Exception:
        _HOST_IFOREST_META = None

    return _HOST_IFOREST_META


def get_host_auth_model():
    """Load and cache the host auth Isolation Forest model and metadata."""
    return {
        "model": load_host_iforest(),
        "meta": load_host_iforest_meta(),
    }


def load_host_behavior_iforest():
    """Load and cache the trained host behavior Isolation Forest model."""
    global _HOST_BEHAVIOR_IFOREST_MODEL, _HOST_BEHAVIOR_IFOREST_LOAD_ATTEMPTED

    if _HOST_BEHAVIOR_IFOREST_LOAD_ATTEMPTED:
        return _HOST_BEHAVIOR_IFOREST_MODEL

    _HOST_BEHAVIOR_IFOREST_LOAD_ATTEMPTED = True

    if not HOST_BEHAVIOR_IFOREST_PATH.exists():
        return None

    try:
        _HOST_BEHAVIOR_IFOREST_MODEL = joblib.load(HOST_BEHAVIOR_IFOREST_PATH)
    except Exception:
        _HOST_BEHAVIOR_IFOREST_MODEL = None

    return _HOST_BEHAVIOR_IFOREST_MODEL


def load_host_behavior_iforest_meta():
    """Load and cache the trained host behavior Isolation Forest metadata."""
    global _HOST_BEHAVIOR_IFOREST_META, _HOST_BEHAVIOR_IFOREST_META_LOAD_ATTEMPTED

    if _HOST_BEHAVIOR_IFOREST_META_LOAD_ATTEMPTED:
        return _HOST_BEHAVIOR_IFOREST_META

    _HOST_BEHAVIOR_IFOREST_META_LOAD_ATTEMPTED = True

    if not HOST_BEHAVIOR_IFOREST_META_PATH.exists():
        return None

    try:
        with HOST_BEHAVIOR_IFOREST_META_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        _HOST_BEHAVIOR_IFOREST_META = data if isinstance(data, dict) else None
    except Exception:
        _HOST_BEHAVIOR_IFOREST_META = None

    return _HOST_BEHAVIOR_IFOREST_META


def get_host_behavior_model():
    """Load and cache the host behavior Isolation Forest model and metadata."""
    return {
        "model": load_host_behavior_iforest(),
        "meta": load_host_behavior_iforest_meta(),
    }


def get_ocsvm_network_model():
    """Load and cache the CICIDS network One-Class SVM model and scaler."""
    global _NETWORK_OCSVM_CICIDS_MODEL
    global _NETWORK_OCSVM_CICIDS_SCALER
    global _NETWORK_OCSVM_CICIDS_LOAD_ATTEMPTED

    if _NETWORK_OCSVM_CICIDS_LOAD_ATTEMPTED:
        return {
            "model": _NETWORK_OCSVM_CICIDS_MODEL,
            "scaler": _NETWORK_OCSVM_CICIDS_SCALER,
        }

    _NETWORK_OCSVM_CICIDS_LOAD_ATTEMPTED = True

    if not NETWORK_OCSVM_CICIDS_PATH.exists() or not NETWORK_OCSVM_CICIDS_SCALER_PATH.exists():
        return {"model": None, "scaler": None}

    try:
        _NETWORK_OCSVM_CICIDS_MODEL = joblib.load(NETWORK_OCSVM_CICIDS_PATH)
    except Exception:
        _NETWORK_OCSVM_CICIDS_MODEL = None

    try:
        _NETWORK_OCSVM_CICIDS_SCALER = joblib.load(NETWORK_OCSVM_CICIDS_SCALER_PATH)
    except Exception:
        _NETWORK_OCSVM_CICIDS_SCALER = None

    return {
        "model": _NETWORK_OCSVM_CICIDS_MODEL,
        "scaler": _NETWORK_OCSVM_CICIDS_SCALER,
    }
