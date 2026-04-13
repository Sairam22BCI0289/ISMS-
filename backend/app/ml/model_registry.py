"""Lightweight model and metadata loaders for anomaly detection."""

import json
from pathlib import Path

import joblib

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
NETWORK_IFOREST_PATH = MODELS_DIR / "network_isolation_forest.joblib"
NETWORK_IFOREST_META_PATH = MODELS_DIR / "network_isolation_forest_meta.json"
NETWORK_OCSVM_PATH = MODELS_DIR / "network_ocsvm.joblib"
_NETWORK_IFOREST_MODEL = None
_NETWORK_IFOREST_LOAD_ATTEMPTED = False
_NETWORK_IFOREST_META = None
_NETWORK_IFOREST_META_LOAD_ATTEMPTED = False
_NETWORK_OCSVM_MODEL = None
_NETWORK_OCSVM_LOAD_ATTEMPTED = False


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
