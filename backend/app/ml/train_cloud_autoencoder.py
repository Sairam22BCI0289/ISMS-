from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.base import SessionLocal
from app.db.models import SecurityEvent
from app.ml.features import extract_cloud_features

MODEL_PATH = BACKEND_DIR / "models" / "cloud_autoencoder.keras"
SCALER_PATH = BACKEND_DIR / "models" / "cloud_autoencoder_scaler.joblib"
META_PATH = BACKEND_DIR / "models" / "cloud_autoencoder_meta.json"
MIN_TRAINING_ROWS = 50


def parse_raw(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def cloudtrail_event_from_raw(raw: dict) -> dict:
    cloudtrail = raw.get("CloudTrailEvent")
    if isinstance(cloudtrail, dict):
        return cloudtrail
    if isinstance(cloudtrail, str):
        try:
            parsed = json.loads(cloudtrail)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def cloudtrail_value(raw: dict, cloudtrail: dict, raw_key: str, cloudtrail_key: str) -> str:
    value = raw.get(raw_key)
    if value in (None, ""):
        value = cloudtrail.get(cloudtrail_key)
    return str(value or "").strip()


def is_lookupevents_noise(raw: dict, cloudtrail: dict) -> bool:
    event_name = cloudtrail_value(raw, cloudtrail, "EventName", "eventName")
    event_source = cloudtrail_value(raw, cloudtrail, "EventSource", "eventSource").lower()
    return event_name == "LookupEvents" and event_source == "cloudtrail.amazonaws.com"


def is_awsservice_assumerole_noise(raw: dict, cloudtrail: dict) -> bool:
    event_name = cloudtrail_value(raw, cloudtrail, "EventName", "eventName")
    event_source = cloudtrail_value(raw, cloudtrail, "EventSource", "eventSource").lower()
    user_identity = cloudtrail.get("userIdentity") if isinstance(cloudtrail.get("userIdentity"), dict) else {}
    identity_type = str(user_identity.get("type") or "").strip()
    return event_name == "AssumeRole" and event_source == "sts.amazonaws.com" and identity_type == "AWSService"


def row_to_event(row: SecurityEvent) -> dict:
    return {
        "source": row.source,
        "event_type": row.event_type,
        "timestamp": row.timestamp,
        "actor": row.actor,
        "ip": row.ip,
        "resource": row.resource,
        "raw": row.raw,
    }


def is_valid_feature_vector(vector: object) -> bool:
    if not isinstance(vector, list) or not vector:
        return False
    for value in vector:
        if not isinstance(value, (int, float)):
            return False
        if not math.isfinite(float(value)):
            return False
    return True


def compute_quantile(sorted_values: list[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("cannot compute quantile for empty input")
    if len(sorted_values) == 1:
        return float(sorted_values[0])

    position = (len(sorted_values) - 1) * probability
    lower_index = int(math.floor(position))
    upper_index = int(math.ceil(position))
    lower_value = float(sorted_values[lower_index])
    upper_value = float(sorted_values[upper_index])

    if lower_index == upper_index:
        return lower_value

    weight = position - lower_index
    return lower_value + ((upper_value - lower_value) * weight)


def load_cloud_rows() -> list[SecurityEvent]:
    db = SessionLocal()
    try:
        return (
            db.query(SecurityEvent)
            .filter(SecurityEvent.source == "cloud")
            .order_by(SecurityEvent.id.asc())
            .all()
        )
    finally:
        db.close()


def build_training_features(rows: list[SecurityEvent]) -> tuple[list[list[float]], int, int]:
    excluded_lookupevents = 0
    excluded_awsservice_assumerole = 0
    feature_rows: list[list[float]] = []

    for row in rows:
        raw = parse_raw(row.raw)
        cloudtrail = cloudtrail_event_from_raw(raw)

        if is_lookupevents_noise(raw, cloudtrail):
            excluded_lookupevents += 1
            continue

        if is_awsservice_assumerole_noise(raw, cloudtrail):
            excluded_awsservice_assumerole += 1
            continue

        try:
            features = extract_cloud_features(row_to_event(row))
        except Exception:
            continue

        if not is_valid_feature_vector(features):
            continue

        feature_rows.append([float(value) for value in features])

    return feature_rows, excluded_lookupevents, excluded_awsservice_assumerole


def main() -> int:
    try:
        import joblib
        from sklearn.preprocessing import StandardScaler
        from tensorflow import keras
    except ImportError as exc:
        print(f"[ERROR] Missing training dependency: {exc}")
        print("[INFO] Install TensorFlow/Keras and scikit-learn in a compatible Python environment before training.")
        return 1

    try:
        rows = load_cloud_rows()
    except Exception as exc:
        print(f"[ERROR] Failed to load cloud rows from database: {exc}")
        return 1

    total_cloud_rows = len(rows)
    feature_rows, excluded_lookupevents, excluded_awsservice_assumerole = build_training_features(rows)
    usable_training_rows = len(feature_rows)

    print(f"[INFO] Total cloud rows read: {total_cloud_rows}")
    print(f"[INFO] Usable cloud training rows: {usable_training_rows}")
    print(f"[INFO] Excluded LookupEvents rows: {excluded_lookupevents}")
    print(f"[INFO] Excluded AWSService AssumeRole rows: {excluded_awsservice_assumerole}")

    if usable_training_rows < MIN_TRAINING_ROWS:
        print(f"[ERROR] Need at least {MIN_TRAINING_ROWS} usable cloud rows to train safely.")
        return 1

    try:
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(feature_rows)
        feature_dim = int(features_scaled.shape[1])

        model = keras.Sequential([
            keras.layers.Input(shape=(feature_dim,)),
            keras.layers.Dense(12, activation="relu"),
            keras.layers.Dense(6, activation="relu"),
            keras.layers.Dense(12, activation="relu"),
            keras.layers.Dense(feature_dim, activation="linear"),
        ])
        model.compile(optimizer="adam", loss="mse")

        early_stopping = keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=6,
            restore_best_weights=True,
        )

        history = model.fit(
            features_scaled,
            features_scaled,
            epochs=50,
            batch_size=16,
            validation_split=0.2,
            shuffle=True,
            callbacks=[early_stopping],
            verbose=0,
        )

        reconstructed = model.predict(features_scaled, verbose=0)
        reconstruction_errors = ((features_scaled - reconstructed) ** 2).mean(axis=1)
        sorted_errors = sorted(float(value) for value in reconstruction_errors)
        mean_error = float(sum(sorted_errors) / len(sorted_errors))
        variance = sum((error - mean_error) ** 2 for error in sorted_errors) / len(sorted_errors)

        training_loss = history.history.get("loss") or []
        validation_loss = history.history.get("val_loss") or []

        metadata = {
            "model_name": "autoencoder_cloud_v1",
            "source_profile": "cloud",
            "feature_dim": feature_dim,
            "total_cloud_rows": total_cloud_rows,
            "usable_training_rows": usable_training_rows,
            "excluded_lookupevents_rows": excluded_lookupevents,
            "excluded_awsservice_assumerole_rows": excluded_awsservice_assumerole,
            "training_loss_final": float(training_loss[-1]) if training_loss else None,
            "validation_loss_final": float(validation_loss[-1]) if validation_loss else None,
            "reconstruction_error_mean": mean_error,
            "reconstruction_error_std": float(math.sqrt(variance)),
            "reconstruction_error_p90": compute_quantile(sorted_errors, 0.90),
            "reconstruction_error_p95": compute_quantile(sorted_errors, 0.95),
            "reconstruction_error_p99": compute_quantile(sorted_errors, 0.99),
        }

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        model.save(MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        META_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"[ERROR] Cloud autoencoder training failed: {exc}")
        return 1

    print(f"[INFO] Saved cloud autoencoder to: {MODEL_PATH}")
    print(f"[INFO] Saved cloud scaler to: {SCALER_PATH}")
    print(f"[INFO] Saved cloud metadata to: {META_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
