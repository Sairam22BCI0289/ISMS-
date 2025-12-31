import json
from sqlalchemy.orm import Session
from app.db.models import SecurityEvent


def create_event(db: Session, event: dict):
    obj = SecurityEvent(
        source=event.get("source"),
        event_type=event.get("event_type"),
        actor=event.get("actor"),
        ip=event.get("ip"),
        resource=event.get("resource"),
        severity=event.get("severity"),
        anomaly_score=event.get("anomaly_score"),
        raw=json.dumps(event),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj
