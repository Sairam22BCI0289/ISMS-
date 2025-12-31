from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from app.db.base import Base, engine, SessionLocal
from app.db import models  # ensures model is registered
from app.db.models import SecurityEvent
from app.db.crud import create_event

app = FastAPI(
    title="Intelligent Security Monitoring System",
    version="0.1.0",
)

# Create DB tables at startup (SQLite file will be created as isms.db)
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/version")
def version():
    return {"version": "0.1.0"}


@app.post("/events")
def add_event(event: dict, db: Session = Depends(get_db)):
    saved = create_event(db, event)
    return {"id": saved.id, "status": "saved"}


@app.get("/events")
def list_events(limit: int = 50, db: Session = Depends(get_db)):
    rows = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    # Return clean JSON (no raw SQLAlchemy objects)
    return [
        {
            "id": r.id,
            "source": r.source,
            "event_type": r.event_type,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "actor": r.actor,
            "ip": r.ip,
            "resource": r.resource,
            "anomaly_score": r.anomaly_score,
            "severity": r.severity,
        }
        for r in rows
    ]
