from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Any, Dict, Union
from datetime import datetime, timezone
import json
import os

from sqlalchemy.orm import Session

from app.db.base import SessionLocal, engine, Base
from app.db import crud

Base.metadata.create_all(bind=engine)
with SessionLocal() as startup_db:
    crud.fix_future_host_timestamps(startup_db)

app = FastAPI(title="ISMS Backend", version="0.1.0")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class EventIn(BaseModel):
    source: Optional[str] = None
    event_type: Optional[str] = None
    timestamp: Optional[Union[datetime, str]] = None
    actor: Optional[str] = None
    ip: Optional[str] = None
    resource: Optional[str] = None
    anomaly_score: Optional[float] = None
    anomaly_score_svm: Optional[float] = None
    anomaly_risk_10: Optional[float] = None
    anomaly_risk_10_svm: Optional[float] = None
    host_auth_risk: Optional[float] = None
    host_behavior_risk: Optional[float] = None
    host_multilayer_risk: Optional[float] = None
    network_multilayer_risk: Optional[float] = None
    anomaly_label: Optional[str] = None
    anomaly_label_svm: Optional[str] = None
    anomaly_model: Optional[str] = None
    anomaly_source_profile: Optional[str] = None
    severity: Optional[str] = None
    severity_reason: Optional[str] = None
    rules_triggered: Optional[Any] = None
    raw: Optional[Any] = None

    model_config = {"extra": "allow"}


class EventOut(BaseModel):
    id: int
    source: str
    event_type: str
    timestamp: datetime
    actor: Optional[str] = None
    ip: Optional[str] = None
    resource: Optional[str] = None
    anomaly_score: Optional[float] = None
    anomaly_score_svm: Optional[float] = None
    anomaly_risk_10: Optional[float] = None
    anomaly_risk_10_svm: Optional[float] = None
    host_auth_risk: Optional[float] = None
    host_behavior_risk: Optional[float] = None
    host_multilayer_risk: Optional[float] = None
    network_multilayer_risk: Optional[float] = None
    anomaly_label: Optional[str] = None
    anomaly_label_svm: Optional[str] = None
    anomaly_model: Optional[str] = None
    anomaly_source_profile: Optional[str] = None
    severity: Optional[str] = None
    severity_reason: Optional[str] = None
    rules_triggered: List[str] = []
    raw: Optional[str] = None

    class Config:
        from_attributes = True


def _normalize_to_utc(ts: Optional[Union[str, datetime]]) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts
        return ts.astimezone(timezone.utc).replace(tzinfo=None)

    s = str(ts).strip()
    if not s:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            return dt
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return datetime.now(timezone.utc).replace(tzinfo=None)


def _host_future_timestamp_fix(payload: Dict[str, Any]) -> None:
    source = str(payload.get("source") or "").lower().strip()
    ts = payload.get("timestamp")
    if source != "host" or not isinstance(ts, datetime):
        return

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    if ts <= now_utc.replace(microsecond=0) + crud.HOST_FUTURE_SKEW_THRESHOLD:
        return

    local_offset = datetime.now().astimezone().utcoffset()
    if not local_offset:
        return

    payload["timestamp"] = ts - local_offset


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


def _to_raw_string(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw, ensure_ascii=False, default=str)
    except Exception:
        return str(raw)


def normalize_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(payload)

    payload["timestamp"] = _normalize_to_utc(payload.get("timestamp"))
    payload["source"] = str(payload.get("source") or "unknown")
    payload["event_type"] = str(payload.get("event_type") or "unknown")
    payload["rules_triggered"] = _coerce_rules(payload.get("rules_triggered"))
    payload["raw"] = _to_raw_string(payload.get("raw"))

    if payload.get("severity_reason") is not None:
        payload["severity_reason"] = str(payload["severity_reason"])

    if payload.get("severity") is not None:
        payload["severity"] = str(payload["severity"]).lower().strip()

    _host_future_timestamp_fix(payload)

    return payload


def _parse_rules_from_db_text(rt_text: Optional[str]) -> List[str]:
    if not rt_text:
        return []
    s = rt_text.strip()
    if s.startswith("[") and s.endswith("]"):
        try:
            arr = json.loads(s)
            if isinstance(arr, list):
                return [str(x) for x in arr]
        except Exception:
            pass
    return [rt_text]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/version")
def version():
    return {"version": app.version}


@app.post("/events")
def ingest_event(evt: EventIn, db: Session = Depends(get_db)):
    data = evt.model_dump()
    data = normalize_event(data)

    created = crud.create_event(db, data)
    return {"ok": True, "id": created.id}


@app.get("/events", response_model=List[EventOut])
def list_events(
    limit: int = 80,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
):
    items = crud.get_events(db, limit=limit, source=source, severity=severity, q=q)

    out: List[EventOut] = []
    for e in items:
        out.append(EventOut(
            id=e.id,
            source=e.source,
            event_type=e.event_type,
            timestamp=e.timestamp.replace(tzinfo=timezone.utc),
            actor=e.actor,
            ip=e.ip,
            resource=e.resource,
            anomaly_score=e.anomaly_score,
            anomaly_score_svm=getattr(e, "anomaly_score_svm", None),
            anomaly_risk_10=getattr(e, "anomaly_risk_10", None),
            anomaly_risk_10_svm=getattr(e, "anomaly_risk_10_svm", None),
            host_auth_risk=getattr(e, "host_auth_risk", None),
            host_behavior_risk=getattr(e, "host_behavior_risk", None),
            host_multilayer_risk=getattr(e, "host_multilayer_risk", None),
            network_multilayer_risk=getattr(e, "network_multilayer_risk", None),
            anomaly_label=getattr(e, "anomaly_label", None),
            anomaly_label_svm=getattr(e, "anomaly_label_svm", None),
            anomaly_model=getattr(e, "anomaly_model", None),
            anomaly_source_profile=getattr(e, "anomaly_source_profile", None),
            severity=e.severity,
            severity_reason=getattr(e, "severity_reason", None),
            rules_triggered=_parse_rules_from_db_text(getattr(e, "rules_triggered", None)),
            raw=e.raw
        ))
    return out


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    here = os.path.dirname(__file__)
    ui_path = os.path.join(here, "ui", "dashboard.html")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())
