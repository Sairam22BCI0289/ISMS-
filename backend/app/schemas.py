from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class EventCreate(BaseModel):
    source: str
    event_type: str
    timestamp: Optional[datetime] = None

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
    rules_triggered: Optional[List[str]] = None

    raw: Optional[str] = None


class EventOut(EventCreate):
    id: int

    class Config:
        from_attributes = True
