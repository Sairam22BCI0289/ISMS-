from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from datetime import datetime
from .base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    # host / cloud / network
    source = Column(String(20), index=True, nullable=False, default="unknown")

    # e.g. win_login_failed, iam_policy_change, net_conn_blocked
    event_type = Column(String(50), index=True, nullable=False, default="unknown")

    timestamp = Column(DateTime, index=True, default=datetime.utcnow)

    actor = Column(String(120), nullable=True, index=True)
    ip = Column(String(64), nullable=True)
    resource = Column(String(200), nullable=True)

    anomaly_score = Column(Float, nullable=True)
    anomaly_score_svm = Column(Float, nullable=True)
    anomaly_risk_10 = Column(Float, nullable=True)
    anomaly_risk_10_svm = Column(Float, nullable=True)
    host_auth_risk = Column(Float, nullable=True)
    host_behavior_risk = Column(Float, nullable=True)
    host_multilayer_risk = Column(Float, nullable=True)
    network_multilayer_risk = Column(Float, nullable=True)
    anomaly_label = Column(String, nullable=True)
    anomaly_label_svm = Column(String, nullable=True)
    anomaly_model = Column(String, nullable=True)
    anomaly_source_profile = Column(String, nullable=True)

    # low / medium / high
    severity = Column(String(20), nullable=True)

    # short human "why"
    severity_reason = Column(String(255), nullable=True)

    # JSON text of triggered rules (list[str])
    rules_triggered = Column(Text, nullable=True)

    # raw payload JSON (string)
    raw = Column(Text, nullable=True)
