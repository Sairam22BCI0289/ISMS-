from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from datetime import datetime
from .base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    # "host" or "cloud"
    source = Column(String(20), index=True)

    # e.g., "login_fail", "process_start", "iam_policy_change"
    event_type = Column(String(50), index=True)

    # when the event happened
    timestamp = Column(DateTime, index=True, default=datetime.utcnow)

    # who triggered it (user / role / account)
    actor = Column(String(120), nullable=True, index=True)

    # ip address if applicable
    ip = Column(String(64), nullable=True)

    # resource affected (file, bucket, instance, policy, etc.)
    resource = Column(String(200), nullable=True)

    # ML / rules outputs
    anomaly_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)  # low/medium/high

    # raw event as JSON string
    raw = Column(Text, nullable=True)
