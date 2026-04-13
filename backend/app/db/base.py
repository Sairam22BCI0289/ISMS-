from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.config import DATABASE_URL

# Needed for SQLite + threads (FastAPI)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
from sqlalchemy.orm import declarative_base  # noqa: E402

Base = declarative_base()


def _ensure_anomaly_risk_column() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as conn:
        exists = conn.execute(text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'"
        )).fetchone()
        if not exists:
            return

        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(security_events)")).fetchall()]
        if "anomaly_risk_10" not in columns:
            conn.execute(text("ALTER TABLE security_events ADD COLUMN anomaly_risk_10 FLOAT"))


_ensure_anomaly_risk_column()


def _ensure_anomaly_svm_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as conn:
        exists = conn.execute(text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'"
        )).fetchone()
        if not exists:
            return

        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(security_events)")).fetchall()]
        if "anomaly_score_svm" not in columns:
            conn.execute(text("ALTER TABLE security_events ADD COLUMN anomaly_score_svm FLOAT"))
        if "anomaly_label_svm" not in columns:
            conn.execute(text("ALTER TABLE security_events ADD COLUMN anomaly_label_svm VARCHAR"))


_ensure_anomaly_svm_columns()
