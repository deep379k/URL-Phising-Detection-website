"""Database models and MySQL configuration for PhishGuard AI."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from urllib.parse import quote_plus, urlsplit, urlunsplit

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index


db = SQLAlchemy()


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    input_type = db.Column(db.String(20), nullable=False, index=True)
    prediction = db.Column(db.String(40), nullable=False, index=True)
    risk_level = db.Column(db.String(20), nullable=False, index=True)
    category = db.Column(db.String(80), nullable=True)
    model_name = db.Column(db.String(120), nullable=False)
    input_preview = db.Column(db.String(512), nullable=True)
    analysis_source = db.Column(db.String(40), nullable=False, default="machine-learning-model")
    model_probability = db.Column(db.Float, nullable=True)
    indicators = db.Column(db.JSON, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        Index("ix_scan_type_created", "input_type", "created_at"),
        Index("ix_scan_prediction_created", "prediction", "created_at"),
    )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "input_type": self.input_type,
            "prediction": self.prediction,
            "risk_level": self.risk_level,
            "category": self.category,
            "model_name": self.model_name,
            "input_preview": self.input_preview,
            "analysis_source": self.analysis_source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def configure_database(app) -> bool:
    """Configure MySQL from environment variables; return whether it is enabled."""
    explicit_url = os.getenv("DATABASE_URL", "").strip()
    host = (os.getenv("DB_HOST") or os.getenv("MYSQLHOST") or "").strip()
    name = (os.getenv("DB_NAME") or os.getenv("MYSQLDATABASE") or "phishguard_db").strip()
    user = (os.getenv("DB_USER") or os.getenv("MYSQLUSER") or "").strip()
    password = os.getenv("DB_PASSWORD") or os.getenv("MYSQLPASSWORD") or ""
    port = (os.getenv("DB_PORT") or os.getenv("MYSQLPORT") or "3306").strip()

    if explicit_url:
        database_url = (
            explicit_url.replace("mysql://", "mysql+pymysql://", 1)
            if explicit_url.startswith("mysql://")
            else explicit_url
        )
        enabled = True
    elif host and user and password:
        database_url = (
            f"mysql+pymysql://{quote_plus(user)}:{quote_plus(password)}@"
            f"{host}:{port}/{quote_plus(name)}?charset=utf8mb4"
        )
        enabled = True
    else:
        # Flask-SQLAlchemy requires a URI. This in-memory database is never
        # initialized or used for persistence when DATABASE_ENABLED is false.
        database_url = "sqlite:///:memory:"
        enabled = False

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    app.config["DATABASE_ENABLED"] = enabled
    db.init_app(app)
    return enabled


def initialize_database(app) -> bool:
    if not app.config.get("DATABASE_ENABLED"):
        return False
    try:
        with app.app_context():
            db.create_all()
        app.config["DATABASE_CONNECTED"] = True
    except Exception:
        app.logger.exception("MySQL initialization failed")
        app.config["DATABASE_CONNECTED"] = False
    return bool(app.config["DATABASE_CONNECTED"])


def sanitize_url_for_history(value: str) -> str:
    """Remove credentials, query parameters, and fragments before storage."""
    parsed = urlsplit(value)
    hostname = parsed.hostname or ""
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path[:300], "", ""))[:512]


def record_url_scan(result: dict[str, object]) -> None:
    scan = ScanHistory(
        input_type="url",
        prediction=str(result["prediction"]),
        risk_level=str(result["risk_level"]),
        model_name=str(result["model_name"]),
        input_preview=sanitize_url_for_history(str(result["url"])),
        analysis_source=str(result["analysis_source"]),
        model_probability=float(result["model_phishing_probability"]),
        indicators=result.get("indicators"),
    )
    db.session.add(scan)
    db.session.commit()


def record_message_scan(result: dict[str, object], character_count: int) -> None:
    """Store derived metadata only; raw private message content is not persisted."""
    themes = result.get("scam_themes") or []
    scan = ScanHistory(
        input_type="message",
        prediction=str(result["prediction"]),
        risk_level=str(result["risk_level"]),
        category=", ".join(str(theme["name"]) for theme in themes)[:80] or None,
        model_name=str(result["model_name"]),
        input_preview=f"Private message content not stored ({character_count} characters)",
        analysis_source="machine-learning-model",
        model_probability=(
            float(result["model_spam_probability"])
            if result.get("model_spam_probability") is not None
            else None
        ),
        indicators=result.get("indicators"),
    )
    db.session.add(scan)
    db.session.commit()


def record_email_scan(result: dict[str, object], character_count: int) -> None:
    """Store email-derived metadata only; never persist the email body."""
    themes = result.get("scam_themes") or []
    scan = ScanHistory(
        input_type="email",
        prediction=str(result["prediction"]),
        risk_level=str(result["risk_level"]),
        category=", ".join(str(theme["name"]) for theme in themes)[:80] or None,
        model_name=str(result["model_name"]),
        input_preview=f"Private email content not stored ({character_count} characters)",
        analysis_source=str(result["analysis_source"]),
        model_probability=(
            float(result["model_spam_probability"])
            if result.get("model_spam_probability") is not None
            else None
        ),
        indicators=result.get("indicators"),
    )
    db.session.add(scan)
    db.session.commit()

