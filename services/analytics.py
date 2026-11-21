"""Database-backed analytics queries used by the admin dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func

from database import ScanHistory, db


def overview() -> dict[str, object]:
    totals = db.session.query(
        func.count(ScanHistory.id),
        func.sum(case((ScanHistory.prediction == "Potential Phishing", 1), else_=0)),
        func.sum(case((ScanHistory.prediction == "Likely Legitimate", 1), else_=0)),
        func.sum(case((ScanHistory.risk_level == "High", 1), else_=0)),
    ).one()
    total = int(totals[0] or 0)
    phishing = int(totals[1] or 0)
    return {
        "total_scans": total,
        "potential_phishing": phishing,
        "likely_legitimate": int(totals[2] or 0),
        "high_risk": int(totals[3] or 0),
        "phishing_rate": round((phishing / total) * 100, 2) if total else 0.0,
    }


def trends(days: int = 30) -> list[dict[str, object]]:
    days = max(7, min(days, 90))
    start = datetime.now(timezone.utc) - timedelta(days=days - 1)
    day_expression = func.date(ScanHistory.created_at)
    rows = (
        db.session.query(
            day_expression.label("day"),
            func.count(ScanHistory.id).label("total"),
            func.sum(case((ScanHistory.prediction == "Potential Phishing", 1), else_=0)).label(
                "phishing"
            ),
        )
        .filter(ScanHistory.created_at >= start)
        .group_by(day_expression)
        .order_by(day_expression)
        .all()
    )
    return [
        {"date": str(row.day), "total": int(row.total), "phishing": int(row.phishing or 0)}
        for row in rows
    ]


def recent_scans(limit: int = 10) -> list[dict[str, object]]:
    limit = max(1, min(limit, 50))
    rows = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(limit).all()
    return [row.to_public_dict() for row in rows]

