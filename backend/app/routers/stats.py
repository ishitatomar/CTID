"""Aggregated statistics for the SOC overview dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Indicator, PipelineRun, Source, Vulnerability
from ..serializers import iso, serialize_indicator, serialize_run

router = APIRouter(prefix="/api/stats", tags=["stats"])

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@router.get("")
def get_stats(
    days: int = Query(default=14, ge=2, le=90),
    db: Session = Depends(get_db),
) -> dict:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days - 1)

    total_indicators = db.scalar(select(func.count()).select_from(Indicator)) or 0
    active_indicators = (
        db.scalar(select(func.count()).select_from(Indicator).where(Indicator.status == "active")) or 0
    )
    new_24h = (
        db.scalar(
            select(func.count())
            .select_from(Indicator)
            .where(Indicator.first_seen >= now - timedelta(hours=24))
        )
        or 0
    )

    severity_rows = db.execute(
        select(Indicator.severity, func.count()).group_by(Indicator.severity)
    ).all()
    by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    for severity, count in severity_rows:
        by_severity[severity or "medium"] = by_severity.get(severity or "medium", 0) + int(count)

    type_rows = db.execute(select(Indicator.type, func.count()).group_by(Indicator.type).order_by(func.count().desc())).all()
    by_type = [{"type": itype, "count": int(count)} for itype, count in type_rows]

    source_rows = db.execute(
        select(
            Source.id,
            Source.name,
            func.count(Indicator.id),
            func.sum(case((Indicator.severity == "critical", 1), else_=0)),
        )
        .join(Indicator, Indicator.source_id == Source.id)
        .group_by(Source.id, Source.name)
        .order_by(func.count(Indicator.id).desc())
    ).all()
    by_source = [
        {"source_id": sid, "source": name, "count": int(count), "critical": int(critical or 0)}
        for sid, name, count, critical in source_rows
    ]

    category_rows = db.execute(
        select(Indicator.threat_type, func.count())
        .group_by(Indicator.threat_type)
        .order_by(func.count().desc())
        .limit(8)
    ).all()
    by_category = [{"category": category, "count": int(count)} for category, count in category_rows]

    status_rows = db.execute(select(Indicator.status, func.count()).group_by(Indicator.status)).all()
    by_status = {status: int(count) for status, count in status_rows}

    # Trend: one bucket per day for the requested window.
    trend_rows = db.execute(
        select(func.date(Indicator.first_seen), Indicator.severity, func.count())
        .where(Indicator.first_seen >= window_start)
        .group_by(func.date(Indicator.first_seen), Indicator.severity)
    ).all()

    buckets: dict[str, dict] = {}
    for day_index in range(days):
        day = (window_start + timedelta(days=day_index)).date().isoformat()
        buckets[day] = {"date": day, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for day_value, severity, count in trend_rows:
        key = str(day_value)[:10]
        if key not in buckets:
            continue
        severity = severity or "medium"
        buckets[key][severity] = buckets[key].get(severity, 0) + int(count)
        buckets[key]["total"] += int(count)
    trend = list(buckets.values())

    cve_total = db.scalar(select(func.count()).select_from(Vulnerability)) or 0
    cve_exploited = (
        db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.exploited.is_(True))) or 0
    )
    cve_critical = (
        db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == "critical")) or 0
    )
    cve_patched = (
        db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.patch_available.is_(True)))
        or 0
    )

    run_rows = db.execute(
        select(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(8)
    ).scalars().all()
    totals = db.execute(
        select(
            func.coalesce(func.sum(PipelineRun.collected), 0),
            func.coalesce(func.sum(PipelineRun.duplicates), 0),
            func.coalesce(func.sum(PipelineRun.rejected), 0),
        )
    ).one()
    collected, duplicates, rejected = (int(value) for value in totals)
    duplicate_rate = round((duplicates / collected) * 100, 1) if collected else 0.0

    active_sources = (
        db.scalar(select(func.count()).select_from(Source).where(Source.status == "active")) or 0
    )
    total_sources = db.scalar(select(func.count()).select_from(Source)) or 0

    weighted = sum(SEVERITY_WEIGHT.get(sev, 2) * count for sev, count in by_severity.items())
    threat_pressure = round((weighted / (4 * total_indicators)) * 100, 1) if total_indicators else 0.0

    recent = db.execute(
        select(Indicator, Source.name)
        .join(Source, Source.id == Indicator.source_id)
        .order_by(Indicator.first_seen.desc())
        .limit(6)
    ).all()

    return {
        "generated_at": iso(now),
        "window_days": days,
        "totals": {
            "indicators": total_indicators,
            "active_indicators": active_indicators,
            "new_24h": new_24h,
            "cves": cve_total,
            "cve_exploited": cve_exploited,
            "cve_critical": cve_critical,
            "cve_patched": cve_patched,
            "sources": total_sources,
            "active_sources": active_sources,
            "pipeline_runs": len(run_rows),
            "collected": collected,
            "duplicate_rate": duplicate_rate,
            "rejected": rejected,
            "threat_pressure": threat_pressure,
        },
        "by_severity": [{"severity": sev, "count": by_severity.get(sev, 0)} for sev in SEVERITY_ORDER],
        "by_type": by_type,
        "by_source": by_source,
        "by_category": by_category,
        "by_status": [
            {"status": status, "count": by_status.get(status, 0)}
            for status in ("active", "monitoring", "resolved", "false_positive")
        ],
        "trend": trend,
        "recent_indicators": [serialize_indicator(ind, name) for ind, name in recent],
        "recent_runs": [serialize_run(run) for run in run_rows],
    }
