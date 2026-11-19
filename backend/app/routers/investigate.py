"""Cross-entity investigation search used by the Investigate page."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Indicator, Source, Vulnerability
from ..serializers import serialize_indicator, serialize_source, serialize_vulnerability

router = APIRouter(prefix="/api/investigate", tags=["investigate"])


@router.get("")
def investigate(q: str = Query(min_length=1, max_length=200), db: Session = Depends(get_db)) -> dict:
    needle = f"%{q.strip().lower()}%"

    indicator_stmt = (
        select(Indicator, Source.name)
        .join(Source, Source.id == Indicator.source_id)
        .where(
            or_(
                func.lower(Indicator.value).like(needle),
                func.lower(Indicator.normalized).like(needle),
                func.lower(Indicator.tags).like(needle),
                func.lower(Indicator.threat_type).like(needle),
                func.lower(Indicator.description).like(needle),
                func.lower(Source.name).like(needle),
            )
        )
        .order_by(Indicator.last_seen.desc())
    )

    indicator_total = db.scalar(select(func.count()).select_from(indicator_stmt.subquery())) or 0
    indicators = db.execute(indicator_stmt.limit(12)).all()

    cve_stmt = select(Vulnerability).where(
        or_(
            func.lower(Vulnerability.cve_id).like(needle),
            func.lower(Vulnerability.title).like(needle),
            func.lower(Vulnerability.description).like(needle),
            func.lower(Vulnerability.affected_products).like(needle),
        )
    )
    cve_total = db.scalar(select(func.count()).select_from(cve_stmt.subquery())) or 0
    cves = db.scalars(cve_stmt.order_by(Vulnerability.cvss.desc()).limit(8)).all()

    source_stmt = select(Source).where(
        or_(
            func.lower(Source.name).like(needle),
            func.lower(Source.description).like(needle),
            func.lower(Source.kind).like(needle),
        )
    )
    sources = db.scalars(source_stmt.limit(5)).all()

    # Pivots: which categories share the same result set, grouped for the analyst.
    pivot_rows = db.execute(
        select(Indicator.threat_type, Indicator.severity, func.count())
        .where(Indicator.id.in_([indicator.id for indicator, _ in indicators]))
        .group_by(Indicator.threat_type, Indicator.severity)
        .order_by(func.count().desc())
        .limit(6)
    ).all()

    return {
        "query": q,
        "counts": {
            "indicators": indicator_total,
            "vulnerabilities": cve_total,
            "sources": len(sources),
            "total": indicator_total + cve_total,
        },
        "indicators": [serialize_indicator(indicator, name) for indicator, name in indicators],
        "vulnerabilities": [serialize_vulnerability(cve) for cve in cves],
        "sources": [serialize_source(source) for source in sources],
        "pivots": [
            {"threat_type": threat_type, "severity": severity, "count": int(count)}
            for threat_type, severity, count in pivot_rows
        ],
    }
