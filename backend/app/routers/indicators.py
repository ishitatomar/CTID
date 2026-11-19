"""Indicator of compromise endpoints: search, filter, detail, CRUD, export."""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Indicator, PipelineRun, Source, Vulnerability, utcnow
from ..normalize import hash_algorithm, normalize, severity_rank
from ..schemas import IndicatorCreate, IndicatorUpdate
from ..serializers import serialize_indicator, serialize_vulnerability

router = APIRouter(prefix="/api/indicators", tags=["indicators"])

SEVERITY_RANK_SQL = case(
    (Indicator.severity == "critical", 4),
    (Indicator.severity == "high", 3),
    (Indicator.severity == "medium", 2),
    (Indicator.severity == "low", 1),
    else_=0,
)

FACETS = {
    "types": ["ip", "domain", "url", "hash"],
    "severities": ["critical", "high", "medium", "low"],
    "statuses": ["active", "monitoring", "resolved", "false_positive"],
}


def _apply_filters(stmt, q, itype, severity, source_id, status, threat_type, days):
    if q:
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Indicator.value).like(needle),
                func.lower(Indicator.normalized).like(needle),
                func.lower(Indicator.tags).like(needle),
                func.lower(Indicator.threat_type).like(needle),
                func.lower(Indicator.description).like(needle),
            )
        )
    if itype and itype != "all":
        stmt = stmt.where(Indicator.type == itype)
    if severity and severity != "all":
        stmt = stmt.where(Indicator.severity == severity)
    if source_id:
        stmt = stmt.where(Indicator.source_id == source_id)
    if status and status != "all":
        stmt = stmt.where(Indicator.status == status)
    if threat_type and threat_type != "all":
        stmt = stmt.where(Indicator.threat_type == threat_type)
    if days:
        stmt = stmt.where(Indicator.last_seen >= datetime.now(timezone.utc) - timedelta(days=days))
    return stmt


@router.get("/export.csv")
def export_indicators(
    q: str | None = None,
    type: str | None = Query(default=None, alias="type"),
    severity: str | None = None,
    source_id: int | None = None,
    status: str | None = None,
    threat_type: str | None = None,
    days: int | None = None,
    db: Session = Depends(get_db),
) -> Response:
    stmt = _apply_filters(select(Indicator, Source.name), q, type, severity, source_id, status, threat_type, days)
    rows = db.execute(stmt.join(Source, Source.id == Indicator.source_id).order_by(Indicator.last_seen.desc()).limit(5000)).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["value", "normalized", "type", "severity", "confidence", "status", "threat_type", "source", "country", "first_seen", "last_seen", "reports"]
    )
    for indicator, source_name in rows:
        writer.writerow(
            [
                indicator.value,
                indicator.normalized,
                indicator.type,
                indicator.severity,
                indicator.confidence,
                indicator.status,
                indicator.threat_type,
                source_name,
                indicator.country or "",
                indicator.first_seen.isoformat() if indicator.first_seen else "",
                indicator.last_seen.isoformat() if indicator.last_seen else "",
                indicator.report_count,
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="cti-indicators.csv"'},
    )


@router.get("")
def list_indicators(
    q: str | None = Query(default=None, max_length=200),
    type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source_id: int | None = None,
    status: str | None = Query(default=None),
    threat_type: str | None = Query(default=None),
    days: int | None = Query(default=None, ge=1, le=365),
    sort: str = Query(default="last_seen"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=15, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict:
    filt = _apply_filters(select(Indicator), q, type, severity, source_id, status, threat_type, days)

    total = db.scalar(select(func.count()).select_from(filt.subquery())) or 0

    order_by = {
        "last_seen": Indicator.last_seen.desc(),
        "first_seen": Indicator.first_seen.desc(),
        "confidence": Indicator.confidence.desc(),
        "reports": Indicator.report_count.desc(),
        "severity": SEVERITY_RANK_SQL.desc(),
        "value": Indicator.normalized.asc(),
    }.get(sort, Indicator.last_seen.desc())

    rows = db.execute(
        filt.add_columns(Source.name)
        .join(Source, Source.id == Indicator.source_id)
        .order_by(order_by, Indicator.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    sources = db.execute(select(Source.id, Source.name).order_by(Source.name)).all()
    threat_types = db.scalars(select(Indicator.threat_type).distinct().order_by(Indicator.threat_type)).all()

    return {
        "items": [serialize_indicator(indicator, source_name) for indicator, source_name in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
        "facets": {
            **FACETS,
            "sources": [{"id": sid, "name": name} for sid, name in sources],
            "threat_types": list(threat_types),
        },
    }


@router.get("/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.execute(
        select(Indicator, Source.name)
        .join(Source, Source.id == Indicator.source_id)
        .where(Indicator.id == indicator_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Indicator not found")

    indicator, source_name = row
    payload = serialize_indicator(indicator, source_name)

    related_rows = db.execute(
        select(Indicator, Source.name)
        .join(Source, Source.id == Indicator.source_id)
        .where(
            Indicator.id != indicator.id,
            or_(
                Indicator.threat_type == indicator.threat_type,
                Indicator.source_id == indicator.source_id,
            ),
        )
        .order_by(Indicator.last_seen.desc())
        .limit(5)
    ).all()
    payload["related"] = [serialize_indicator(item, name) for item, name in related_rows]

    text = f"{indicator.description} {indicator.tags} {indicator.threat_type}"
    mentioned = {token.upper() for token in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)}
    linked_cves = (
        db.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(mentioned)).limit(4)).all()
        if mentioned
        else []
    )
    payload["related_cves"] = [serialize_vulnerability(cve) for cve in linked_cves]

    history = db.execute(
        select(PipelineRun)
        .where(PipelineRun.source_id == indicator.source_id)
        .order_by(PipelineRun.started_at.desc())
        .limit(3)
    ).scalars().all()
    payload["source_runs"] = [
        {"id": run.id, "started_at": run.started_at.isoformat() if run.started_at else None, "stored": run.stored}
        for run in history
    ]

    return payload


@router.post("", status_code=201)
def create_indicator(payload: IndicatorCreate, db: Session = Depends(get_db)) -> dict:
    parsed = normalize(payload.value)
    if parsed is None:
        raise HTTPException(
            status_code=422,
            detail="Unrecognized indicator. Provide an IPv4/IPv6 address, domain, http(s) URL, or MD5/SHA1/SHA256 hash.",
        )
    normalized, itype = parsed

    existing = db.scalar(select(Indicator).where(Indicator.type == itype, Indicator.normalized == normalized))
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Indicator already tracked (id {existing.id})")

    source_id = payload.source_id
    if source_id is None:
        source_id = db.scalar(select(Source.id).order_by(Source.id))
    elif db.get(Source, source_id) is None:
        raise HTTPException(status_code=404, detail="Source not found")

    now = utcnow()
    indicator = Indicator(
        value=payload.value.strip(),
        normalized=normalized,
        type=itype,
        hash_algorithm=hash_algorithm(normalized) if itype == "hash" else None,
        severity=payload.severity,
        confidence=payload.confidence,
        status=payload.status,
        threat_type=payload.threat_type,
        country=payload.country,
        tags=",".join(tag.strip().lower() for tag in payload.tags if tag.strip()),
        description=payload.description,
        report_count=1,
        first_seen=now,
        last_seen=now,
        source_id=source_id,
    )
    db.add(indicator)
    db.commit()
    db.refresh(indicator)

    return serialize_indicator(indicator)


@router.patch("/{indicator_id}")
def update_indicator(indicator_id: int, payload: IndicatorUpdate, db: Session = Depends(get_db)) -> dict:
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")

    if payload.severity is not None:
        indicator.severity = payload.severity
    if payload.status is not None:
        indicator.status = payload.status
    if payload.confidence is not None:
        indicator.confidence = payload.confidence

    db.commit()
    db.refresh(indicator)
    return serialize_indicator(indicator)


@router.delete("/{indicator_id}", status_code=204)
def delete_indicator(indicator_id: int, db: Session = Depends(get_db)) -> Response:
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    db.delete(indicator)
    db.commit()
    return Response(status_code=204)


@router.get("/{indicator_id}/severity-rank")
def severity_ordering(indicator_id: int, db: Session = Depends(get_db)) -> dict:
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"severity": indicator.severity, "rank": severity_rank(indicator.severity)}
