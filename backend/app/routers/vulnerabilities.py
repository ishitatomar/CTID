"""Vulnerability (CVE) endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Vulnerability
from ..serializers import serialize_vulnerability

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
def list_vulnerabilities(
    q: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None),
    exploited: bool | None = Query(default=None),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    sort: str = Query(default="cvss"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=12, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Vulnerability)
    if q:
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Vulnerability.cve_id).like(needle),
                func.lower(Vulnerability.title).like(needle),
                func.lower(Vulnerability.description).like(needle),
                func.lower(Vulnerability.affected_products).like(needle),
            )
        )
    if severity and severity != "all":
        stmt = stmt.where(Vulnerability.severity == severity)
    if exploited is not None:
        stmt = stmt.where(Vulnerability.exploited.is_(exploited))
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss >= min_cvss)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    order_by = {
        "cvss": Vulnerability.cvss.desc(),
        "published": Vulnerability.published_at.desc(),
        "cve": Vulnerability.cve_id.desc(),
    }.get(sort, Vulnerability.cvss.desc())

    rows = db.execute(
        stmt.order_by(order_by, Vulnerability.id.desc()).offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()

    severity_rows = db.execute(
        select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)
    ).all()
    by_severity = {sev: 0 for sev in ("critical", "high", "medium", "low")}
    for sev, count in severity_rows:
        by_severity[sev or "medium"] = int(count)

    return {
        "items": [serialize_vulnerability(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
        "summary": {
            "total": db.scalar(select(func.count()).select_from(Vulnerability)) or 0,
            "exploited": db.scalar(
                select(func.count()).select_from(Vulnerability).where(Vulnerability.exploited.is_(True))
            )
            or 0,
            "patch_available": db.scalar(
                select(func.count()).select_from(Vulnerability).where(Vulnerability.patch_available.is_(True))
            )
            or 0,
            # Only scored CVEs (NVD/demo data) contribute; KEV-only rows carry no score.
            "average_cvss": round(
                float(
                    db.scalar(select(func.avg(Vulnerability.cvss)).where(Vulnerability.cvss > 0)) or 0.0
                ),
                1,
            ),
            "by_severity": by_severity,
        },
    }


@router.get("/{cve_id}")
def get_vulnerability(cve_id: str, db: Session = Depends(get_db)) -> dict:
    vuln = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper()))
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return serialize_vulnerability(vuln)
