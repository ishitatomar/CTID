"""Feed management and pipeline endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..live_sources import CVE_SOURCES, LIVE_CONNECTORS
from ..models import Indicator, PipelineRun, Source
from ..pipeline import collect_all, collect_from_source
from ..scheduler import scheduler
from ..schemas import CollectRequest, SourceUpdate
from ..serializers import serialize_run, serialize_source

router = APIRouter(prefix="/api", tags=["feeds"])


@router.get("/sources")
def list_sources(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(
        select(
            Source,
            func.count(Indicator.id),
            func.coalesce(func.sum(case((Indicator.severity == "critical", 1), else_=0)), 0),
        )
        .outerjoin(Indicator, Indicator.source_id == Source.id)
        .group_by(Source.id)
        .order_by(Source.name)
    ).all()

    items = [serialize_source(source, int(count), int(critical)) for source, count, critical in rows]
    return {"items": items, "total": len(items)}


@router.patch("/sources/{source_id}")
def update_source(source_id: int, payload: SourceUpdate, db: Session = Depends(get_db)) -> dict:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    if payload.status is not None:
        source.status = payload.status
    db.commit()
    db.refresh(source)
    return serialize_source(source)


@router.post("/sources/{source_id}/collect")
def collect_source(source_id: int, payload: CollectRequest | None = None, db: Session = Depends(get_db)) -> dict:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    if source.status == "paused":
        raise HTTPException(status_code=409, detail="Source is paused; resume it before collecting")

    batch_size = payload.batch_size if payload else None
    run = collect_from_source(db, source, batch_size)
    db.refresh(run)
    return serialize_run(run, source.name)


@router.post("/pipeline/collect")
def collect_everything(payload: CollectRequest | None = None, db: Session = Depends(get_db)) -> dict:
    batch_size = payload.batch_size if payload else None
    runs = collect_all(db, batch_size)
    totals = {
        "collected": sum(run.collected for run in runs),
        "stored": sum(run.stored for run in runs),
        "duplicates": sum(run.duplicates for run in runs),
        "rejected": sum(run.rejected for run in runs),
        "sources": len(runs),
        "failed": sum(1 for run in runs if run.status == "failed"),
    }
    return {"totals": totals, "runs": [serialize_run(run, run.source.name if run.source else None) for run in runs]}


@router.get("/pipeline/status")
def pipeline_status() -> dict:
    """Scheduler state plus which sources can collect live under this config."""
    return {
        **scheduler.status(),
        "live_connectors": sorted(LIVE_CONNECTORS),
        "cve_feeds": list(CVE_SOURCES),
        "max_records_per_source": settings.max_records_per_source,
        "credentials": {
            "otx": bool(settings.otx_api_key),
            "nvd": bool(settings.nvd_api_key),
            "taxii": bool(settings.taxii_url and settings.taxii_collection),
        },
    }


@router.get("/pipeline/runs")
def list_runs(
    limit: int = Query(default=12, ge=1, le=100),
    source_id: int | None = None,
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(PipelineRun, Source.name).join(Source, Source.id == PipelineRun.source_id, isouter=True)
    if source_id:
        stmt = stmt.where(PipelineRun.source_id == source_id)
    rows = db.execute(stmt.order_by(PipelineRun.started_at.desc()).limit(limit)).all()

    stats = db.execute(
        select(
            func.count(PipelineRun.id),
            func.coalesce(func.sum(PipelineRun.collected), 0),
            func.coalesce(func.sum(PipelineRun.stored), 0),
            func.coalesce(func.sum(PipelineRun.duplicates), 0),
            func.coalesce(func.sum(PipelineRun.rejected), 0),
        )
    ).one()

    return {
        "items": [serialize_run(run, name) for run, name in rows],
        "summary": {
            "runs": int(stats[0] or 0),
            "collected": int(stats[1] or 0),
            "stored": int(stats[2] or 0),
            "duplicates": int(stats[3] or 0),
            "rejected": int(stats[4] or 0),
        },
    }
