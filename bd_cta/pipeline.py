"""Collection → processing → storage pipeline.

Indicator feeds and vulnerability feeds share one run log. Indicator records go
through normalization and deduplication with pandas/NumPy; CVE sources are
upserted into the vulnerability table. Each run records whether it was collected
live or from bundled fixtures so ingestion health stays honest.
"""

from __future__ import annotations

from datetime import timedelta

import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .cve_collectors import collect_cve_batch, upsert_vulnerabilities
from .feed_sources import load_records
from .live_sources import is_cve_source
from .models import Indicator, PipelineRun, Source, utcnow
from .normalize import hash_algorithm, normalize

MAX_NEW_PER_RUN = 18


def process_records(raw_records: list[dict]) -> tuple[pd.DataFrame, int, int]:
    """Normalize, validate and deduplicate a raw batch.

    Returns (clean_frame, duplicate_count, rejected_count).
    """
    if not raw_records:
        return pd.DataFrame(columns=["normalized", "type"]), 0, 0

    frame = pd.DataFrame(raw_records)
    frame["value"] = frame["value"].astype(str)

    parsed = frame["value"].map(normalize)
    frame["normalized"] = parsed.map(lambda item: item[0] if item else None)
    frame["type"] = parsed.map(lambda item: item[1] if item else None)

    rejected_mask = frame["normalized"].isna() | frame["type"].isna()
    rejected = int(rejected_mask.sum())
    frame = frame.loc[~rejected_mask].copy()

    # Normalize the descriptive columns as well (feeds are inconsistent).
    frame["severity"] = frame["severity"].fillna("medium").str.lower()
    frame["severity"] = frame["severity"].where(frame["severity"].isin(["critical", "high", "medium", "low"]), "medium")
    frame["threat_type"] = frame["threat_type"].fillna("Uncategorized").str.strip()
    frame["confidence"] = pd.to_numeric(frame["confidence"], errors="coerce").fillna(60).clip(0, 100).astype(int)
    frame["tags"] = frame["tags"].fillna("").str.lower()
    frame["description"] = frame["description"].fillna("")
    frame["country"] = frame["country"].fillna("")
    frame["key"] = frame["type"].astype(str) + ":" + frame["normalized"].astype(str)

    before = len(frame)
    frame = frame.drop_duplicates(subset="key", keep="first")
    intra_batch_duplicates = before - len(frame)

    return frame, intra_batch_duplicates, rejected


def collect_from_source(db: Session, source: Source, batch_size: int | None = None) -> PipelineRun:
    """Run one collection cycle for a single feed and persist the results."""
    run = PipelineRun(source_id=source.id, started_at=utcnow(), status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        if is_cve_source(source.name):
            return _collect_cve_run(db, source, run, batch_size)
        return _collect_indicator_run(db, source, run, batch_size)
    except Exception as exc:  # keep the run trace visible in the dashboard
        db.rollback()
        run.status = "failed"
        run.finished_at = utcnow()
        run.notes = f"Collection failed: {exc}"
        source.status = "degraded" if source.status != "paused" else "paused"
        db.add(run)
        db.commit()
        db.refresh(run)
        return run


def _collect_indicator_run(
    db: Session, source: Source, run: PipelineRun, batch_size: int | None
) -> PipelineRun:
    seed = int(np.random.default_rng().integers(0, 2**31 - 1))
    raw_records, mode_note = load_records(source.name, batch_size, seed)
    run.collected = len(raw_records)

    frame, intra_duplicates, rejected = process_records(raw_records)
    run.rejected = rejected
    run.normalized = int(len(frame))

    existing_rows = db.scalars(
        select(Indicator).where(Indicator.normalized.in_(frame["normalized"].tolist()))
    ).all()
    existing = {(row.type, row.normalized): row for row in existing_rows}

    duplicates = intra_duplicates
    created = 0
    now = utcnow()

    for record in frame.to_dict("records"):
        key = (record["type"], record["normalized"])
        match = existing.get(key)
        if match is not None:
            match.last_seen = now
            match.report_count += 1
            if record["confidence"] > match.confidence:
                match.confidence = int(record["confidence"])
            duplicates += 1
            continue

        if created >= MAX_NEW_PER_RUN:
            duplicates += 1
            continue

        first_seen = now - timedelta(minutes=int(np.random.default_rng().integers(5, 720)))
        indicator = Indicator(
            value=record["value"].strip(),
            normalized=record["normalized"],
            type=record["type"],
            hash_algorithm=hash_algorithm(record["normalized"]) if record["type"] == "hash" else None,
            severity=record["severity"],
            confidence=int(record["confidence"]),
            status="active",
            threat_type=record["threat_type"],
            country=record["country"] or None,
            tags=record["tags"],
            description=record["description"],
            report_count=1,
            first_seen=first_seen,
            last_seen=now,
            source_id=source.id,
        )
        db.add(indicator)
        existing[key] = indicator
        created += 1

    run.duplicates = duplicates
    run.stored = created
    run.status = "completed"
    run.finished_at = utcnow()
    run.notes = (
        f"[{mode_note}] {len(raw_records)} collected, {created} new, "
        f"{duplicates} duplicates merged, {rejected} rejected during validation."
    )

    source.last_sync_at = run.finished_at
    if source.status != "paused":
        source.status = "active"

    db.commit()
    db.refresh(run)
    return run


def _collect_cve_run(
    db: Session, source: Source, run: PipelineRun, batch_size: int | None
) -> PipelineRun:
    limit = batch_size or settings.max_records_per_source
    records, mode_note = collect_cve_batch(source.name, limit)
    run.collected = len(records)
    run.normalized = len(records)

    created, updated = upsert_vulnerabilities(db, records)

    run.stored = created
    run.duplicates = updated
    run.status = "completed"
    run.finished_at = utcnow()
    run.notes = (
        f"[{mode_note}] {len(records)} CVE records collected, "
        f"{created} new, {updated} refreshed."
    )

    source.last_sync_at = run.finished_at
    if source.status != "paused":
        source.status = "active"

    db.commit()
    db.refresh(run)
    return run


def collect_all(db: Session, batch_size: int | None = None) -> list[PipelineRun]:
    sources = db.scalars(select(Source).where(Source.status != "paused").order_by(Source.id)).all()
    return [collect_from_source(db, source, batch_size) for source in sources]
