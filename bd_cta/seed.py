"""Seed the database with sources, indicators, CVEs and pipeline history."""

from __future__ import annotations

from datetime import timedelta

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .cve_seed import CVE_SEEDS
from .feed_sources import SOURCE_SEEDS, generate_records
from .models import Indicator, PipelineRun, Source, Vulnerability, utcnow
from .normalize import hash_algorithm
from .pipeline import process_records

INDICATORS_PER_SOURCE = 34
HISTORY_DAYS = 29


def _seed_sources(db: Session) -> int:
    existing = set(db.scalars(select(Source.name)).all())
    created = 0
    for seed in SOURCE_SEEDS:
        if seed["name"] in existing:
            continue
        db.add(Source(**seed, status="active"))
        created += 1
    db.commit()
    return created


def _seed_indicators(db: Session) -> int:
    if db.scalar(select(func.count()).select_from(Indicator)):
        return 0

    sources = {source.name: source for source in db.scalars(select(Source)).all()}
    rng = np.random.default_rng(20260401)
    now = utcnow()
    seen: set[tuple[str, str]] = set()
    created = 0

    for index, seed in enumerate(SOURCE_SEEDS):
        source = sources.get(seed["name"])
        if source is None:
            continue
        records = generate_records(seed["name"], INDICATORS_PER_SOURCE, seed=index * 97 + 11)
        frame, _, _ = process_records(records)

        for row in frame.to_dict("records"):
            key = (row["type"], row["normalized"])
            if key in seen:
                continue
            seen.add(key)

            # Bias the history towards recent days so the trend chart is meaningful.
            days_ago = int(HISTORY_DAYS * (float(rng.random()) ** 1.6))
            first_seen = now - timedelta(
                days=days_ago,
                hours=int(rng.integers(0, 24)),
                minutes=int(rng.integers(0, 60)),
            )
            last_seen = min(now, first_seen + timedelta(hours=int(rng.integers(1, 96))))

            status_roll = float(rng.random())
            if status_roll > 0.94:
                status = "resolved"
            elif status_roll > 0.86:
                status = "monitoring"
            else:
                status = "active"

            db.add(
                Indicator(
                    value=row["value"].strip(),
                    normalized=row["normalized"],
                    type=row["type"],
                    hash_algorithm=hash_algorithm(row["normalized"]) if row["type"] == "hash" else None,
                    severity=row["severity"],
                    confidence=int(row["confidence"]),
                    status=status,
                    threat_type=row["threat_type"],
                    country=row["country"] or None,
                    tags=row["tags"],
                    description=row["description"],
                    report_count=int(rng.integers(1, 14)),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    source_id=source.id,
                )
            )
            created += 1

    db.commit()
    return created


def _seed_vulnerabilities(db: Session) -> int:
    existing = set(db.scalars(select(Vulnerability.cve_id)).all())
    created = 0
    for seed in CVE_SEEDS:
        if seed["cve_id"] in existing:
            continue
        db.add(
            Vulnerability(
                **seed,
                modified_at=seed["published_at"] + timedelta(days=14),
                source_name="CISA KEV" if seed["exploited"] else "NVD CVE API v2",
            )
        )
        created += 1
    db.commit()
    return created


def _seed_runs(db: Session) -> int:
    if db.scalar(select(func.count()).select_from(PipelineRun)):
        return 0

    rng = np.random.default_rng(77)
    now = utcnow()
    sources = db.scalars(select(Source).order_by(Source.id)).all()
    created = 0

    for cycle in range(6):
        cycle_start = now - timedelta(days=5 - cycle, hours=int(rng.integers(1, 6)))
        for source in sources:
            started = cycle_start - timedelta(minutes=int(rng.integers(0, 180)))
            collected = int(rng.integers(6, 18))
            duplicates = int(rng.integers(1, 6))
            rejected = int(rng.integers(0, 3))
            stored = max(0, collected - duplicates - rejected)
            db.add(
                PipelineRun(
                    source_id=source.id,
                    started_at=started,
                    finished_at=started + timedelta(seconds=int(rng.integers(4, 40))),
                    status="completed",
                    collected=collected,
                    normalized=collected - rejected,
                    duplicates=duplicates,
                    rejected=rejected,
                    stored=stored,
                    notes=(
                        f"{collected} collected, {stored} new, {duplicates} duplicates merged, "
                        f"{rejected} rejected during validation."
                    ),
                )
            )
            source.last_sync_at = started
            created += 1
    db.commit()
    return created


def seed_database(db: Session, force: bool = False) -> dict[str, int]:
    """Populate demo data. Existing rows are never duplicated."""
    counts = {"sources": 0, "indicators": 0, "vulnerabilities": 0, "runs": 0}
    if force:
        db.query(Indicator).delete()
        db.query(PipelineRun).delete()
        db.query(Vulnerability).delete()
        db.query(Source).delete()
        db.commit()

    counts["sources"] = _seed_sources(db)
    counts["indicators"] = _seed_indicators(db)
    counts["vulnerabilities"] = _seed_vulnerabilities(db)
    counts["runs"] = _seed_runs(db)
    return counts
