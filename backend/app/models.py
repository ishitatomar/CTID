"""SQLAlchemy models for the threat-intelligence store."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Source(Base):
    """An authorized threat-intelligence feed or API."""

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(40))  # REST API | STIX 2.1 | TAXII 2.1 | JSON feed
    url: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    trust_score: Mapped[int] = mapped_column(Integer, default=70)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | degraded | paused
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    indicators: Mapped[list["Indicator"]] = relationship(back_populates="source")
    runs: Mapped[list["PipelineRun"]] = relationship(back_populates="source")


class Indicator(Base):
    """A normalized indicator of compromise (IoC)."""

    __tablename__ = "indicators"
    __table_args__ = (
        Index("ix_indicators_type_normalized", "type", "normalized", unique=True),
        Index("ix_indicators_severity", "severity"),
        Index("ix_indicators_first_seen", "first_seen"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(512))  # as reported by the feed
    normalized: Mapped[str] = mapped_column(String(512), index=True)  # canonical form
    type: Mapped[str] = mapped_column(String(16))  # ip | domain | url | hash
    hash_algorithm: Mapped[str | None] = mapped_column(String(12), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | monitoring | resolved | false_positive
    threat_type: Mapped[str] = mapped_column(String(60), default="Uncategorized")
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    tags: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    report_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    source: Mapped[Source] = relationship(back_populates="indicators")


class Vulnerability(Base):
    """A CVE record collected from vulnerability feeds."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    affected_products: Mapped[str] = mapped_column(String(255), default="")
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    references: Mapped[str] = mapped_column(Text, default="")  # newline separated URLs
    source_name: Mapped[str] = mapped_column(String(120), default="NVD CVE API v2")


class PipelineRun(Base):
    """One execution of the collection → processing → storage pipeline."""

    __tablename__ = "pipeline_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id"), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running | completed | failed
    collected: Mapped[int] = mapped_column(Integer, default=0)
    normalized: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    stored: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str] = mapped_column(Text, default="")

    source: Mapped[Source | None] = relationship(back_populates="runs")
