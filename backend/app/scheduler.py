"""Background collection loop.

Runs a full collection cycle every ``CTI_COLLECT_INTERVAL_MINUTES`` minutes in a
worker thread (the SQLAlchemy session and HTTP clients are blocking), and exposes
its state for the dashboard's ingestion panel. No external scheduler dependency.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from .config import settings
from .database import SessionLocal
from .pipeline import collect_all

logger = logging.getLogger("cti.scheduler")


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if moment else None


class CollectionScheduler:
    """Interval loop that keeps the corpus current without operator action."""

    def __init__(self) -> None:
        self.interval_minutes = settings.collect_interval_minutes
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self.running = False
        self.last_run_at: datetime | None = None
        self.next_run_at: datetime | None = None
        self.last_result: dict | None = None
        self.last_error: str | None = None
        self.cycles = 0

    @property
    def enabled(self) -> bool:
        return self.interval_minutes > 0

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        if not self.enabled or self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="cti-collector")
        logger.info("Collection scheduler started (every %s min)", self.interval_minutes)

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - shutdown must not raise
                pass
            self._task = None
        logger.info("Collection scheduler stopped")

    # -- loop ------------------------------------------------------------
    async def _loop(self) -> None:
        interval = timedelta(minutes=self.interval_minutes)
        if settings.collect_on_start:
            await self._cycle()
        while not self._stopping.is_set():
            self.next_run_at = datetime.now(timezone.utc) + interval
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval.total_seconds())
                break
            except asyncio.TimeoutError:
                await self._cycle()

    async def _cycle(self) -> None:
        if self.running:
            return
        self.running = True
        started = datetime.now(timezone.utc)
        try:
            result = await asyncio.to_thread(self._run_cycle)
            self.last_result = result
            self.last_error = None
        except Exception as exc:  # a bad feed must never kill the loop
            self.last_error = str(exc)
            logger.exception("Scheduled collection cycle failed")
        finally:
            self.running = False
            self.last_run_at = started
            self.cycles += 1

    @staticmethod
    def _run_cycle() -> dict:
        with SessionLocal() as db:
            runs = collect_all(db)
        return {
            "sources": len(runs),
            "failed": sum(1 for run in runs if run.status == "failed"),
            "collected": sum(run.collected for run in runs),
            "stored": sum(run.stored for run in runs),
            "duplicates": sum(run.duplicates for run in runs),
            "rejected": sum(run.rejected for run in runs),
        }

    # -- introspection ---------------------------------------------------
    def status(self) -> dict:
        return {
            "mode": settings.feed_mode,
            "enabled": self.enabled,
            "interval_minutes": self.interval_minutes,
            "collect_on_start": settings.collect_on_start,
            "running": self.running,
            "cycles": self.cycles,
            "last_run_at": _iso(self.last_run_at),
            "next_run_at": _iso(self.next_run_at) if self.enabled and not self._stopping.is_set() else None,
            "last_result": self.last_result,
            "last_error": self.last_error,
        }


scheduler = CollectionScheduler()
