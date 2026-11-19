"""Request models (validation) for the API."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = ("active", "monitoring", "resolved", "false_positive")


class IndicatorCreate(BaseModel):
    value: str = Field(min_length=3, max_length=512, examples=["hxxps://login-verify-42[.]example/login"])
    severity: str = Field(default="medium")
    confidence: int = Field(default=60, ge=0, le=100)
    threat_type: str = Field(default="Uncategorized", max_length=60)
    description: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list)
    country: str | None = Field(default=None, max_length=8)
    source_id: int | None = None
    status: str = Field(default="active")

    @field_validator("severity")
    @classmethod
    def _severity(cls, value: str) -> str:
        lowered = (value or "").strip().lower()
        if lowered not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        return lowered

    @field_validator("status")
    @classmethod
    def _status(cls, value: str) -> str:
        lowered = (value or "").strip().lower()
        if lowered not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        return lowered


class IndicatorUpdate(BaseModel):
    severity: str | None = None
    status: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)

    @field_validator("severity")
    @classmethod
    def _severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.strip().lower()
        if lowered not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        return lowered

    @field_validator("status")
    @classmethod
    def _status(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.strip().lower()
        if lowered not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        return lowered


class CollectRequest(BaseModel):
    source_id: int | None = Field(default=None, description="Collect from one feed, or all feeds when omitted.")
    batch_size: int | None = Field(default=None, ge=1, le=200)


class SourceUpdate(BaseModel):
    status: str | None = None

    @field_validator("status")
    @classmethod
    def _status(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.strip().lower()
        if lowered not in ("active", "degraded", "paused"):
            raise ValueError("status must be one of active, degraded, paused")
        return lowered
