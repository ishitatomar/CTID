"""Configuration loaded from environment variables (with optional .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so the app has no dependency on python-dotenv."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value: str, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _feed_mode(value: str) -> str:
    lowered = value.strip().lower()
    return lowered if lowered in {"auto", "live", "fixture"} else "auto"


@dataclass(frozen=True)
class Settings:
    app_name: str = "Cyber Threat Intelligence API"
    version: str = "1.1.0"
    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'cti.db'}")
    seed_on_startup: bool = _as_bool(os.getenv("CTI_SEED_ON_STARTUP", "true"))
    cors_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "CTI_CORS_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000,"
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    )

    # --- Live collection -------------------------------------------------
    # auto    : live connector when one exists, bundled fixtures as fallback
    # live    : live only; a failed fetch is recorded as a failed pipeline run
    # fixture : never touch the network (offline demos, CI)
    feed_mode: str = _feed_mode(os.getenv("CTI_FEED_MODE", "auto"))
    http_timeout: float = _as_float(os.getenv("CTI_HTTP_TIMEOUT", "25"), 25.0)
    http_retries: int = _as_int(os.getenv("CTI_HTTP_RETRIES", "2"), 2)
    max_records_per_source: int = _as_int(os.getenv("CTI_MAX_RECORDS_PER_SOURCE", "60"), 60)

    # Credentials — only needed for feeds that require them.
    otx_api_key: str = os.getenv("OTX_API_KEY", "").strip()
    nvd_api_key: str = os.getenv("NVD_API_KEY", "").strip()
    # abuse.ch made an Auth-Key mandatory in 2025; the same key unlocks URLhaus,
    # MalwareBazaar and friends. https://auth.abuse.ch
    abusech_auth_key: str = (
        os.getenv("ABUSECH_AUTH_KEY", "").strip() or os.getenv("URLHAUS_AUTH_KEY", "").strip()
    )

    # Generic TAXII 2.1 collection poller (used by the ATT&CK source).
    taxii_url: str = os.getenv("TAXII_URL", "").strip().rstrip("/")
    taxii_collection: str = os.getenv("TAXII_COLLECTION", "").strip()
    taxii_token: str = os.getenv("TAXII_TOKEN", "").strip()

    # Background collection loop.
    collect_interval_minutes: int = _as_int(os.getenv("CTI_COLLECT_INTERVAL_MINUTES", "15"), 15)
    collect_on_start: bool = _as_bool(os.getenv("CTI_COLLECT_ON_START", "false"))


settings = Settings()
