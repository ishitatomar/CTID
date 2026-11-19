"""Pytest fixtures: an isolated SQLite database seeded with demo data."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

DB_PATH = Path(tempfile.mkdtemp(prefix="cti-test-")) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["CTI_SEED_ON_STARTUP"] = "true"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client
