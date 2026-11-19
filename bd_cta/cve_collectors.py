"""CVE ingestion: CISA KEV and NVD into the vulnerability table.

The KEV feed carries exploitation facts but no CVSS, while NVD carries CVSS and
affected products. Records are upserted, so a CVE seen in both sources keeps the
exploitation flag from KEV and the score from NVD.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .cve_seed import CVE_SEEDS
from .live_sources import (
    CISA_KEV_JSON,
    NVD_CVES_API,
    FeedError,
    http_get,
    parse_json,
    rotate_window,
    utc_stamp,
)
from .models import Vulnerability, utcnow


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Parsers (pure, unit-tested offline)
# ---------------------------------------------------------------------------
def parse_cisa_kev(payload: object, limit: int) -> list[dict]:
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    records: list[dict] = []

    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        ransomware = str(item.get("knownRansomwareCampaignUse") or "").lower() == "known"
        vendor = str(item.get("vendorProject") or "").strip()
        product = str(item.get("product") or "").strip()
        published = utc_stamp(str(item.get("dateAdded") or "")) or utcnow()
        records.append(
            {
                "cve_id": cve_id,
                "title": str(item.get("vulnerabilityName") or cve_id)[:200],
                "description": str(item.get("shortDescription") or ""),
                "cvss": 0.0,  # KEV publishes no CVSS; NVD enriches the record
                "severity": "critical" if ransomware else "high",
                "affected_products": f"{vendor} {product}".strip()[:255],
                "exploited": True,
                "patch_available": True,
                "published_at": published,
                "modified_at": utcnow(),
                "references": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source_name": "CISA Known Exploited Vulnerabilities",
            }
        )
        if len(records) >= limit:
            break

    if not records:
        raise FeedError("CISA KEV feed contained no CVE records")
    return records


def _nvd_metric(cve: dict) -> tuple[float, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0] or {}
        data = entry.get("cvssData") or {}
        try:
            score = float(data.get("baseScore", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return score, str(severity).lower() if severity else None
    return 0.0, None


def _nvd_products(cve: dict) -> str:
    products: list[str] = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    label = f"{parts[3]} {parts[4]}".replace("_", " ").strip()
                    if label and label not in products:
                        products.append(label)
                if len(products) >= 6:
                    return ", ".join(products)[:255]
    return ", ".join(products)[:255]


def parse_nvd(payload: object, limit: int) -> list[dict]:
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    records: list[dict] = []

    for item in vulnerabilities:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue

        description = ""
        for entry in cve.get("descriptions") or []:
            if str(entry.get("lang", "")).lower() == "en":
                description = str(entry.get("value") or "")
                break

        score, severity = _nvd_metric(cve)
        references = [
            str(ref.get("url"))
            for ref in (cve.get("references") or [])
            if isinstance(ref, dict) and ref.get("url")
        ]
        tags = {
            str(tag).lower()
            for ref in (cve.get("references") or [])
            if isinstance(ref, dict)
            for tag in (ref.get("tags") or [])
        }

        records.append(
            {
                "cve_id": cve_id,
                "title": (description[:197] + "...") if len(description) > 200 else (description or cve_id),
                "description": description,
                "cvss": score,
                "severity": severity or _severity_from_score(score),
                "affected_products": _nvd_products(cve),
                "exploited": "exploit" in tags,
                "patch_available": "patch" in tags,
                "published_at": utc_stamp(str(cve.get("published") or "")) or utcnow(),
                "modified_at": utc_stamp(str(cve.get("lastModified") or "")) or utcnow(),
                "references": "\n".join(references[:8])[:4000]
                or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source_name": "NVD CVE API v2",
            }
        )
        if len(records) >= limit:
            break

    if not records:
        raise FeedError("NVD returned no CVE records")
    return records


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------
def fetch_cisa_kev(limit: int) -> list[dict]:
    response = http_get(CISA_KEV_JSON)
    # The catalogue holds ~1.5k entries; rotate so each cycle ingests a new slice.
    return rotate_window(parse_cisa_kev(parse_json(response.text), 5000), limit)


def fetch_nvd_recent(limit: int) -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    response = http_get(
        NVD_CVES_API,
        params={
            "resultsPerPage": max(1, min(limit, 200)),
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        },
        headers=headers,
    )
    return parse_nvd(parse_json(response.text), limit)


# ---------------------------------------------------------------------------
# Offline fixtures (bundled public CVE records)
# ---------------------------------------------------------------------------
def fixture_cve_records(source_name: str, limit: int) -> list[dict]:
    offset = datetime.now(timezone.utc).timetuple().tm_yday % max(1, len(CVE_SEEDS))
    rotated = CVE_SEEDS[offset:] + CVE_SEEDS[:offset]
    chosen = rotated[: max(1, min(limit, 12))]

    return [
        {
            "cve_id": seed["cve_id"],
            "title": seed["title"][:200],
            "description": seed["description"],
            "cvss": float(seed["cvss"]),
            "severity": seed["severity"],
            "affected_products": seed["affected_products"][:255],
            "exploited": bool(seed["exploited"]),
            "patch_available": bool(seed["patch_available"]),
            "published_at": seed["published_at"],
            "modified_at": utcnow(),
            "references": seed["references"],
            "source_name": source_name,
        }
        for seed in chosen
    ]


def collect_cve_batch(source_name: str, limit: int) -> tuple[list[dict], str]:
    """Return (records, mode note) for one CVE source."""
    if settings.feed_mode != "fixture":
        try:
            from .live_sources import fetch_live_cves

            return fetch_live_cves(source_name, limit), "live"
        except FeedError as exc:
            if settings.feed_mode == "live":
                raise
            return fixture_cve_records(source_name, limit), f"fixture fallback: {exc}"
    return fixture_cve_records(source_name, limit), "fixture"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def upsert_vulnerabilities(db: Session, records: list[dict]) -> tuple[int, int]:
    """Insert new CVEs and merge updates into existing ones. Returns (created, updated)."""
    created = 0
    updated = 0

    for record in records:
        existing = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == record["cve_id"]))
        if existing is None:
            db.add(Vulnerability(**record))
            created += 1
            continue

        # Never downgrade facts: KEV exploitation survives an NVD refresh, and a
        # CVSS of 0 from KEV must not overwrite a real NVD score.
        if record["cvss"] > 0:
            existing.cvss = record["cvss"]
            existing.severity = record["severity"]
        elif existing.cvss == 0 and existing.severity != "critical":
            existing.severity = record["severity"]

        existing.exploited = existing.exploited or record["exploited"]
        existing.patch_available = existing.patch_available or record["patch_available"]
        existing.title = record["title"] or existing.title
        existing.description = existing.description or record["description"]
        existing.affected_products = existing.affected_products or record["affected_products"]
        existing.references = existing.references or record["references"]
        existing.modified_at = record["modified_at"]
        updated += 1

    db.commit()
    return created, updated
