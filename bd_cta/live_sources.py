"""Live threat-intelligence connectors.

Every connector is split in two: a transport function that performs the HTTP
call and a pure ``parse_*`` function that turns a payload into the raw record
shape the pipeline expects. Parsers are unit-tested offline; only the transport
touches the network.

Raw record shape (unchanged from the bundled fixtures)::

    {"value", "severity", "confidence", "threat_type", "country", "tags", "description"}
"""

from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone
from typing import Callable

import httpx

from .config import settings

USER_AGENT = (
    "CTI-Sentinel/1.1 (threat-intelligence dashboard; "
    "+https://github.com/DivyanshThakur2004/Cyber-Threat-Intelligence-Dashboard)"
)

# abuse.ch returns HTTP 410 on the old keyless download paths. The export API
# carries the Auth-Key in the path and is refreshed every five minutes.
URLHAUS_EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
FEODO_IPBLOCKLIST_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
OTX_SUBSCRIBED_PULSES = "https://otx.alienvault.com/api/v1/pulses/subscribed"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVES_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# URLhaus threat column -> dashboard category.
URLHAUS_THREAT_TYPES = {
    "malware_download": "Malware Distribution",
    "malware": "Malware Distribution",
    "ransomware": "Ransomware",
    "phishing": "Phishing",
    "botnet": "Botnet",
}


class FeedError(RuntimeError):
    """A live fetch failed or returned nothing usable."""


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------
def rotate_window(items: list[dict], limit: int) -> list[dict]:
    """Take a rotating slice of a static feed.

    KEV and Feodo publish the same ordering every time, so a fixed ``[:limit]``
    would re-ingest the same records forever. Advancing the offset every ten
    minutes walks the whole feed over successive cycles.
    """
    if not items:
        return items
    size = max(1, limit)
    offset = (int(time.time()) // 600 * size) % len(items)
    return (items[offset:] + items[:offset])[:limit]


def http_get(url: str, *, params: dict | None = None, headers: dict | None = None) -> httpx.Response:
    """GET with a timeout, bounded retries and a descriptive failure mode."""
    merged_headers = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
    attempts = max(1, settings.http_retries + 1)
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            with httpx.Client(
                timeout=settings.http_timeout,
                follow_redirects=True,
                headers=merged_headers,
            ) as client:
                response = client.get(url, params=params)
            if response.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
                last_error = FeedError(f"{url} returned HTTP {response.status_code}")
                continue
            response.raise_for_status()
            return response
        except httpx.HTTPError as exc:  # network, timeout, TLS, status
            last_error = exc
            if attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))

    raise FeedError(f"request to {url} failed: {last_error}")


# ---------------------------------------------------------------------------
# Abuse.ch URLhaus — recent malicious URLs (CSV, no key required)
# ---------------------------------------------------------------------------
def parse_urlhaus_csv(text: str, limit: int) -> list[dict]:
    """Parse a URLhaus export.

    Accepts both the CSV database dump and the plain-text URL list, because the
    export endpoint can serve either depending on the file you request.
    """
    body = "\n".join(line for line in text.splitlines() if line.strip() and not line.startswith("#"))
    if not body:
        raise FeedError("URLhaus export contained no rows")

    first_line = body.splitlines()[0]
    if "," not in first_line:
        # Plain-text URL list: one indicator per line.
        return [
            {
                "value": url.strip(),
                "severity": "high",
                "confidence": 84,
                "threat_type": "Malware Distribution",
                "country": None,
                "tags": "urlhaus,malware",
                "description": "URLhaus plain-text malware URL export.",
            }
            for url in body.splitlines()
            if url.strip().lower().startswith(("http://", "https://", "hxxp"))
        ][:limit] or _urlhaus_empty()

    records: list[dict] = []
    for row in csv.DictReader(io.StringIO(body)):
        url = (row.get("url") or "").strip()
        if not url:
            continue
        threat = (row.get("threat") or "malware_download").strip().lower()
        status = (row.get("url_status") or "").strip().lower()
        tags = (row.get("tags") or "").strip()
        records.append(
            {
                "value": url,
                "severity": "critical" if status == "online" and threat == "ransomware" else "high",
                "confidence": 88 if status == "online" else 74,
                "threat_type": URLHAUS_THREAT_TYPES.get(threat, "Malware Distribution"),
                "country": None,
                "tags": ",".join(part.strip().lower() for part in tags.split(",") if part.strip()),
                "description": (
                    f"URLhaus entry {row.get('id', 'n/a')} ({status or 'unknown status'}), "
                    f"added {row.get('dateadded', 'unknown date')}."
                ),
            }
        )
        if len(records) >= limit:
            break

    if not records:
        raise FeedError("URLhaus returned no usable URLs")
    return records


def _urlhaus_empty() -> list[dict]:
    raise FeedError("URLhaus export contained no usable URLs")


def fetch_urlhaus(limit: int) -> list[dict]:
    if not settings.abusech_auth_key:
        raise FeedError("ABUSECH_AUTH_KEY is not configured (abuse.ch requires an Auth-Key)")
    response = http_get(URLHAUS_EXPORT_URL.format(key=settings.abusech_auth_key))
    return parse_urlhaus_csv(response.text, limit)


# ---------------------------------------------------------------------------
# Abuse.ch Feodo Tracker — botnet C2 IP blocklist (JSON, no key required)
# ---------------------------------------------------------------------------
def parse_feodo_json(payload: object, limit: int) -> list[dict]:
    if isinstance(payload, dict):
        entries = payload.get("data") or []
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = []

    records: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ip = str(entry.get("ip_address") or "").strip()
        if not ip:
            continue
        malware = str(entry.get("malware") or "unknown").strip()
        online = str(entry.get("status") or "").strip().lower() == "online"
        first_seen = str(entry.get("first_seen") or "").strip()
        records.append(
            {
                "value": ip,
                "severity": "critical" if online else "high",
                "confidence": 92 if online else 80,
                "threat_type": "Command & Control",
                "country": (str(entry.get("country") or "").strip().upper() or None),
                "tags": ",".join(tag for tag in ("c2", "botnet", malware.lower()) if tag),
                "description": (
                    f"Feodo Tracker {malware} C2 server on port {entry.get('port', '?')}, "
                    f"{'online' if online else 'offline'}, first seen {first_seen or 'unknown'}."
                ),
            }
        )
        if len(records) >= limit:
            break

    if not records:
        raise FeedError("Feodo Tracker returned no C2 addresses")
    return records


def fetch_feodo(limit: int) -> list[dict]:
    headers = {"Auth-Key": settings.abusech_auth_key} if settings.abusech_auth_key else None
    response = http_get(FEODO_IPBLOCKLIST_JSON, headers=headers)
    return rotate_window(parse_feodo_json(response.json(), 1000), limit)


# ---------------------------------------------------------------------------
# AlienVault OTX — community pulses (requires OTX_API_KEY)
# ---------------------------------------------------------------------------
OTX_TYPE_MAP = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "filehash-md5": "hash",
    "filehash-sha1": "hash",
    "filehash-sha256": "hash",
    "filehash-sha512": "hash",
}


def parse_otx_pulses(payload: object, limit: int) -> list[dict]:
    pulses = payload.get("results", []) if isinstance(payload, dict) else []
    records: list[dict] = []

    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        pulse_name = str(pulse.get("name") or "OTX pulse").strip()
        tags = [str(tag).strip().lower() for tag in (pulse.get("tags") or []) if str(tag).strip()]
        for indicator in pulse.get("indicators") or []:
            if not isinstance(indicator, dict):
                continue
            kind = str(indicator.get("type") or "").strip().lower()
            if kind not in OTX_TYPE_MAP:
                continue
            value = str(indicator.get("indicator") or "").strip()
            if not value:
                continue
            records.append(
                {
                    "value": value,
                    "severity": "high" if "ransomware" in tags or "apt" in tags else "medium",
                    "confidence": 70,
                    "threat_type": "Phishing" if "phishing" in tags else "Command & Control",
                    "country": None,
                    "tags": ",".join(tags[:4]),
                    "description": f"OTX pulse “{pulse_name[:120]}” reported this {kind} indicator.",
                }
            )
            if len(records) >= limit:
                return records

    if not records:
        raise FeedError("OTX returned no supported indicators (is OTX_API_KEY valid?)")
    return records


def fetch_otx(limit: int) -> list[dict]:
    if not settings.otx_api_key:
        raise FeedError("OTX_API_KEY is not configured")
    response = http_get(
        OTX_SUBSCRIBED_PULSES,
        params={"limit": max(1, min(50, limit // 2 or 1)), "page": 1},
        headers={"X-OTX-API-KEY": settings.otx_api_key},
    )
    return parse_otx_pulses(response.json(), limit)


# ---------------------------------------------------------------------------
# STIX 2.1 / TAXII 2.1 — indicator objects from a configured collection
# ---------------------------------------------------------------------------
STIX_PATTERN_TYPES = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "file": "hash",
}


def indicators_from_bundle(bundle: object) -> list[dict]:
    """Map STIX 2.1 indicator objects onto raw records (pattern parsing)."""
    import re

    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
    records: list[dict] = []

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = str(obj.get("pattern") or "")
        match = re.search(r"\[([a-z0-9-]+):([a-z0-9_.'\-]+)\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        if not match:
            continue
        stix_type, path, value = match.group(1).lower(), match.group(2).lower(), match.group(3).strip()
        if stix_type not in STIX_PATTERN_TYPES or not value:
            continue
        if stix_type == "file" and "hash" not in path:
            continue

        labels = [str(label).lower() for label in (obj.get("labels") or [])]
        records.append(
            {
                "value": value,
                "severity": "high" if {"malicious-activity", "ransomware"} & set(labels) else "medium",
                "confidence": 72,
                "threat_type": "Malware Distribution" if stix_type == "file" else "Command & Control",
                "country": None,
                "tags": ",".join(labels[:4]) or "stix",
                "description": (
                    f"STIX indicator {obj.get('name') or value} "
                    f"(valid from {obj.get('valid_from', 'unknown')})."
                ),
            }
        )

    return records


def fetch_taxii(limit: int) -> list[dict]:
    """Poll a TAXII 2.1 collection for STIX indicator objects."""
    if not settings.taxii_url or not settings.taxii_collection:
        raise FeedError("TAXII_URL and TAXII_COLLECTION are not configured")

    headers = {"Accept": "application/taxii+json;version=2.1"}
    if settings.taxii_token:
        headers["Authorization"] = f"Bearer {settings.taxii_token}"

    response = http_get(
        f"{settings.taxii_url}/collections/{settings.taxii_collection}/objects",
        params={"limit": max(1, min(500, limit * 4)), "match[type]": "indicator"},
        headers=headers,
    )
    records = indicators_from_bundle(response.json())
    if not records:
        raise FeedError("TAXII collection returned no STIX indicator objects")
    return records[:limit]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# Source name (as stored in ``sources.name``) -> live connector.
LIVE_CONNECTORS: dict[str, Callable[[int], list[dict]]] = {
    "Abuse.ch URLhaus": fetch_urlhaus,
    "Abuse.ch Feodo Tracker": fetch_feodo,
    "AlienVault OTX — Community Pulses": fetch_otx,
    "MITRE ATT&CK — TAXII 2.1": fetch_taxii,
}

# Sources that populate the vulnerability table instead of the indicator table.
CVE_SOURCES = ("CISA Known Exploited Vulnerabilities", "NVD CVE API v2")


def is_cve_source(name: str) -> bool:
    return name in CVE_SOURCES


def live_capable(name: str) -> bool:
    if is_cve_source(name):
        return True
    connector = LIVE_CONNECTORS.get(name)
    if connector is fetch_urlhaus and not settings.abusech_auth_key:
        return False
    if connector is fetch_otx and not settings.otx_api_key:
        return False
    if connector is fetch_taxii and not (settings.taxii_url and settings.taxii_collection):
        return False
    return connector is not None


def source_mode(name: str) -> str:
    """How a source will be collected under the current configuration."""
    if settings.feed_mode == "fixture" or not live_capable(name):
        return "fixture"
    return "live"


def fetch_live_records(name: str, limit: int) -> list[dict]:
    connector = LIVE_CONNECTORS.get(name)
    if connector is None:
        raise FeedError(f"no live connector registered for {name}")
    return connector(limit)


def fetch_live_cves(name: str, limit: int) -> list[dict]:
    from .cve_collectors import fetch_cisa_kev, fetch_nvd_recent

    if name == "CISA Known Exploited Vulnerabilities":
        return fetch_cisa_kev(limit)
    if name == "NVD CVE API v2":
        return fetch_nvd_recent(limit)
    raise FeedError(f"{name} is not a vulnerability feed")


def utc_stamp(value: str | None) -> datetime | None:
    """Parse the assorted ISO-8601 flavours NVD/CISA emit."""
    if not value:
        return None
    cleaned = value.strip().replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T")):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedError(f"feed returned invalid JSON: {exc}") from exc
