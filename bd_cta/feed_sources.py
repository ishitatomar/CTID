"""Bundled feed snapshots used by the collection layer.

The project is built around *authorized* threat-intelligence sources. In this
demo the HTTP connectors are replaced by deterministic fixture generators so
the pipeline can be exercised end to end without API keys or network access.

Each generator returns raw, deliberately messy records — mixed case, defanged
values, duplicates and a few invalid entries — exactly what real feeds look
like before processing. To go live, replace :func:`fetch_raw_records` with an
HTTP client for the source in ``signature`` and return the same record shape.
"""

from __future__ import annotations

import hashlib

import numpy as np

SOURCE_SEEDS: list[dict] = [
    {
        "name": "AlienVault OTX — Community Pulses",
        "kind": "REST API",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "description": "Subscribed community pulses containing domains, URLs and hashes.",
        "trust_score": 78,
    },
    {
        "name": "Abuse.ch URLhaus",
        "kind": "REST API",
        "url": "https://urlhaus-api.abuse.ch/v1/",
        "description": "Malware distribution URLs reported by the community.",
        "trust_score": 86,
    },
    {
        "name": "Abuse.ch Feodo Tracker",
        "kind": "REST API",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist/",
        "description": "Botnet command-and-control IP blocklist.",
        "trust_score": 84,
    },
    {
        "name": "CISA Known Exploited Vulnerabilities",
        "kind": "JSON feed",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "Vulnerabilities with confirmed in-the-wild exploitation.",
        "trust_score": 95,
    },
    {
        "name": "NVD CVE API v2",
        "kind": "REST API",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "description": "CVE records with CVSS base metrics and affected products.",
        "trust_score": 92,
    },
    {
        "name": "MITRE ATT&CK — TAXII 2.1",
        "kind": "TAXII 2.1",
        "url": "https://attack-taxii.mitre.org/taxii2/collections/",
        "description": "Adversary infrastructure observable objects as STIX bundles.",
        "trust_score": 90,
    },
    {
        "name": "Spamhaus DROP (STIX 2.1)",
        "kind": "STIX 2.1",
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "description": "Hijacked and leased netblocks used for spam and abuse.",
        "trust_score": 88,
    },
]

THREAT_TYPES = [
    "Command & Control",
    "Phishing",
    "Malware Distribution",
    "Ransomware",
    "Botnet",
    "Credential Harvesting",
    "Exploit Kit",
    "Scanning Activity",
]

COUNTRIES = ["RU", "CN", "IR", "KP", "BR", "VN", "IN", "NL", "UA", "TR", "NG", "US"]

DOMAIN_PREFIXES = [
    "secure-login",
    "account-verify",
    "invoice-portal",
    "update-service",
    "cloud-share",
    "auth-check",
    "billing-support",
    "payroll-docs",
    "delivery-track",
    "vpn-access",
    "mfa-reset",
    "bank-alert",
    "teams-file",
    "docusign-view",
    "onedrive-share",
    "hr-portal",
    "it-helpdesk",
    "payment-confirm",
]

# RFC 2606 reserved TLDs — no real infrastructure is referenced anywhere.
DOMAIN_TLDS = ["example", "example.com", "example.net", "example.org"]

URL_PATHS = [
    "login/verify",
    "auth/session",
    "download/invoice.zip",
    "update/patch.exe",
    "docs/share",
    "pay/confirm",
    "portal/sso",
    "files/receipt.pdf.exe",
]

TAG_POOL = [
    "c2",
    "phishing",
    "credential-theft",
    "dropper",
    "ransomware",
    "botnet",
    "malware",
    "exploit",
    "payload",
    "bruteforce",
]

TEST_NET_BLOCKS = ["192.0.2", "198.51.100", "203.0.113"]

SEVERITY_BY_TYPE = {
    "Command & Control": "critical",
    "Ransomware": "critical",
    "Credential Harvesting": "high",
    "Phishing": "high",
    "Malware Distribution": "high",
    "Botnet": "medium",
    "Exploit Kit": "high",
    "Scanning Activity": "low",
}

# How many raw records each feed contributes per collection cycle.
FEED_VOLUME = {
    "AlienVault OTX — Community Pulses": 12,
    "Abuse.ch URLhaus": 14,
    "Abuse.ch Feodo Tracker": 9,
    "CISA Known Exploited Vulnerabilities": 3,
    "NVD CVE API v2": 4,
    "MITRE ATT&CK — TAXII 2.1": 6,
    "Spamhaus DROP (STIX 2.1)": 8,
}


def _defang_url(url: str) -> str:
    return url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def _defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def _make_ip(rng: np.random.Generator) -> str:
    block = TEST_NET_BLOCKS[int(rng.integers(0, len(TEST_NET_BLOCKS)))]
    return f"{block}.{int(rng.integers(1, 255))}"


def _make_domain(rng: np.random.Generator) -> str:
    prefix = DOMAIN_PREFIXES[int(rng.integers(0, len(DOMAIN_PREFIXES)))]
    tld = DOMAIN_TLDS[int(rng.integers(0, len(DOMAIN_TLDS)))]
    return f"{prefix}-{int(rng.integers(10, 99))}.{tld}"


def _make_url(rng: np.random.Generator) -> str:
    scheme = "https" if rng.random() > 0.35 else "http"
    path = URL_PATHS[int(rng.integers(0, len(URL_PATHS)))]
    token = hashlib.sha1(f"{rng.random()}".encode()).hexdigest()[:8]
    return f"{scheme}://{_make_domain(rng)}/{path}?id={token}"


def _make_hash(rng: np.random.Generator) -> str:
    algorithm = ["sha256", "sha1", "md5"][int(rng.integers(0, 3))]
    body = hashlib.sha256(f"malware-sample-{rng.random()}".encode()).hexdigest()
    return body if algorithm == "sha256" else hashlib.new(algorithm, body.encode()).hexdigest()


def _make_type(rng: np.random.Generator) -> str:
    return ["ip", "domain", "url", "hash"][int(rng.integers(0, 4))]


def _make_value(rng: np.random.Generator, itype: str) -> str:
    if itype == "ip":
        return _make_ip(rng)
    if itype == "domain":
        return _make_domain(rng)
    if itype == "url":
        return _make_url(rng)
    return _make_hash(rng)


def _maybe_defang(rng: np.random.Generator, value: str, itype: str) -> str:
    roll = rng.random()
    if roll < 0.18:
        if itype == "domain":
            return value.upper()
        if itype == "url":
            return _defang_url(value)
        if itype == "ip":
            return _defang_ip(value)
    if roll > 0.94:
        return f" {value} "
    return value


def generate_records(source_name: str, count: int, seed: int) -> list[dict]:
    """Build a raw feed batch for one source (deterministic for a given seed)."""
    rng = np.random.default_rng(seed)
    records: list[dict] = []

    for _ in range(count):
        itype = _make_type(rng)
        threat_type = THREAT_TYPES[int(rng.integers(0, len(THREAT_TYPES)))]
        raw_value = _maybe_defang(rng, _make_value(rng, itype), itype)
        severity = SEVERITY_BY_TYPE.get(threat_type, "medium")
        if severity == "high" and rng.random() < 0.18:
            severity = "critical"
        if severity == "critical" and rng.random() < 0.2:
            severity = "high"

        tags = sorted(
            {
                TAG_POOL[int(rng.integers(0, len(TAG_POOL)))],
                TAG_POOL[int(rng.integers(0, len(TAG_POOL)))],
            }
        )

        records.append(
            {
                "value": raw_value,
                "severity": severity,
                "confidence": int(rng.integers(55, 99)),
                "threat_type": threat_type,
                "country": COUNTRIES[int(rng.integers(0, len(COUNTRIES)))],
                "tags": ",".join(tags),
                "description": (
                    f"{threat_type} indicator reported by {source_name}; "
                    f"observed in {int(rng.integers(2, 40))} distinct sessions."
                ),
            }
        )

    # Real feeds repeat indicators within a batch — the dedupe step must catch it.
    duplicates = int(rng.integers(1, 3))
    for index in range(duplicates):
        if records:
            records.append(dict(records[int(rng.integers(0, len(records)))], value=records[index]["value"]))

    # ...and sometimes emit something unparseable.
    records.append(
        {
            "value": ["999.999.999.999", "not_a_domain..bad", "hxxp://", "https://", "zzz.$$$"][int(rng.integers(0, 5))],
            "severity": "medium",
            "confidence": 40,
            "threat_type": "Scanning Activity",
            "country": None,
            "tags": "malformed",
            "description": "Malformed record rejected during normalization.",
        }
    )

    rng.shuffle(records)
    return records


def fetch_raw_records(source_name: str, batch_size: int | None = None, seed: int = 0) -> list[dict]:
    """Bundled fixture batch for a source (never touches the network)."""
    volume = batch_size or FEED_VOLUME.get(source_name, 8)
    return generate_records(source_name, volume, seed)


def load_records(
    source_name: str, batch_size: int | None, seed: int
) -> tuple[list[dict], str]:
    """Collect one batch, live when configured, fixtures otherwise.

    Returns ``(records, mode_note)`` where the note is surfaced on the pipeline
    run so operators can see whether a cycle was live or a fixture fallback.
    """
    from .config import settings
    from .live_sources import FeedError, fetch_live_records, source_mode

    mode = source_mode(source_name)
    if mode == "live":
        limit = batch_size or settings.max_records_per_source
        try:
            return fetch_live_records(source_name, limit), "live"
        except FeedError as exc:
            if settings.feed_mode == "live":
                raise
            volume = batch_size or FEED_VOLUME.get(source_name, 8)
            return (
                generate_records(source_name, volume, seed),
                f"fixture fallback ({exc})",
            )

    volume = batch_size or FEED_VOLUME.get(source_name, 8)
    reason = "fixture mode requested" if settings.feed_mode == "fixture" else "no live connector configured"
    return generate_records(source_name, volume, seed), f"fixture ({reason})"
