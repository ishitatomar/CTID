"""Indicator validation, refanging and normalization.

Feeds report the same indicator in many shapes ("hxxps://evil[.]example",
"EVIL.EXAMPLE", "1.2.3[.]4"). This module turns any of those into one
canonical form so the deduplication step can work on a stable key.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}

_DEFANG_RULES = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[@]", "@"),
)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_LABEL_ONLY_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def refang(value: str) -> str:
    """Undo common defanging used in threat reports."""
    out = (value or "").strip().strip("'\"")
    for needle, replacement in _DEFANG_RULES:
        out = out.replace(needle, replacement)
        out = out.replace(needle.upper(), replacement)
    return out.strip()


def detect_type(raw: str) -> str | None:
    """Return 'ip' | 'domain' | 'url' | 'hash' or None when unparseable."""
    value = refang(raw)
    if not value or len(value) > 512 or " " in value:
        return None

    if value.isdigit() is False and re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        return "hash"

    if "://" in value:
        return "url"

    if _IPV4_RE.match(value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return None
        return "ip"

    if ":" in value:  # bare IPv6
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            return None
        return "ip"

    if _LABEL_ONLY_RE.match(value.lower()):
        return "domain"

    return None


def _normalize_domain(value: str) -> str | None:
    host = value.lower().strip().strip(".")
    if host.startswith("*."):
        host = host[2:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not _DOMAIN_RE.match(host):
        return None
    return host


def _normalize_url(value: str) -> str | None:
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None
    host = _normalize_domain(parts.hostname or "")
    if host is None:
        return None

    netloc = host
    if parts.port and not ((scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443)):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize(raw: str) -> tuple[str, str | None] | None:
    """Return (normalized_value, type) or None when the value is not valid."""
    value = refang(raw)
    itype = detect_type(value)
    if itype is None:
        return None

    if itype == "ip":
        try:
            return ipaddress.ip_address(value).compressed, "ip"
        except ValueError:
            return None

    if itype == "domain":
        host = _normalize_domain(value)
        return (host, "domain") if host else None

    if itype == "url":
        url = _normalize_url(value)
        return (url, "url") if url else None

    return value.lower(), "hash"


def hash_algorithm(normalized: str) -> str | None:
    return HASH_LENGTHS.get(len(normalized or ""))


def severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((severity or "").lower(), 0)


def slugify(value: str) -> str:
    """Lowercase, hyphen-separated token used for filter matching."""
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
