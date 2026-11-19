"""End-to-end tests for the threat-intelligence API."""

from __future__ import annotations


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_stats_payload(client):
    response = client.get("/api/stats?days=14")
    assert response.status_code == 200
    body = response.json()

    assert body["totals"]["indicators"] > 0
    assert body["totals"]["cves"] > 0
    assert len(body["trend"]) == 14
    assert len(body["by_severity"]) == 4
    assert sum(item["count"] for item in body["by_severity"]) == body["totals"]["indicators"]

    severities = {item["severity"] for item in body["by_severity"]}
    assert severities == {"critical", "high", "medium", "low"}


def test_indicator_list_filters_and_pagination(client):
    response = client.get("/api/indicators?page=1&page_size=5")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] > 0
    assert len(body["items"]) <= 5
    assert body["pages"] >= 1
    assert "facets" in body

    filtered = client.get("/api/indicators?type=ip&page_size=100").json()
    assert filtered["total"] > 0
    assert all(item["type"] == "ip" for item in filtered["items"])

    searched = client.get("/api/indicators?q=phishing&page_size=50").json()
    assert searched["total"] >= 0


def test_indicator_detail_has_related(client):
    listing = client.get("/api/indicators?page_size=1").json()
    indicator_id = listing["items"][0]["id"]

    response = client.get(f"/api/indicators/{indicator_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == indicator_id
    assert isinstance(body["related"], list)
    assert body["normalized"]


def test_manual_indicator_deduplicates(client):
    payload = {
        "value": "hxxps://evil-login[.]example/verify",
        "severity": "critical",
        "confidence": 88,
        "threat_type": "Phishing",
        "description": "Reported by analyst from a phishing email.",
        "tags": ["phishing", "sso"],
    }
    created = client.post("/api/indicators", json=payload)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["type"] == "url"
    assert body["normalized"] == "https://evil-login.example/verify"

    duplicate = client.post("/api/indicators", json=payload)
    assert duplicate.status_code == 409

    invalid = client.post("/api/indicators", json={"value": "not a real indicator"})
    assert invalid.status_code == 422


def test_indicator_status_update(client):
    listing = client.get("/api/indicators?page_size=1").json()
    indicator_id = listing["items"][0]["id"]

    response = client.patch(f"/api/indicators/{indicator_id}", json={"status": "monitoring"})
    assert response.status_code == 200
    assert response.json()["status"] == "monitoring"

    invalid = client.patch(f"/api/indicators/{indicator_id}", json={"severity": "urgent"})
    assert invalid.status_code == 422


def test_export_csv(client):
    response = client.get("/api/indicators/export.csv?severity=critical")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.strip().splitlines()
    assert lines[0].startswith("value,normalized,type")


def test_sources_and_runs(client):
    sources = client.get("/api/sources").json()
    assert sources["total"] >= 5
    assert all("indicator_count" in item for item in sources["items"])

    runs = client.get("/api/pipeline/runs?limit=5").json()
    assert len(runs["items"]) == 5
    assert runs["summary"]["collected"] > 0


def test_collection_pipeline_stores_new_indicators(client):
    before = client.get("/api/stats").json()["totals"]["indicators"]

    response = client.post("/api/pipeline/collect", json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["totals"]["sources"] > 0
    assert body["totals"]["collected"] > 0

    after = client.get("/api/stats").json()["totals"]["indicators"]
    assert after >= before

    paused = client.patch(f"/api/sources/{body['runs'][0]['source_id']}", json={"status": "paused"})
    assert paused.status_code == 200
    blocked = client.post(f"/api/sources/{body['runs'][0]['source_id']}/collect", json={})
    assert blocked.status_code == 409


def test_vulnerability_endpoints(client):
    listing = client.get("/api/vulnerabilities?severity=critical&page_size=5")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] > 0
    assert all(item["severity"] == "critical" for item in body["items"])

    exploited = client.get("/api/vulnerabilities?exploited=true").json()
    assert all(item["exploited"] for item in exploited["items"])

    detail = client.get("/api/vulnerabilities/CVE-2021-44228")
    assert detail.status_code == 200
    assert detail.json()["cvss"] == 10.0

    assert client.get("/api/vulnerabilities/CVE-0000-0000").status_code == 404


def test_investigate_search(client):
    response = client.get("/api/investigate?q=phishing")
    assert response.status_code == 200
    body = response.json()
    assert body["counts"]["total"] >= 1
    assert "pivots" in body

    cve_search = client.get("/api/investigate?q=CVE-2021-44228").json()
    assert cve_search["counts"]["vulnerabilities"] >= 1
