# CTI Sentinel — Cyber Threat Intelligence Dashboard

Team ID: **MP2026CSE28** · Guided by Dr. Mohammad Wazid

A centralized platform that collects authorized cyber threat intelligence, processes and
normalizes it, stores it, and presents it through a SOC-style dashboard for investigation.

The project follows the pipeline from the brief: **Collect → Process → Store → Analyze → Visualize → Investigate**.

```
 Threat feeds / APIs            Processing (pandas)                Storage            Analysis            Presentation
┌────────────────────┐    ┌──────────────────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│ OTX · URLhaus      │───▶│ refang → validate →       │───▶│ PostgreSQL   │───▶│ aggregations │───▶│ React dashboard  │
│ Feodo · CISA KEV   │    │ normalize → deduplicate   │    │ (or SQLite)  │    │ & search     │    │ (Recharts, SOC)  │
│ NVD · ATT&CK · DROP│    └──────────────────────────┘    └──────────────┘    └──────────────┘    └──────────────────┘
└────────────────────┘             PipelineRun log                                              IoCs · CVEs · Feeds
```

## What it does

| Objective (from the brief) | Implementation |
| --- | --- |
| Threat intelligence collection | 7 authorized sources: live HTTP/STIX/TAXII connectors in `backend/app/live_sources.py` plus a background collection loop, driven by `POST /api/pipeline/collect` or `CTI_COLLECT_INTERVAL_MINUTES` |
| IoC management | Malicious IPs, domains, URLs and file hashes with severity, confidence, category, tags, status and source |
| Data processing | Refanging (`hxxp`, `[.]`), validation, normalization and deduplication with **pandas/NumPy** |
| Vulnerability analysis | CVE records with CVSS, severity, exploitation and patch status (`/api/vulnerabilities`) |
| Threat visualization | Stacked severity trend, severity donut, source/category bars, CVE posture ring |
| SOC-style dashboard | Dark operational console with KPI strip, filterable tables, detail drawers and quick pivots |
| Investigation | Cross-entity search across indicators, CVEs and feeds with threat-category pivots |

## Tech stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2
- **Data processing:** pandas, NumPy
- **Feed transport:** httpx (REST, CSV, JSON) with STIX 2.1 pattern parsing and a TAXII 2.1 poller
- **Database:** PostgreSQL (production target) with SQLite as a zero-setup default
- **Frontend:** React 18, Vite, Recharts, React Router
- **Threat intel formats:** REST APIs, STIX 2.1, TAXII 2.1, JSON feeds
- **Tests:** pytest + FastAPI TestClient

## Project structure

```
backend/
  app/
    main.py            FastAPI app, CORS, seeding, optional static hosting of the build
    config.py          Environment configuration (.env supported)
    database.py        Engine + session dependency (SQLite / PostgreSQL)
    models.py          Source, Indicator, Vulnerability, PipelineRun
    schemas.py         Request validation models
    normalize.py       Refang, type detection, canonicalization, validation
    pipeline.py        Collection → processing → dedup → storage pipeline
    feed_sources.py    Feed registry + fixture generators (offline batches)
    live_sources.py    Live HTTP/STIX/TAXII connectors and payload parsers
    cve_collectors.py  CISA KEV + NVD ingestion, CVSS mapping, CVE upsert
    scheduler.py       Background collection loop and its status
    seed.py            Demo corpus seeding
    cve_seed.py        Public CVE records
    routers/           stats, indicators, vulnerabilities, feeds, investigate
  tests/               API test suite
frontend/
  src/
    pages/             Overview, Indicators, Vulnerabilities, Feeds, Investigate
    components/        Layout, charts, UI primitives
    api.js, hooks.js, utils.js, styles.css
docker-compose.yml     PostgreSQL service
```

## Quick start

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The API starts at `http://localhost:8000` (interactive docs at `/docs`). On first start the
database is created and seeded with sources, indicators, CVEs and pipeline history.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev                         # http://localhost:3000 (proxies /api to :8000)
```

### 3. PostgreSQL (optional but recommended)

The default database is SQLite so the project runs anywhere. To use PostgreSQL:

```bash
docker compose up -d                # postgres on localhost:5432, db/user/pass = cti
cp backend/.env.example backend/.env
# set DATABASE_URL=postgresql+psycopg://cti:cti@localhost:5432/cti
```

The schema and demo data are created automatically on the next start.

### Production build

```bash
cd frontend && npm run build        # emits frontend/dist
cd ../backend && uvicorn app.main:app --port 8000
```

When `frontend/dist` exists, FastAPI serves the built SPA on the same origin — one process,
one port.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Service health |
| GET | `/api/stats?days=14` | KPIs, severity/type/source/category breakdowns, daily trend, recent activity |
| GET | `/api/indicators` | Filter by `q`, `type`, `severity`, `source_id`, `status`, `threat_type`, `days`; sort and paginate |
| GET | `/api/indicators/{id}` | Indicator detail with related indicators and source history |
| POST | `/api/indicators` | Manually add an indicator (normalized + deduplicated, `409` on duplicate) |
| PATCH | `/api/indicators/{id}` | Update severity, confidence or triage status |
| DELETE | `/api/indicators/{id}` | Remove an indicator |
| GET | `/api/indicators/export.csv` | CSV export of the current filter set |
| GET | `/api/vulnerabilities` | CVE list with severity, exploitation and CVSS filters plus summary |
| GET | `/api/vulnerabilities/{cve_id}` | Single CVE record |
| GET | `/api/sources` | Connected feeds with indicator and critical counts |
| PATCH | `/api/sources/{id}` | Pause or resume a feed |
| POST | `/api/sources/{id}/collect` | Run one feed through the pipeline |
| POST | `/api/pipeline/collect` | Run every active feed |
| GET | `/api/pipeline/runs` | Pipeline history and ingestion totals |
| GET | `/api/pipeline/status` | Scheduler state, collection mode and credential availability |
| GET | `/api/investigate?q=` | Cross-entity search with pivots |

## Processing pipeline

Each collection cycle:

1. **Collect** raw records from the source (see `fetch_raw_records`).
2. **Refang & detect type** — `hxxps://evil[.]example` → `https://evil.example`, uppercase domains, padded values.
3. **Validate** — invalid IPs, malformed domains and empty URLs are rejected and counted.
4. **Normalize** — lowercase hosts, IDNA encoding, canonical URL form (default ports and fragments dropped), lowercase hashes with algorithm detection.
5. **Deduplicate** — by `(type, normalized)` both within the batch and against the stored corpus; duplicates bump `report_count` and `last_seen`.
6. **Store** — new indicators persist with first/last seen, severity, confidence, category and source.
7. **Record** — every run stores collected / normalized / duplicates / rejected / stored counts, shown on the Feeds page.

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```

Covers health, statistics aggregation, indicator filtering/pagination/detail, manual creation and
deduplication, status updates, CSV export, collection cycles, paused feeds, CVE queries,
investigation search, scheduler status, and the live parsers (URLhaus CSV, Feodo JSON, OTX pulses,
STIX patterns, CISA KEV, NVD). Tests force `CTI_FEED_MODE=fixture` and never touch the network.

## Demo data

All indicators are synthetic and use **RFC 2606 reserved domains** (`example`, `example.com`,
`example.net`, `example.org`) and **RFC 5737 documentation IP ranges**
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Nothing points at real infrastructure.
CVE records use public NVD/CISA KEV facts.

With `CTI_FEED_MODE=auto` (the default) each source collects from its live endpoint and falls back
to deterministic fixtures only when that endpoint is unreachable or unconfigured, so the dashboard
works offline and still records real data when the network is available. Set
`CTI_FEED_MODE=live` to make an unreachable feed a visible failed run instead of a fallback, or
`CTI_FEED_MODE=fixture` for a fully offline demo.

## Live collection and real time

| Source | Live endpoint | Key needed |
| --- | --- | --- |
| Abuse.ch URLhaus | `urlhaus-api.abuse.ch/v2/files/exports/<key>/recent.csv` | yes (`ABUSECH_AUTH_KEY`; the old keyless paths return HTTP 410) |
| Abuse.ch Feodo Tracker | `feodotracker.abuse.ch/downloads/ipblocklist.json` | optional (`ABUSECH_AUTH_KEY` is sent when set) |
| CISA Known Exploited Vulnerabilities | `cisa.gov/.../known_exploited_vulnerabilities.json` | no |
| NVD CVE API v2 | `services.nvd.nist.gov/rest/json/cves/2.0` | optional (`NVD_API_KEY`, raises the rate limit) |
| AlienVault OTX | `otx.alienvault.com/api/v1/pulses/subscribed` | yes (`OTX_API_KEY`) |
| MITRE ATT&CK — TAXII 2.1 | any TAXII 2.1 collection you are entitled to poll | `TAXII_URL`, `TAXII_COLLECTION`, optional `TAXII_TOKEN` |
| Spamhaus DROP | netblocks, not host-level IoCs — stays on fixtures | no |

Every connector is split into transport (`http_get`) and a pure `parse_*` function, so parsers are
tested offline and a changed upstream schema is a one-function fix.

Feeds that publish a static catalogue (CISA KEV, Feodo) are read through a rotating window, so
each cycle ingests a different slice instead of re-processing the same first N records.

CVE sources write to the vulnerability table instead of the indicator table. Because KEV carries
exploitation facts without CVSS and NVD carries CVSS without exploitation history, records are
upserted and merged: a CVE seen in both keeps KEV's `exploited` flag and NVD's score.

**Automatic refresh.** `backend/app/scheduler.py` runs a full collection cycle every
`CTI_COLLECT_INTERVAL_MINUTES` (default 15, `0` disables it) in a worker thread. The Feeds page shows
the mode, schedule, next cycle, last cycle totals, credential status and the mode/notes of each run.
Set `CTI_COLLECT_ON_START=true` to collect immediately on boot.

To run fully live:

```bash
cd backend
cp .env.example .env          # then set CTI_FEED_MODE=live, keys as available
uvicorn app.main:app --reload --port 8000
```

Indicators collected from real feeds are real malicious infrastructure — treat them as live threat
data and keep the API off the public internet (there is no authentication layer).

Notes from a live run on a normal connection:

- A full cycle takes roughly 1–3 minutes because CISA KEV is a ~2 MB JSON document and the NVD API is
  deliberately slow without a key. `NVD_API_KEY` (free) raises the limit from 5 to 50 requests per 30s.
- Sources without a key or endpoint (OTX, URLhaus, TAXII, Spamhaus) fall back to fixtures and are
  labelled `Fixture` on the Feeds page; a run's `notes` field always starts with `[live]` or
  `[fixture …]` so ingestion provenance is never ambiguous.
- Set `CTI_SEED_ON_STARTUP=false` on a fresh database if you want an entirely live corpus instead of
  the bundled demo indicators alongside real ones.
