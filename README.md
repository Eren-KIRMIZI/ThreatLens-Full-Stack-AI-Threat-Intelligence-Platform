# ThreatLens — Full-Stack AI Threat Intelligence Platform

Evidence-first threat intelligence analysis with a deterministic scoring
engine, an LLM interpreter that only reasons from real virus-total evidence,
and one-click PDF reports.

- **Backend** — FastAPI (Python 3.11) · SQLAlchemy(async) + SQLite/Alembic · VirusTotal
  v3 REST client with normalized evidence · OpenRouter LLM (free-tier friendly)
  · reportlab PDF rendering
- **Frontend** — React 19 + TypeScript · Vite 8 · Tailwind CSS v4 · TanStack Query ·
  React Hook Form + Zod · Recharts · oxlint

> [Backend README](backend/README.md) · [Frontend README](frontend/README.md) · Interactive API docs at `http://127.0.0.1:8000/docs`

---

## Features

- **Multi-indicator analysis** — SHA256/SHA1/MD5 hashes, URLs, domains, IPs and
  file uploads (≤32 MB, hashed server-side, submitted to VirusTotal and polled).
- **Deterministic scoring** — every verdict comes from a transparent,
  evidence-anchored rubric (`malicious_engines`, reputation, votes), completely
  independent from the AI layer:
  ```
  score = clamp( 10*malicious_engines
               + 4*suspicious_engines
               + reputation_adjustment   (negative VT reputation raises it)
               + vote_adjustment         (malicious vs harmless votes)
               , 0..100 )
  level  = clean(0-19) | suspicious(20-39) | malicious(40-69) | critical(70-100)
  ```
- **Evidence-based AI interpretation** — via OpenRouter. The model receives only
  normalized VirusTotal evidence (never raw file bytes), returns structured JSON
  (tactics, threat actor profile, capabilities/impact, recommendations, lifecycle,
  threat level assessment). `evidence_refs` are validated server-side against the
  real detections — fabricated citations are dropped (**anti-hallucination guard**).
  Works with `:free` OpenRouter models out of the box.
- **Separation of concerns** — the score is stored per analysis and fuels
  filtering/sorting; the AI's qualitative assessment is reported separately.
- **Caching & lazy enrichment** — repeat analyses within the TTL (default 1 h)
  are answered from the DB without hitting upstreams; analyses saved without AI
  can be enriched later (`POST /analysis/{id}/ai`).
- **Multi-provider enrichment** — parallel fan-out to VirusTotal, AbuseIPDB, URLhaus,
  MalwareBazaar, ThreatFox, OTX and RDAP/GeoIP/DNS with per-provider timeouts,
  evidence normalisation and an explainable confidence rubric.
- **IOC inventory & timelines** — every analysis feeds a deduplicated indicator
  registry with snapshot history, so you can see how a verdict evolves over time.
- **IOC relationship graph** — pivots from a root indicator through sources to
  related campaign indicators, rendered in the UI with React Flow.
- **Investigations** — group indicators into cases, add analyst notes, tags and
  pin analyses to a workspace.
- **Watchlist & alert engine** — monitor indicators, define rules (`score_ge`,
  `engines_ge`, `new_detection`, `level_is`), rescan on demand or on a schedule,
  and triage a deduplicated alert inbox.
- **MITRE ATT&CK mapping** — curated technique catalog, validation and evidence
  → technique mapping for every analysis.
- **Exports** — history CSV, raw analysis JSON, STIX 2.1 bundles and generated
  YARA / Sigma rules.
- **Global search & digest** — cross-entity search plus day/week/month intelligence
  digests of activity, detections and provider health.
- **PDF reports** — server-side rendering with reportlab. One report model
  produces both the structured JSON preview and the downloadable PDF, so they
  never drift. Unicode fonts (Segoe UI → Arial → Helvetica fallback).
- **Dashboard, history, detailed views** — threat gauge, detection tables,
  MITRE-style AI analysis, filter/search/pagination.

## Architecture

```
Frontend (Vite :5173) ──proxy──▶ API (FastAPI :8000) ──▶ VirusTotal v3
     │  reports/preview + PDF        │  normalize evidence
     │                               ├─▶ deterministic threat_score
     │                               └─▶ OpenRouter LLM (structured JSON,
                                            evidence_refs enforced)
```

```
backend/
  app/api/v1/          FastAPI routers (analyze, analysis, history, reports,
                       iocs, investigations, watchlist, intel, exports)
  app/services/        providers/ (VT, AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox,
                       OTX, RDAP, GeoIP, DNS), enrichment_service, confidence,
                       graph_service, alert_engine, rescan_service, mitre, stix,
                       signatures, intel_service, report_service, ai_service
  app/repositories/    SQLAlchemy data access (analyses, registry, investigations,
                       watchlist/alerts)
  app/models|schemas/  ORM models & Pydantic schemas
  tests/               156 tests — in-memory DB, mocks for all upstreams
frontend/
  src/pages/           Dashboard, Analyze, AnalysisDetail, History, Reports,
                       IOCs, Investigations, Watchlist, Graph
  src/components/      analysis/, analyze/, reports/, layout/, ui/
  src/services/api.ts  typed HTTP client (fetch)
  src/hooks/, src/utils/
```

## Quickstart

### 0) Prerequisites

- Python 3.11+
- Node.js 20+ (lockfile generated with Node 22)
- Free API keys: [VirusTotal](https://www.virustotal.com/gui/my-apikey) and
  [OpenRouter](https://openrouter.ai/keys) (a `:free` model works — see below)

### 1) Backend

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt      # Windows
cp .env.example .env                                  # fill in API keys
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

### 2) Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173
```

Open `http://localhost:5173` and analyze your first indicator.

### 3) Free-tier AI (no cost)

Set the model to any working `:free` model on OpenRouter, for example:

```bash
OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free
```

The backend retries transient upstream errors (429/5xx) with exponential
backoff, so flaky free-tier providers degrade gracefully.

### 4) Tests & lint

```bash
cd backend
.\.venv\Scripts\python -m pytest -q                 # 156 tests, upstreams mocked

cd frontend
npm run lint                                         # oxlint
npm run build                                        # tsc -b && vite build
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 API key (required for analysis) |
| `OPENROUTER_API_KEY` | — | OpenRouter key (required for AI interpretation) |
| `OPENROUTER_MODEL` | `openrouter/auto` | e.g. `nvidia/nemotron-3-super-120b-a12b:free` |
| `AI_ASSIST_DEFAULT` | `false` | run AI interpretation on every analysis |
| `DATABASE_URL` | `sqlite+aiosqlite:///./threatlens.db` | SQLite (dev) or `postgresql+asyncpg://…` |
| `CACHE_TTL_SECONDS` | `3600` | freshness/cache window for repeat analyses |
| `MAX_UPLOAD_SIZE_MB` | `32` | max upload size for `analyze/file` |
| `WATCHLIST_RESCAN_INTERVAL_SECONDS` | `0` | background rescan cadence (`0` = on-demand only) |
| `RBAC_ENABLED` | `false` | require `X-ThreatLens-Role` (viewer / analyst / admin) |
| `CORS_ORIGINS` | `["http://localhost:5173","http://127.0.0.1:5173"]` | allowed frontends |

## API overview (`/api/v1`)

| Endpoint | Description |
| --- | --- |
| `GET /health` | service health |
| `POST /analyze/hash` · `POST /analyze/url` · `POST /analyze/domain` · `POST /analyze/ip` | indicator analysis (accepts `"ai": true`) |
| `POST /analyze/file` | file upload → hash → submit → poll |
| `GET /history?limit=&offset=&filter=&search=` | paginated history (filter: all/malicious/suspicious/clean) |
| `GET /analysis/{id}` | stored analysis result |
| `POST /analysis/{id}/ai` | enrich existing analysis with AI |
| `GET /analysis/{id}/graph` | IOC relationship graph (nodes/edges for React Flow) |
| `GET /reports/{id}` · `GET /reports/{id}/pdf` | structured report (JSON preview) and downloadable PDF |
| `GET /iocs` · `GET /iocs/{value}` · `GET /iocs/{value}/analyses` | deduplicated IOC inventory + per-indicator timeline |
| `GET /iocs/health/providers` · `GET /iocs/health/virustotal` | provider availability/health and VT key check |
| `GET /investigations` · `POST /investigations` · `PATCH /investigations/{id}` | case management |
| `POST /investigations/{id}/items` | link an indicator/analysis to a case |
| `POST /investigations/{analysis_id}/notes` · `GET …/notes` | analyst notes |
| `POST /investigations/analysis/{id}/tags` · `GET …/tags` | analysis tags |
| `POST /investigations/analysis/{id}/pin` · `GET /investigations/pinned/list` | pinning |
| `GET /watchlist` · `POST /watchlist` · `PATCH/DELETE /watchlist/{id}` | monitored indicators |
| `GET/POST /watchlist/rules` · `DELETE /watchlist/rules/{id}` | alert rules (`score_ge`, `engines_ge`, `new_detection`, `level_is`) |
| `GET /watchlist/alerts` · `POST /watchlist/alerts/mark-seen` | alert inbox |
| `POST /watchlist/{id}/rescan` · `POST /watchlist/rescan/all` | force re-analysis (all = admin when RBAC on) |
| `GET /intel/digest?window=day|week|month` | period intelligence digest |
| `GET /intel/search?q=` | global search across analyses/IOCs/cases |
| `GET/POST /intel/mitre/*` | ATT&CK catalog, validation and evidence mapping |
| `GET /intel/me` | resolved RBAC role |
| `GET /export/history.csv` | history CSV download |
| `GET /export/analyses/{id}.json` | raw analysis JSON |
| `GET /export/analyses/{id}/stix.json` | STIX 2.1 bundle |
| `GET /export/analyses/{id}/yara` · `/sigma` | generated YARA / Sigma rule |

## CI/CD

`.github/workflows/ci.yml` runs on every push/PR to `main`:

- **Backend**: install `requirements.txt`, create an empty-key `.env`, run the full
  pytest suite (upstreams mocked via in-memory DB + httpx mock transports).
- **Frontend**: `npm ci` → `npm run lint` → `npm run build`.

## Deployment notes

- Use PostgreSQL (e.g. Supabase) in production via `DATABASE_URL` and manage schema
  with Alembic (`python -m alembic upgrade head`).
- Set `APP_ENV=production`, `DEBUG=false` and never commit `.env` — keys are read
  from environment variables in production.
- Static frontend build (`frontend/dist`) can be served by any CDN/host; in
  production the API keys stay on the backend (the dev proxy in `vite.config.ts`
  forwards `/api/*` to `:8000`, and the backend enforces CORS via `CORS_ORIGINS`).