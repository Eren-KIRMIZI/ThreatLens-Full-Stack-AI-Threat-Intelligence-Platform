# ThreatLens Backend

FastAPI service powering the ThreatLens threat intelligence platform.

## Setup

```bash
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt          # Windows
cp .env.example .env                                      # then fill in keys
.\.venv\Scripts\python -m uvicorn app.main:app --reload  # dev
```

Development uses SQLite (`sqlite+aiosqlite`) with schema auto-created on
startup. For production (e.g. Supabase/PostgreSQL), set `DATABASE_URL` in
`.env` and manage the schema with Alembic instead.

## Database migrations

```bash
.\.venv\Scripts\python -m alembic upgrade head   # apply migrations
.\.venv\Scripts\python -m alembic revision --autogenerate -m "change"  # new migration
```

## Tests

```bash
.\.venv\Scripts\python -m pytest tests/ -q
```

## Endpoints (v1)

- `GET /api/v1/health` — service health
- `POST /api/v1/analyze/hash` — analyze a SHA256/SHA1/MD5 hash
- `POST /api/v1/analyze/url` — analyze (or submit) a URL
- `POST /api/v1/analyze/domain` — domain reputation & intelligence
- `POST /api/v1/analyze/ip` — IP reputation & intelligence
- `POST /api/v1/analyze/file` — upload a file (max 32 MB); hashes are computed
  server-side, submitted to VirusTotal and polled until completion
- `GET /api/v1/analysis/{analysis_id}` — fetch a stored analysis result
- `POST /api/v1/analysis/{analysis_id}/ai` — run / refresh the evidence-based
  AI interpretation of a stored analysis
- `GET /api/v1/history?limit=&offset=&filter=all|malicious|suspicious|clean&search=` —
  paginated, filterable analysis history (also the freshness cache)
- `GET /api/v1/reports/{analysis_id}` — structured report document (JSON)
- `GET /api/v1/reports/{analysis_id}/pdf` — downloadable PDF report

### Reports & PDF export

`app/services/report_service.py` compiles a deterministic report from any
stored analysis:

- **One model, two outputs** — `build_report` produces a structured
  `ReportDocument` (executive summary + evidence tables + optional AI
  section); `render_pdf` renders that same model with reportlab, so the JSON
  preview and the PDF never drift apart.
- **Rendered server-side** — `GET /reports/{id}/pdf` streams
  `application/pdf` with proper Content-Disposition. A Unicode font
  (Segoe UI, then Arial) is embedded when available; otherwise Helvetica is
  used so PDF generation always succeeds.
- **AI integration** — when the analysis carries an `ai` interpretation,
  tactics, capabilities, recommendations, correlations and the threat actor
  profile are included in the report.

Requires `reportlab>=4.2` (included in `requirements.txt`).

### Threat scoring

Every analysis carries a deterministic, evidence-based `threat_score` (0-100)
and a `threat_level`:

```
score = clamp( 10*malicious_engines
             + 4*suspicious_engines
             + reputation_adjustment   (negative VT reputation raises it)
             + vote_adjustment         (malicious vs harmless votes)
             , 0..100 )
level = clean(0-19) | suspicious(20-39) | malicious(40-69) | critical(70-100)
```

The rubric is A/Vendor-count anchored (a strong, transparent signal), fully
independent from the AI layer so the same evidence always produces the same
verdict, and stored per analysis for filtering/sorting history.

### AI-assisted analysis

All `POST /api/v1/analyze/*` requests accept an `"ai": true` flag (or set
`AI_ASSIST_DEFAULT=true`) to attach a structured, evidence-based AI
interpretation (`ai` object on the result) generated via OpenRouter:

- **Evidence only** — the model only receives the normalized VirusTotal
  evidence; raw file bytes never reach the AI layer.
- **Structured output** — summary, tactics (MITRE-style phases/techniques),
  threat actor profile, capabilities & impact, recommendations, threat
  intelligence lifecycle stage, correlations, and a threat level assessment.
- **Scoring separation** — the deterministic `threat_score`/`threat_level`
  come from evidence alone; the AI's qualitative
  `threat_level_assessment` is reported separately.
- **Anti-hallucination guard** — `evidence_refs` (cited engines) are validated
  server-side against the actual detections; fabricated citations are dropped.
- **Cached & lazy** — repeat claims within the TTL skip both upstreams; results
  stored without AI can be enriched later via `POST /analysis/{id}/ai`.

Repeat analyses of the same indicator within `CACHE_TTL_SECONDS` (default
3600) are answered from the database without calling VirusTotal again.

Interactive docs: `http://127.0.0.1:8000/docs`.

See the root `README.md` for the full platform documentation.