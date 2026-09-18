<div align="center">

# ThreatLens — Full-Stack AI Threat Intelligence Platform

**🇬🇧 [English](#english) · 🇹🇷 [Türkçe](#turkce)**

_Evidence-first threat intelligence analysis with a deterministic scoring
engine, an LLM interpreter that only reasons from real VirusTotal evidence,
and one-click PDF reports._

</div>

---
<a id="english"></a>

## English

## Stack

- **Backend** — FastAPI (Python 3.11) · SQLAlchemy (async) + SQLite/Alembic ·
  VirusTotal v3 REST client with normalized evidence · parallel enrichment
  (AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox, OTX, RDAP, GeoIP, DNS) ·
  OpenRouter LLM (free-tier friendly) · reportlab PDF rendering
- **Frontend** — React 19 + TypeScript · Vite 8 · Tailwind CSS v4 · TanStack
  Query · React Hook Form + Zod · Recharts · oxlint

Interactive API docs: `http://127.0.0.1:8000/docs`

---

### Features

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

### Architecture

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

#### Frontend routes

| Route | Page |
| --- | --- |
| `/` | Dashboard — verdict distribution `critical/malicious/suspicious/clean`, quick analyze |
| `/analyze` | Analyze — hash / URL / domain / IP / file upload, AI toggle |
| `/analysis/:analysisId` | Analysis detail — detections table, metadata, AI interpretation, PDF download |
| `/history` | History — filter by verdict, search, pagination |
| `/iocs` | IOC Inventory — deduplicated registry with per-indicator timelines |
| `/investigations` | Investigations — cases, notes, tags, pinning |
| `/watchlist` | Watchlist — monitored indicators, alert rules, alert inbox |
| `/reports` | Reports — saved analyses with JSON preview + PDF download |
| `/graph` (nested) | IOC relationship graph |
| `/settings` | Settings — runtime configuration status (keys live server-side) |

#### Frontend scripts

| Script | What it does |
| --- | --- |
| `npm run dev` | Vite dev server with HMR + API proxy (`/api/*` → `:8000`) |
| `npm run build` | `tsc -b` then `vite build` (output in `dist/`) |
| `npm run lint` | oxlint over `src/` |
| `npm run preview` | serve the production build locally |

### Quickstart

#### 0) Prerequisites

- Python 3.11+
- Node.js 20+ (lockfile generated with Node 22)
- Free API keys: [VirusTotal](https://www.virustotal.com/gui/my-apikey) and
  [OpenRouter](https://openrouter.ai/keys) (a `:free` model works — see below)

#### 1) Backend

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt      # Windows
cp .env.example .env                                  # fill in API keys
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

Development uses SQLite (`sqlite+aiosqlite`) with the schema auto-created on
startup. For production (e.g. Supabase/PostgreSQL), set `DATABASE_URL` in `.env`
and manage the schema with Alembic instead:

```bash
.\.venv\Scripts\python -m alembic upgrade head                                  # apply migrations
.\.venv\Scripts\python -m alembic revision --autogenerate -m "change"          # new migration
```

#### 2) Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173
```

Open `http://localhost:5173` and analyze your first indicator.

#### 3) Free-tier AI (no cost)

Set the model to any working `:free` model on OpenRouter, for example:

```bash
OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free
```

The backend retries transient upstream errors (429/5xx) with exponential
backoff, so flaky free-tier providers degrade gracefully.

#### 4) Tests & lint

```bash
cd backend
.\.venv\Scripts\python -m pytest -q                 # 156 tests, upstreams mocked

cd frontend
npm run lint                                         # oxlint
npm run build                                        # tsc -b && vite build
```

### Configuration

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

### API overview (`/api/v1`)

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

#### Reports & PDF export (backend detail)

`app/services/report_service.py` compiles a deterministic report from any
stored analysis:

- **One model, two outputs** — `build_report` produces a structured
  `ReportDocument` (executive summary + evidence tables + optional AI section);
  `render_pdf` renders that same model with reportlab, so the JSON preview and
  the PDF never drift apart.
- **Rendered server-side** — `GET /reports/{id}/pdf` streams `application/pdf`
  with a proper `Content-Disposition`. A Unicode font (Segoe UI, then Arial) is
  embedded when available; otherwise Helvetica is used so PDF generation always
  succeeds.
- **AI integration** — when the analysis carries an `ai` interpretation,
  tactics, capabilities, recommendations, correlations and the threat actor
  profile are included in the report.

### CI/CD

`.github/workflows/ci.yml` runs on every push/PR to `main`:

- **Backend**: install `requirements.txt`, create an empty-key `.env`, run the full
  pytest suite (upstreams mocked via in-memory DB + httpx mock transports).
- **Frontend**: `npm ci` → `npm run lint` → `npm run build`.

### Deployment notes

- Use PostgreSQL (e.g. Supabase) in production via `DATABASE_URL` and manage schema
  with Alembic (`python -m alembic upgrade head`).
- Set `APP_ENV=production`, `DEBUG=false` and never commit `.env` — keys are read
  from environment variables in production.
- Static frontend build (`frontend/dist`) can be served by any CDN/host; in
  production the API keys stay on the backend (the dev proxy in `vite.config.ts`
  forwards `/api/*` to `:8000`, and the backend enforces CORS via `CORS_ORIGINS`).

---

<a id="turkce"></a>

## Türkçe

# ThreatLens — Full-Stack Yapay Zeka Tehdit İstihbaratı Platformu

_Kanıta dayalı tehdit istihbaratı analizi: deterministik puanlama motoru,
yalnızca gerçek VirusTotal kanıtlarından akıl yürüten bir LLM yorumlayıcısı
ve tek tıkla PDF raporları._

## Teknolojik Altyapı

- **Backend** — FastAPI (Python 3.11) · SQLAlchemy (async) + SQLite/Alembic ·
  normalize edilmiş kanıtlarla VirusTotal v3 REST istemcisi · paralel
  zenginleştirme (AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox, OTX, RDAP,
  GeoIP, DNS) · OpenRouter LLM (ücretsiz seviyeyle uyumlu) · reportlab PDF
  dönüştürücü
- **Frontend** — React 19 + TypeScript · Vite 8 · Tailwind CSS v4 · TanStack
  Query · React Hook Form + Zod · Recharts · oxlint

İnteraktif API dökümantasyonu: `http://127.0.0.1:8000/docs`

---

### Özellikler

- **Çoklu gösterge analizi** — SHA256/SHA1/MD5 hash'leri, URL'ler, alan adları,
  IP'ler ve dosya yüklemeleri (≤32 MB; hash'ler sunucuda hesaplanır, VirusTotal'e
  gönderilir ve tamamlanana kadar yoklanır).
- **Deterministik puanlama** — her sonuç, AI katmanından tamamen bağımsız,
  şeffaf ve kanıta dayalı bir ölçütten gelir (`malicious_engines`, itibar,
  oylar):
  ```
  puan = clamp( 10*zararli_motor_adedi
              + 4*supheli_motor_adedi
              + itibar_ayarlamasi        (negatif VT itibarı puanı yükseltir)
              + oy_ayarlamasi            (zararlı ile zararsız oyları)
              , 0..100 )
  seviye = temiz(0-19) | supheli(20-39) | zararli(40-69) | kritik(70-100)
  ```
- **Kanıta dayalı AI yorumu** — OpenRouter üzerinden. Model yalnızca normalize
  edilmiş VirusTotal kanıtlarını alır (ham dosya baytları asla AI katmanına
  ulaşmaz) ve yapılandırılmış JSON döndürür (taktikler, tehdit aktörü profili,
  yetenekler/etki, öneriler, yaşam döngüsü, tehdit seviyesi değerlendirmesi).
  `evidence_refs` sunucu tarafında gerçek tespitlere karşı doğrulanır; uydurma
  alıntılar atılır (**halüsinasyon koruması**). `:free` OpenRouter modelleriyle
  kutudan çıktığı gibi çalışır.
- **İş bölümü** — puan her analiz için saklanır ve filtreleme/sıralamayı besler;
  AI'ın nitel değerlendirmesi ayrıca raporlanır.
- **Önbellek & tembel zenginleştirme** — TTL içindeki tekrar analizler (varsayılan
  1 saat) yukarı akışlara dokunmadan veritabanından yanıtlanır; AI olmadan
  kaydedilen analizler sonradan zenginleştirilebilir (`POST /analysis/{id}/ai`).
- **Çok sağlayıcılı zenginleştirme** — VirusTotal, AbuseIPDB, URLhaus,
  MalwareBazaar, ThreatFox, OTX ve RDAP/GeoIP/DNS'ye sağlayıcı başına zaman
  aşımları, kanıt normalizasyonu ve açıklanabilir güven ölçütüyle paralel dağıtım.
- **IOC envanteri ve zaman çizelgeleri** — her analiz, anlık görüntü geçmişine
  sahip tekilleştirilmiş bir gösterge kayıt defterini besler; böylece bir
  sonucun zaman içinde nasıl evrildiğini görebilirsin.
- **IOC ilişki grafiği** — kök göstergeden kaynaklara, oradan ilgili kampanya
  göstergelerine dallanır; UI'da React Flow ile çizilir.
- **Soruşturmalar** — göstergeleri vakalarda grupla, analist notları ve
  etiketler ekle, analizleri çalışma alanına sabitle.
- **İzleme listesi ve uyarı motoru** — göstergeleri izle, kuralları tanımla
  (`score_ge`, `engines_ge`, `new_detection`, `level_is`), isteğe bağlı veya
  zamanlanmış yeniden tarama yap ve tekilleştirilmiş uyarı gelen kutusunu yönet.
- **MITRE ATT&CK eşlemesi** — küratörlü teknik kataloğu, doğrulama ve her analiz
  için kanıt → teknik eşlemesi.
- **Dışa aktarımlar** — geçmiş CSV'si, ham analiz JSON'u, STIX 2.1 paketleri ve
  üretilmiş YARA / Sigma kuralları.
- **Genel arama ve özet** — varlıklar arası arama artı etkinlik, tespit ve
  sağlayıcı sağlığının gün/hafta/ay istihbarat özetleri.
- **PDF raporları** — reportlab ile sunucu tarafında üretim. Tek rapor modeli hem
  yapılandırılmış JSON önizlemesini hem de indirilebilir PDF'i üretir; birbirinden
  asla sapmazlar. Unicode yazı tipleri (Segoe UI → Arial → Helvetica yedeği).
- **Panel, geçmiş ve detay görünümleri** — tehdit göstergesi, tespit tabloları,
  MITRE tarzı AI analizi, filtre/arama/sayfalama.

### Mimari

```
Frontend (Vite :5173) ──proxy──▶ API (FastAPI :8000) ──▶ VirusTotal v3
     │  rapor/önizleme + PDF           │  kanıtı normalize et
     │                                 ├─▶ deterministik threat_score
     │                                 └─▶ OpenRouter LLM (yapılandırılmış JSON,
                                            evidence_refs zorunlu)
```

```
backend/
  app/api/v1/          FastAPI yönlendiricileri (analyze, analysis, history, reports,
                       iocs, investigations, watchlist, intel, exports)
  app/services/        providers/ (VT, AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox,
                       OTX, RDAP, GeoIP, DNS), enrichment_service, confidence,
                       graph_service, alert_engine, rescan_service, mitre, stix,
                       signatures, intel_service, report_service, ai_service
  app/repositories/    SQLAlchemy veri erişimi (analyses, registry, investigations,
                       watchlist/alerts)
  app/models|schemas/  ORM modelleri ve Pydantic şemaları
  tests/               156 test — bellek içi DB, tüm yukarı akışlar mock
frontend/
  src/pages/           Dashboard, Analyze, AnalysisDetail, History, Reports,
                       IOCs, Investigations, Watchlist, Graph
  src/components/      analysis/, analyze/, reports/, layout/, ui/
  src/services/api.ts  tür bazlı HTTP istemcisi (fetch)
  src/hooks/, src/utils/
```

#### Frontend yönlendirmeleri

| Rota | Sayfa |
| --- | --- |
| `/` | Panel — sonuç dağılımı `critical/malicious/suspicious/clean`, hızlı analiz |
| `/analyze` | Analiz — hash / URL / alan adı / IP / dosya yükleme, AI anahtarı |
| `/analysis/:analysisId` | Analiz detayı — tespit tablosu, meta veri, AI yorumu, PDF indirme |
| `/history` | Geçmiş — sonuca göre filtre, arama, sayfalama |
| `/iocs` | IOC Envanteri — gösterge başına zaman çizelgeli tekilleştirilmiş kayıt |
| `/investigations` | Soruşturmalar — vakalar, notlar, etiketler, sabitleme |
| `/watchlist` | İzleme listesi — izlenen göstergeler, uyarı kuralları, uyarı kutusu |
| `/reports` | Raporlar — JSON önizlemeli ve PDF indirmeli saklanan analizler |
| `/graph` (iç içe) | IOC ilişki grafiği |
| `/settings` | Ayarlar — çalışma zamanı yapılandırma durumu (anahtarlar sunucuda) |

#### Frontend komutları

| Komut | İşi |
| --- | --- |
| `npm run dev` | HMR + API proxy'li Vite dev sunucusu (`/api/*` → `:8000`) |
| `npm run build` | önce `tsc -b`, sonra `vite build` (çıktı: `dist/`) |
| `npm run lint` | `src/` üzerinde oxlint |
| `npm run preview` | üretim derlemesini yerelde sunma |

### Hızlı Başlangıç

#### 0) Ön Koşullar

- Python 3.11+
- Node.js 20+ (lockfile Node 22 ile üretildi)
- Ücretsiz API anahtarları: [VirusTotal](https://www.virustotal.com/gui/my-apikey)
  ve [OpenRouter](https://openrouter.ai/keys) (bir `:free` model çalışır — aşağıya bak)

#### 1) Backend

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt      # Windows
cp .env.example .env                                  # API anahtarlarını doldur
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

Geliştirmede şema başlangıçta otomatik oluşturulan SQLite
(`sqlite+aiosqlite`) kullanılır. Üretim için (örn. Supabase/PostgreSQL)
`.env` içinde `DATABASE_URL` ayarlayın ve şemayı Alembic ile yönetin:

```bash
.\.venv\Scripts\python -m alembic upgrade head                                  # göçleri uygula
.\.venv\Scripts\python -m alembic revision --autogenerate -m "change"          # yeni göç
```

#### 2) Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173
```

`http://localhost:5173` adresini açın ve ilk göstergenizi analiz edin.

#### 3) Ücretsiz Seviye AI (maliyetsiz)

Modeli OpenRouter üzerindeki çalışan herhangi bir `:free` modele ayarlayın,
örneğin:

```bash
OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free
```

Backend, geçici yukarı akış hatalarını (429/5xx) üstel geri çekme ile yeniden
dener; böylece dengesiz ücretsiz sağlayıcılar zarifçe devreye girer.

#### 4) Testler ve lint

```bash
cd backend
.\.venv\Scripts\python -m pytest -q                 # 156 test, yukarı akışlar mock

cd frontend
npm run lint                                         # oxlint
npm run build                                        # tsc -b && vite build
```

### Yapılandırma

| Değişken | Varsayılan | Amaç |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 API anahtarı (analiz için zorunlu) |
| `OPENROUTER_API_KEY` | — | OpenRouter anahtarı (AI yorumu için zorunlu) |
| `OPENROUTER_MODEL` | `openrouter/auto` | örn. `nvidia/nemotron-3-super-120b-a12b:free` |
| `AI_ASSIST_DEFAULT` | `false` | her analizde AI yorumunu çalıştır |
| `DATABASE_URL` | `sqlite+aiosqlite:///./threatlens.db` | SQLite (dev) veya `postgresql+asyncpg://…` |
| `CACHE_TTL_SECONDS` | `3600` | tekrar analizler için tazelik/önbellek penceresi |
| `MAX_UPLOAD_SIZE_MB` | `32` | `analyze/file` için maksimum yükleme boyutu |
| `WATCHLIST_RESCAN_INTERVAL_SECONDS` | `0` | arka plan yeniden tarama sıklığı (`0` = yalnızca istek üzerine) |
| `RBAC_ENABLED` | `false` | `X-ThreatLens-Role` zorunluluğu (viewer / analyst / admin) |
| `CORS_ORIGINS` | `["http://localhost:5173","http://127.0.0.1:5173"]` | izin verilen frontend'ler |

### API özeti (`/api/v1`)

| Endpoint | Açıklama |
| --- | --- |
| `GET /health` | servis sağlığı |
| `POST /analyze/hash` · `POST /analyze/url` · `POST /analyze/domain` · `POST /analyze/ip` | gösterge analizi (`"ai": true` kabul eder) |
| `POST /analyze/file` | dosya yükle → hash → gönder → yokla |
| `GET /history?limit=&offset=&filter=&search=` | sayfalı geçmiş (filtre: all/malicious/suspicious/clean) |
| `GET /analysis/{id}` | saklanan analiz sonucu |
| `POST /analysis/{id}/ai` | mevcut analizi AI ile zenginleştir |
| `GET /analysis/{id}/graph` | IOC ilişki grafiği (React Flow için düğüm/kenar) |
| `GET /reports/{id}` · `GET /reports/{id}/pdf` | yapılandırılmış rapor (JSON önizleme) ve indirilebilir PDF |
| `GET /iocs` · `GET /iocs/{value}` · `GET /iocs/{value}/analyses` | tekilleştirilmiş IOC envanteri + gösterge başına zaman çizelgesi |
| `GET /iocs/health/providers` · `GET /iocs/health/virustotal` | sağlayıcı kullanılabilirliği/sağlığı ve VT anahtar kontrolü |
| `GET /investigations` · `POST /investigations` · `PATCH /investigations/{id}` | vaka yönetimi |
| `POST /investigations/{id}/items` | bir gösterge/analizi vakaya bağla |
| `POST /investigations/{analysis_id}/notes` · `GET …/notes` | analist notları |
| `POST /investigations/analysis/{id}/tags` · `GET …/tags` | analiz etiketleri |
| `POST /investigations/analysis/{id}/pin` · `GET /investigations/pinned/list` | sabitleme |
| `GET /watchlist` · `POST /watchlist` · `PATCH/DELETE /watchlist/{id}` | izlenen göstergeler |
| `GET/POST /watchlist/rules` · `DELETE /watchlist/rules/{id}` | uyarı kuralları (`score_ge`, `engines_ge`, `new_detection`, `level_is`) |
| `GET /watchlist/alerts` · `POST /watchlist/alerts/mark-seen` | uyarı gelen kutusu |
| `POST /watchlist/{id}/rescan` · `POST /watchlist/rescan/all` | zorunlu yeniden analiz (all = RBAC açıkken admin) |
| `GET /intel/digest?window=day|week|month` | dönem istihbarat özeti |
| `GET /intel/search?q=` | analiz/IOC/vaka genelinde genel arama |
| `GET/POST /intel/mitre/*` | ATT&CK kataloğu, doğrulama ve kanıt eşlemesi |
| `GET /intel/me` | çözümlenmiş RBAC rolü |
| `GET /export/history.csv` | geçmiş CSV indirme |
| `GET /export/analyses/{id}.json` | ham analiz JSON'u |
| `GET /export/analyses/{id}/stix.json` | STIX 2.1 paketi |
| `GET /export/analyses/{id}/yara` · `/sigma` | üretilmiş YARA / Sigma kuralı |

#### Raporlar ve PDF dışa aktarma (backend detayı)

`app/services/report_service.py`, saklanan herhangi bir analizden deterministik
bir rapor derler:

- **Tek model, iki çıktı** — `build_report` yapılandırılmış bir `ReportDocument`
  üretir (yönetici özeti + kanıt tabloları + isteğe bağlı AI bölümü); `render_pdf`
  aynı modeli reportlab ile çizer; böylece JSON önizlemesi ile PDF asla
  birbirinden sapmaz.
- **Sunucu tarafında çizilir** — `GET /reports/{id}/pdf`, uygun bir
  `Content-Disposition` ile `application/pdf` akışı döndürür. Müsaitse Unicode
  yazı tipi (önce Segoe UI, sonra Arial) gömülür; aksi halde PDF üretimi her
  zaman başarılı olsun diye Helvetica kullanılır.
- **AI entegrasyonu** — analiz bir `ai` yorumu taşıyorsa taktikler, yetenekler,
  öneriler, ilişkiler ve tehdit aktörü profili rapora dahil edilir.

### CI/CD

`.github/workflows/ci.yml`, `main`'e yapılan her push/PR'da çalışır:

- **Backend**: `requirements.txt` kurulur, boş anahtarlı bir `.env` oluşturulur,
  tüm pytest takımı çalıştırılır (yukarı akışlar bellek içi DB + httpx mock
  taşıyıcılarıyla taklit edilir).
- **Frontend**: `npm ci` → `npm run lint` → `npm run build`.

### Dağıtım Notları

- Üretimde `DATABASE_URL` ile PostgreSQL (örn. Supabase) kullanın ve şemayı
  Alembic ile yönetin (`python -m alembic upgrade head`).
- `APP_ENV=production` ve `DEBUG=false` ayarlayın; `.env` dosyasını asla
  commit'lemeyin — üretimde anahtarlar ortam değişkenlerinden okunur.
- Statik frontend derlemesi (`frontend/dist`) herhangi bir CDN/host'tan
  sunulabilir; üretimde API anahtarları backend'de kalır (dev proxy'si
  `vite.config.ts` içinde `/api/*` öğesini `:8000`'e iletir ve backend,
  `CORS_ORIGINS` ile CORS'u zorlar).