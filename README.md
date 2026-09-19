<div align="center">

# ThreatLens — Full-Stack Yapay Zeka Tehdit İstihbaratı Platformu

_Kanıta dayalı tehdit istihbaratı analizi: deterministik puanlama motoru,
yalnızca gerçek VirusTotal kanıtlarından akıl yürüten bir LLM yorumlayıcısı
ve tek tıkla PDF raporları._

</div>

---

## Özellikler

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
- **Önbellek ve tembel zenginleştirme** — TTL içindeki tekrar analizler
  (varsayılan 1 saat) yukarı akışlara dokunmadan veritabanından yanıtlanır; AI
  olmadan kaydedilen analizler sonradan zenginleştirilebilir
  (`POST /analysis/{id}/ai`).
- **Çok sağlayıcılı zenginleştirme** — VirusTotal, AbuseIPDB, OTX ve
  RDAP/GeoIP/DNS'ye sağlayıcı başına zaman aşımları, kanıt normalizasyonu ve
  açıklanabilir güven ölçütüyle paralel dağıtım.
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

## Teknolojik Altyapı

| Katman | Teknoloji |
| --- | --- |
| **Backend** | FastAPI (Python 3.11), SQLAlchemy (async), SQLite/Alembic, VirusTotal v3 REST istemcisi, reportlab PDF |
| **Enrichment** | AbuseIPDB, OTX, RDAP, GeoIP, DNS |
| **AI** | OpenRouter LLM (ücretsiz model zinciri + otomatik yedekleme), `evidence_refs` doğrulama |
| **Frontend** | React 19 + TypeScript, Vite 8, Tailwind CSS v4, TanStack Query, React Hook Form + Zod, Recharts |
| **Kalite** | oxlint, pytest (158 test) |

İnteraktif API dökümantasyonu: `http://127.0.0.1:8000/docs`

## Mimari

```
Frontend (Vite :5173) ──proxy──▶ API (FastAPI :8000) ──▶ VirusTotal v3
     │  rapor/önizleme + PDF           │  kanıtları normalize et
     │                                 ├─▶ deterministik threat_score
     │                                 └─▶ OpenRouter LLM (yapılandırılmış JSON,
                                            evidence_refs zorunlu)
```

```
backend/
  app/api/v1/          FastAPI yönlendiricileri (analyze, analysis, history, reports,
                       iocs, investigations, watchlist, intel, exports)
  app/services/        providers/ (VT, AbuseIPDB, OTX, RDAP, GeoIP, DNS),
                       enrichment_service, confidence,
                       graph_service, alert_engine, rescan_service, mitre, stix,
                       signatures, intel_service, report_service, ai_service
  app/repositories/    SQLAlchemy veri erişimi (analyses, registry, investigations,
                       watchlist/alerts)
  app/models|schemas/  ORM modelleri ve Pydantic şemaları
  tests/               158 test — bellek içi DB, tüm yukarı akışlar mock

frontend/
  src/pages/           Dashboard, Analyze, AnalysisDetail, History, Reports,
                       IOCs, Investigations, Watchlist, Graph
  src/components/      analysis/, analyze/, reports/, layout/, ui/
  src/services/api.ts  tür bazlı HTTP istemcisi (fetch)
  src/hooks/, src/utils/
```

### Frontend yönlendirmeleri

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

### Frontend komutları

| Komut | İşi |
| --- | --- |
| `npm run dev` | HMR + API proxy'li Vite dev sunucusu (`/api/*` → `:8000`) |
| `npm run build` | önce `tsc -b`, sonra `vite build` (çıktı: `dist/`) |
| `npm run lint` | `src/` üzerinde oxlint |
| `npm run preview` | üretim derlemesini yerelde sunma |

## Hızlı Başlangıç

### 0) Ön Koşullar

- Python 3.11+
- Node.js 20+ (lockfile Node 22 ile üretildi)
- Ücretsiz API anahtarları: [VirusTotal](https://www.virustotal.com/gui/my-apikey)
  ve [OpenRouter](https://openrouter.ai/keys) (ücretsiz model zinciri — aşağıya bak)

### 1) Backend

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt      # Windows
cp .env.example .env                                  # API anahtarlarını doldur
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

Geliştirmede şema, başlangıçta otomatik oluşturulan SQLite
(`sqlite+aiosqlite`) kullanılır. Üretim için (örn. Supabase/PostgreSQL)
`.env` içinde `DATABASE_URL` ayarlayın ve şemayı Alembic ile yönetin:

```bash
.\.venv\Scripts\python -m alembic upgrade head                                  # göçleri uygula
.\.venv\Scripts\python -m alembic revision --autogenerate -m "change"          # yeni göç
```

### 2) Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173
```

`http://localhost:5173` adresini açın ve ilk göstergenizi analiz edin.

### 3) Ücretsiz Seviye AI (maliyetsiz)

OpenRouter üzerindeki ücretsiz `:free` modeller dengesizdir ("Service
temporarily overloaded" yaygındır). ThreatLens bu yüzden sıralı bir **model
zinciri** kullanır: birincil model doygunlaşırsa otomatik olarak sonraki
ücretsiz modele geçer. Varsayılan açılışı:

```bash
OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free
OPENROUTER_FALLBACK_MODELS=["z-ai/glm-5.2:free","google/gemma-4-26b-a4b-it:free","thinkingmachines/inkling:free","deepseek/deepseek-v4-flash-0731:free"]
```

Backend, geçici yukarı akış hatalarını (429/5xx) yeniden dener ve kibarca
doygunlaşan her model için zincirde bir sonraki modele atlar; böylece dengesiz
ücretsiz sağlayıcılar zarifçe devreye girer.

### 4) Testler ve lint

```bash
cd backend
.\.venv\Scripts\python -m pytest -q                 # 158 test, yukarı akışlar mock

cd frontend
npm run lint                                         # oxlint
npm run build                                        # tsc -b && vite build
```

## Yapılandırma

| Değişken | Varsayılan | Amaç |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 API anahtarı (analiz için zorunlu) |
| `OPENROUTER_API_KEY` | — | OpenRouter anahtarı (AI yorumu için zorunlu) |
| `OPENROUTER_MODEL` | `openrouter/auto` | birincil model, örn. `nvidia/nemotron-3-super-120b-a12b:free` |
| `OPENROUTER_FALLBACK_MODELS` | `[]` | sıralı yedek model zinciri (JSON dizi veya virgülle ayrılmış) |
| `AI_ASSIST_DEFAULT` | `false` | her analizde AI yorumunu çalıştır |
| `DATABASE_URL` | `sqlite+aiosqlite:///./threatlens.db` | SQLite (dev) veya `postgresql+asyncpg://…` |
| `CACHE_TTL_SECONDS` | `3600` | tekrar analizler için tazelik/önbellek penceresi |
| `MAX_UPLOAD_SIZE_MB` | `32` | `analyze/file` için maksimum yükleme boyutu |
| `WATCHLIST_RESCAN_INTERVAL_SECONDS` | `0` | arka plan yeniden tarama sıklığı (`0` = yalnızca istek üzerine) |
| `RBAC_ENABLED` | `false` | `X-ThreatLens-Role` zorunluluğu (viewer / analyst / admin) |
| `CORS_ORIGINS` | `["http://localhost:5173","http://127.0.0.1:5173"]` | izin verilen frontend'ler |

## API Özeti (`/api/v1`)

| Endpoint | Açıklama |
| --- | --- |
| `GET /health` | servis sağlığı |
| `POST /analyze/hash` · `POST /analyze/url` · `POST /analyze/domain` · `POST /analyze/ip` | gösterge analizi (`"ai": true` kabul eder) |
| `POST /analyze/file` | dosya yükle → hash → gönder → yokla |
| `GET /history?limit=&offset=&filter=&search=` | sayfalı geçmiş (filtre: all/malicious/suspicious/clean) |
| `GET /analysis/{id}` | saklanan analiz sonucu |
| `POST /analysis/{id}/ai` | mevcut analizi AI ile zenginleştir |
| `GET /analysis/{id}/graph` | IOC ilişki grafiği (düğüm/kenar — React Flow) |
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

### Raporlar ve PDF Dışa Aktarma

`app/services/report_service.py`, saklanan herhangi bir analizden deterministik
bir rapor derler:

- **Tek model, iki çıktı** — `build_report`, yapılandırılmış bir `ReportDocument`
  üretir (yönetici özeti + kanıt tabloları + isteğe bağlı AI bölümü); `render_pdf`
  aynı modeli reportlab ile çizer; böylece JSON önizlemesi ile PDF asla
  birbirinden sapmaz.
- **Sunucu tarafında çizilir** — `GET /reports/{id}/pdf`, uygun bir
  `Content-Disposition` ile `application/pdf` akışı döndürür. Müsaitse Unicode
  yazı tipi (önce Segoe UI, sonra Arial) gömülür; aksi halde PDF üretimi her
  zaman başarılı olsun diye Helvetica kullanılır.
- **AI entegrasyonu** — analiz bir `ai` yorumu taşıyorsa taktikler, yetenekler,
  öneriler, ilişkiler ve tehdit aktörü profili rapora dahil edilir.

## CI/CD

`.github/workflows/ci.yml`, `main`'e yapılan her push/PR'da çalışır:

- **Backend**: `requirements.txt` kurulur, boş anahtarlı bir `.env` oluşturulur,
  tüm pytest takımı çalıştırılır (yukarı akışlar bellek içi DB + httpx mock
  taşıyıcılarıyla taklit edilir).
- **Frontend**: `npm ci` → `npm run lint` → `npm run build`.

## Dağıtım Notları

- Üretimde `DATABASE_URL` ile PostgreSQL (örn. Supabase) kullanın ve şemayı
  Alembic ile yönetin (`python -m alembic upgrade head`).
- `APP_ENV=production` ve `DEBUG=false` ayarlayın; `.env` dosyasını asla
  commit'lemeyin — üretimde anahtarlar ortam değişkenlerinden okunur.
- Statik frontend derlemesi (`frontend/dist`) herhangi bir CDN/host'tan
  sunulabilir; üretimde API anahtarları backend'de kalır (dev proxy'si
  `vite.config.ts` içinde `/api/*` öğesini `:8000`'e iletir ve backend,
  `CORS_ORIGINS` ile CORS'u zorlar).