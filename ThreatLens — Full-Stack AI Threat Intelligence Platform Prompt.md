# THREATLENS — AI-ASSISTED THREAT INTELLIGENCE PLATFORM

## 1. PROJE TANIMI

Profesyonel görünümlü, modern bir web tabanlı cybersecurity / threat intelligence platformu geliştir.

Projenin adı:

**ThreatLens**

Temel fikir:

Kullanıcı bir dosya, hash, URL, domain veya IP adresi gönderir.

Uygulama:

1. VirusTotal API üzerinden teknik güvenlik verilerini toplar.
2. VirusTotal sonuçlarını normalize eder.
3. Dosya davranışları, antivirus detection sonuçları, network indicators, reputation bilgileri ve mevcut diğer teknik göstergeleri analiz eder.
4. OpenRouter API üzerinden bir LLM'e yalnızca elde edilen teknik kanıtları gönderir.
5. LLM bu verileri bir malware/security analyst gibi yorumlar.
6. Kullanıcıya teknik veriyi sadeleştiren ama teknik doğruluğu koruyan profesyonel bir güvenlik raporu sunar.

Önemli:

LLM hiçbir zaman VirusTotal'da bulunmayan bir davranışı gerçekmiş gibi uydurmamalıdır.

Sistem:

**Evidence → Analysis → Explanation**

mantığıyla çalışmalıdır.

Bu proje basit bir VirusTotal API wrapper gibi görünmemeli.

Gerçek bir security product hissi vermelidir.

---

# 2. TEKNOLOJİ STACK

## Backend

- Python 3.11+
- FastAPI
- Pydantic v2
- httpx
- SQLAlchemy 2
- Alembic
- SQLite development için kullanılabilir
- Production-ready yapı için MSSQL desteğini mümkün kıl
- python-dotenv
- structlog veya standart logging
- pytest
- asyncio

VirusTotal:

- VirusTotal API v3
- API key `.env` içerisinden okunmalı

AI:

- OpenRouter API
- API key `.env` içerisinden okunmalı
- Model `.env` üzerinden değiştirilebilir olmalı

Örneğin:

```env
VIRUSTOTAL_API_KEY=
OPENROUTER_API_KEY=
OPENROUTER_MODEL=
DATABASE_URL=
```

API key'ler kesinlikle frontend'e gönderilmemeli.

---

# 3. FRONTEND

Kullan:

- React
- TypeScript
- Vite
- Tailwind CSS
- React Router
- TanStack Query
- Axios
- React Hook Form
- Zod
- Lucide Icons
- Recharts

Frontend modern, premium ve profesyonel görünmeli.

Generic admin dashboard yapılmamalı.

Cybersecurity ürünleri ve modern security operation center dashboardlarından ilham alan ama özgün bir tasarım oluştur.

---

# 4. TASARIM DİLİ

Arayüzün en önemli özelliklerinden biri profesyonel görünmesi.

Tasarım:

- Dark-first
- Minimal
- Premium
- Technical
- Clean
- High information density
- Modern typography
- Subtle glass effect
- İnce borderlar
- Soft shadows
- Büyük boşluk kullanımı
- Gereksiz gradient kullanımından kaçın
- Gereksiz neon/cyberpunk efektleri kullanma
- Emoji kullanma
- "AI generated" hissi veren hazır dashboard tasarımlarından kaçın

Renk paleti:

Ana arka plan:

near-black / charcoal

Kartlar:

birkaç ton daha açık koyu gri

Accent:

tek bir ana accent rengi kullan.

Threat seviyeleri için:

- LOW
- MEDIUM
- HIGH
- CRITICAL

durumlarını görsel olarak birbirinden ayır.

Ancak ekranı kırmızıya boğma.

---

# 5. ANA LAYOUT

Desktop layout:

```text
┌─────────────────────────────────────────────────────────────┐
│ ThreatLens                         Search      Settings     │
├──────────────┬──────────────────────────────────────────────┤
│              │                                              │
│ Dashboard    │                                              │
│              │                                              │
│ Analyze      │              MAIN CONTENT                    │
│              │                                              │
│ History      │                                              │
│              │                                              │
│ Reports      │                                              │
│              │                                              │
│              │                                              │
│ Settings     │                                              │
│              │                                              │
├──────────────┴──────────────────────────────────────────────┤
│ API Status: Operational                                     │
└─────────────────────────────────────────────────────────────┘
```

Sidebar:

- ThreatLens logo
- Dashboard
- Analyze
- History
- Reports
- Settings

Sidebar sade ve profesyonel olmalı.

---

# 6. DASHBOARD

Dashboard uygulamanın ana ekranı.

Üst bölüm:

```text
Threat Intelligence Dashboard

Monitor, investigate and understand suspicious indicators.
```

Altında hızlı analiz alanı:

```text
┌──────────────────────────────────────────────────────┐
│ Analyze an indicator                                  │
│                                                      │
│ [ Hash / URL / Domain / IP / File ]        [Analyze] │
└──────────────────────────────────────────────────────┘
```

Son analizler:

```text
Recent Investigations

sample.exe
SHA256
HIGH
5 detections
2 minutes ago

example.com
DOMAIN
LOW
0 detections
12 minutes ago
```

İstatistik kartları:

- Total Analyses
- Malicious
- Suspicious
- Clean
- High Risk

Dashboard üzerinde gereksiz grafik kalabalığı oluşturma.

En az:

- Threat distribution chart
- Analysis activity chart

kullan.

---

# 7. ANALYZE SAYFASI

En önemli sayfalardan biri.

Üstte segmented input selector:

```text
[ File ] [ Hash ] [ URL ] [ Domain ] [ IP ]
```

## Hash

SHA256 / SHA1 / MD5 kabul et.

Hash gönderildiğinde VirusTotal'dan mevcut dosya raporunu çek.

---

## URL

Kullanıcı URL girebilir.

VirusTotal URL analizini kullan.

---

## Domain

Domain reputation ve ilgili VirusTotal bilgilerini getir.

---

## IP

IP reputation ve ilişkili bilgileri getir.

---

## File

Dosya upload destekle.

Dosya:

- SHA256 hesapla
- SHA1 hesapla
- MD5 hesapla
- VirusTotal'a gönder
- Analysis ID al
- Analysis durumunu takip et
- Sonuçları getir

Dosyanın kendisini LLM'e gönderme.

LLM'e VirusTotal'dan elde edilen normalize edilmiş teknik verileri gönder.

---

# 8. ANALYSIS RESULT SAYFASI

Bu sayfa projenin en önemli ekranı.

Örneğin:

```text
THREAT ANALYSIS

sample.exe

SHA256
44d88612fea8a8f36de82e1278abb02f

┌────────────────────────────────────────────┐
│              HIGH RISK                     │
│                                            │
│                 82 / 100                   │
│                                            │
│  5 Malicious    2 Suspicious    51 Clean   │
└────────────────────────────────────────────┘
```

Altında tab sistemi:

```text
[ Overview ]
[ Detections ]
[ Behavior ]
[ Network ]
[ Indicators ]
[ AI Analysis ]
```

---

# 9. OVERVIEW

Göster:

- File name
- File type
- File size
- MD5
- SHA1
- SHA256
- First seen
- Last analysis
- Reputation
- Detection ratio

Örnek:

```text
File Information

Name          sample.exe
Type          Win32 EXE
Size          2.41 MB

SHA256
44d886...

First Seen
2026-09-10

Last Analysis
2026-09-15
```

---

# 10. DETECTIONS

VirusTotal antivirus engine sonuçlarını göster.

Tablo:

```text
Engine              Result              Category

Microsoft           Trojan              Malicious
Kaspersky           HEUR:Trojan         Malicious
ESET                Win32/Trojan        Malicious
Bitdefender         Trojan.Generic      Malicious
Avast               —                   Undetected
```

Filtre:

```text
All
Malicious
Suspicious
Undetected
Harmless
```

Her detection için engine adı, result ve category göster.

---

# 11. BEHAVIOR

VirusTotal behavior verisi varsa göster.

Örneğin:

```text
Behavioral Analysis

Processes
├── powershell.exe
├── cmd.exe
└── rundll32.exe

File System
├── Creates executable
├── Modifies files
└── Deletes temporary files

Registry
├── Registry modification detected
└── Startup key activity

Network
├── HTTP connection
├── DNS request
└── Remote IP connection
```

Her davranışın yanında:

- severity
- evidence
- source

gibi bilgiler gösterilebilir.

---

# 12. NETWORK

Network indicators varsa:

```text
Network Activity

Domains
example.com
malicious-domain.test

IP Addresses
185.xxx.xxx.xxx

URLs
https://example.com/...

DNS Requests
...
```

Network indicator'larını tıklanabilir yap.

Kullanıcı bir indicator'a tıkladığında tekrar VirusTotal analizi yapılabilsin.

---

# 13. AI ANALYSIS

Bu ekran uygulamanın ana fark yaratıcı özelliği.

Başlık:

```text
AI SECURITY ANALYSIS
```

Altında:

```text
Generated from VirusTotal evidence

Model:
<model name>

Analysis confidence:
Medium
```

LLM sonucu bölümlere ayrılmalı.

## Executive Summary

Normal bir insanın anlayacağı dilde:

> Bu dosya neden tehlikeli olabilir?

---

## What Was Detected?

VirusTotal kanıtlarını özetle.

---

## Why Is It Suspicious?

Davranışları açıkla.

---

## Possible Impact

Kanıtların desteklediği ölçüde:

- Credential theft
- Persistence
- Remote access
- Data exfiltration
- Process injection
- Downloader behavior

gibi olası etkileri belirt.

Ancak kesin kanıt yoksa:

"Potentially associated with..."

gibi ihtiyatlı dil kullan.

---

## Evidence

LLM'in kullandığı VirusTotal kanıtlarını göster.

Örneğin:

```text
Evidence #1

5 antivirus engines classified the file as malicious.

Source:
VirusTotal Detection Results

Confidence:
High
```

---

## Recommended Actions

Örneğin:

1. Do not execute the file.
2. Isolate the affected endpoint.
3. Investigate contacted domains.
4. Search for the SHA256 across endpoint logs.
5. Review persistence-related events.

Öneriler teknik ama güvenli olmalı.

---

# 14. AI HALLUCINATION KONTROLÜ

ÇOK ÖNEMLİ.

LLM system prompt'u şu prensiplere sahip olmalı:

- Sadece verilen evidence üzerinden yorum yap.
- VirusTotal'da bulunmayan bir davranışı varmış gibi gösterme.
- Kanıt yoksa "insufficient evidence" de.
- Tahmin ile kesin bulguyu birbirinden ayır.
- Confidence score üret.
- Teknik ifadeleri açıkla.
- Detection label'ını doğrudan malware family olarak kabul etme.
- Bir antivirus engine'in generic detection'ını kesin malware davranışı olarak yorumlama.
- Çelişkili veriler varsa belirt.
- Kullanıcıya gereksiz kesinlik verme.

Örneğin:

YANLIŞ:

```text
This malware steals browser passwords.
```

Eğer böyle bir evidence yoksa.

DOĞRU:

```text
The available evidence does not confirm browser credential theft.
Some observed behaviors may be consistent with credential-access activity, but additional evidence is required.
```

---

# 15. THREAT SCORE

Kendi threat scoring sistemini oluştur.

0-100 arası:

```text
0-20      LOW
21-40     MODERATE
41-60     ELEVATED
61-80     HIGH
81-100    CRITICAL
```

Score hesaplanırken:

- malicious detection ratio
- suspicious ratio
- behavior severity
- network indicators
- reputation
- file characteristics

gibi mevcut kanıtlar kullanılabilir.

Score'un neden oluştuğunu kullanıcıya göster.

Örneğin:

```text
Threat Score: 82

+30 Multiple malicious detections
+20 Suspicious behavioral indicators
+15 Network activity
+10 Persistence-related behavior
-03 Low confidence indicators
```

Score tamamen şeffaf olmalı.

---

# 16. HISTORY

Kullanıcının yaptığı analizleri listele.

Kolonlar:

```text
Indicator
Type
Risk
Score
Detections
Analyzed At
```

Filtre:

```text
All
Malicious
Suspicious
Clean
```

Arama:

```text
Search SHA256 / URL / Domain / IP
```

Bir analize tıklayınca detay sayfasına git.

---

# 17. REPORTS

Kullanıcı analiz sonucunu rapor olarak görüntüleyebilmeli.

Report içeriği:

```text
ThreatLens Security Report

Indicator
Threat Level
Threat Score

Executive Summary

Detection Summary

Behavioral Analysis

Network Indicators

AI Security Analysis

Evidence

Recommended Actions
```

PDF export desteği ekle.

---

# 18. API ENDPOINTLERİ

Backend aşağıdaki yapıya sahip olsun:

```text
/api/v1/health

/api/v1/analyze/hash
/api/v1/analyze/url
/api/v1/analyze/domain
/api/v1/analyze/ip
/api/v1/analyze/file

/api/v1/analysis/{analysis_id}

/api/v1/analysis/{analysis_id}/detections
/api/v1/analysis/{analysis_id}/behavior
/api/v1/analysis/{analysis_id}/network
/api/v1/analysis/{analysis_id}/ai

/api/v1/history
/api/v1/reports/{analysis_id}
```

API response'larını Pydantic schema'larıyla standardize et.

---

# 19. SERVICE ARCHITECTURE

Backend'i tek bir devasa dosyaya koyma.

Şuna benzer bir yapı kullan:

```text
backend/
│
├── app/
│   ├── main.py
│   │
│   ├── api/
│   │   └── v1/
│   │       ├── analyze.py
│   │       ├── analysis.py
│   │       ├── history.py
│   │       └── reports.py
│   │
│   ├── core/
│   │   ├── config.py
│   │   ├── logging.py
│   │   └── security.py
│   │
│   ├── models/
│   │   ├── analysis.py
│   │   ├── indicator.py
│   │   └── report.py
│   │
│   ├── schemas/
│   │   ├── analysis.py
│   │   ├── virustotal.py
│   │   └── ai.py
│   │
│   ├── services/
│   │   ├── virustotal_service.py
│   │   ├── openrouter_service.py
│   │   ├── analysis_service.py
│   │   ├── threat_score_service.py
│   │   └── report_service.py
│   │
│   ├── repositories/
│   │   └── analysis_repository.py
│   │
│   └── utils/
│
├── tests/
│
├── alembic/
│
├── .env.example
├── requirements.txt
└── README.md
```

Frontend:

```text
frontend/
│
├── src/
│   ├── components/
│   │   ├── layout/
│   │   ├── charts/
│   │   ├── analysis/
│   │   ├── detections/
│   │   └── ai/
│   │
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Analyze.tsx
│   │   ├── AnalysisDetail.tsx
│   │   ├── History.tsx
│   │   ├── Reports.tsx
│   │   └── Settings.tsx
│   │
│   ├── services/
│   │   └── api.ts
│   │
│   ├── hooks/
│   │
│   ├── types/
│   │
│   ├── utils/
│   │
│   ├── App.tsx
│   └── main.tsx
│
└── package.json
```

---

# 20. VIRUSTOTAL SERVICE

VirusTotal API erişimini frontend'den kesinlikle yapma.

Backend üzerinden yap.

Özel service oluştur:

```text
VirusTotalService
```

Bu service:

- get_file
- upload_file
- get_analysis
- get_url
- get_domain
- get_ip
- get_relationships

gibi fonksiyonlara sahip olabilir.

API response'larını doğrudan frontend'e göndermek yerine normalize et.

---

# 21. OPENROUTER SERVICE

Ayrı service:

```text
OpenRouterService
```

Fonksiyon:

```text
generate_security_analysis(evidence)
```

LLM'e gönderilen payload mümkün olduğunca küçük ve anlamlı olmalı.

Tüm gereksiz VirusTotal JSON'unu modele göndermeyin.

Önce:

```text
Raw VirusTotal Data
        ↓
Normalization
        ↓
Relevant Evidence
        ↓
LLM
```

pipeline'ı oluştur.

---

# 22. STRUCTURED AI RESPONSE

LLM'den düz metin isteme.

JSON response iste.

Örneğin:

```json
{
  "risk_level": "HIGH",
  "confidence": 0.87,
  "summary": "...",
  "what_was_detected": [],
  "why_suspicious": [],
  "possible_impact": [],
  "evidence": [],
  "recommended_actions": [],
  "limitations": []
}
```

Backend bu JSON'u validate etmeli.

Invalid JSON gelirse güvenli şekilde retry/fallback yap.

Frontend bu response'u güzel kartlar halinde göstermeli.

---

# 23. ERROR HANDLING

Aşağıdaki durumların hepsini düzgün yönet:

- VirusTotal API key missing
- OpenRouter API key missing
- VirusTotal rate limit
- OpenRouter rate limit
- Invalid hash
- Invalid URL
- Invalid IP
- Invalid domain
- File too large
- Unsupported file type
- VirusTotal analysis pending
- VirusTotal analysis failed
- AI response timeout
- AI invalid JSON
- Network error

Kullanıcıya teknik stack trace gösterme.

Örneğin:

```text
Unable to retrieve VirusTotal analysis.

Please try again in a moment.
```

göster.

---

# 24. LOADING EXPERIENCE

Loading ekranları profesyonel olmalı.

Dosya analizinde:

```text
Uploading file...
        ↓
Calculating hashes...
        ↓
Submitting to VirusTotal...
        ↓
Waiting for analysis...
        ↓
Collecting detections...
        ↓
Collecting behavioral indicators...
        ↓
Generating AI analysis...
        ↓
Building report...
```

gibi progress state göster.

Ancak sahte progress üretme.

Gerçek backend durumuna göre ilerlet.

---

# 25. SECURITY

Aşağıdaki güvenlik kurallarına uy:

- API key'leri frontend'e gönderme.
- `.env` gitignore'a ekle.
- `.env.example` oluştur.
- Kullanıcı inputlarını validate et.
- URL validation yap.
- IP validation yap.
- Hash validation yap.
- Upload size limit koy.
- Dosya türü validation yap.
- Path traversal risklerini engelle.
- Dosya adını sanitize et.
- SSRF riskine dikkat et.
- Kullanıcının verdiği URL'yi backend'in doğrudan fetch etmesi gerekiyorsa güvenli URL validation uygula.
- API rate limiting ekle.
- Sensitive data loglama.
- Exception mesajlarında API key veya secret gösterme.

---

# 26. CACHE

Aynı hash tekrar sorgulandığında gereksiz VirusTotal API çağrısı yapma.

Örneğin:

```text
SHA256
   ↓
Local DB
   ↓
Existing recent result?
   │
 YES ──→ return cached result
   │
 NO
   ↓
VirusTotal
```

Cache TTL configurable olsun.

---

# 27. RESPONSIVE DESIGN

Desktop öncelikli geliştir.

Ama:

- tablet
- mobile

ekranlarda da düzgün çalışmalı.

Analysis ekranı mobilde kullanılabilir olmalı.

---

# 28. EMPTY STATES

Boş ekran bırakma.

Örneğin Dashboard'da analiz yoksa:

```text
No investigations yet.

Start by analyzing a file, hash, URL, domain or IP.
```

ve:

```text
[ Start Analysis ]
```

butonu göster.

---

# 29. DEMO DATA

API key olmadan frontend'in tasarımını test edebilmek için development mode'da mock data desteği oluştur.

Örneğin:

```text
demo-malware
demo-clean
demo-suspicious
```

analizleri.

Ancak gerçek VirusTotal sonucu gibi gösterme.

UI üzerinde:

```text
DEMO DATA
```

etiketi kullan.

---

# 30. README

Profesyonel README oluştur.

README'de:

## ThreatLens

AI-assisted threat intelligence platform powered by VirusTotal and OpenRouter.

### Features

- File analysis
- Hash analysis
- URL analysis
- Domain intelligence
- IP intelligence
- Antivirus detections
- Behavioral analysis
- Network indicators
- AI-assisted explanation
- Threat scoring
- Analysis history
- Security reports
- PDF export

### Architecture

```text
React
  ↓
FastAPI
  ↓
Analysis Engine
  ├── VirusTotal
  └── OpenRouter
```

### Setup

Environment variables.

### API

Endpoint documentation.

### Security Notes

API keys.

### Limitations

VirusTotal API limits.

AI analysis is an interpretation layer and not a replacement for professional malware analysis.

---

# 31. UI MICRO-INTERACTIONS

Kullanıcı deneyimini kaliteli yap:

- subtle hover states
- smooth page transitions
- skeleton loaders
- expandable cards
- copy-to-clipboard buttons
- tooltip
- toast notifications
- collapsible evidence sections
- expandable detection rows

Ancak animasyonları abartma.

---

# 32. COPY HASH BUTTON

SHA256 gibi uzun değerlerin yanında:

```text
44d88612fea8a8f36de82...    [Copy]
```

butonu olsun.

Kopyalandığında:

```text
Copied
```

toast göster.

---

# 33. THREAT LEVEL COMPONENT

Threat score için profesyonel bir visualization oluştur.

Örneğin:

```text
          82

       HIGH RISK

████████████████░░░░
```

Animasyonlu olabilir.

Ancak gereksiz radial gauge kullanma.

---

# 34. EVIDENCE-FIRST AI

AI Analysis ekranında:

```text
AI Interpretation
```

ile

```text
Observed Evidence
```

birbirinden görsel olarak ayrılmalı.

Kullanıcı her AI yorumunun hangi evidence'a dayandığını görebilmeli.

Bu özellik projenin en önemli farklarından biri.

---

# 35. IMPORTANT PRODUCT RULE

Uygulama hiçbir zaman:

```text
VirusTotal says malware
→ AI invents malware behavior
```

şeklinde çalışmamalı.

Doğru pipeline:

```text
VirusTotal
    ↓
Raw Data
    ↓
Normalization
    ↓
Evidence Extraction
    ↓
Threat Scoring
    ↓
OpenRouter
    ↓
AI Interpretation
    ↓
Human-readable Report
```

---

# 36. DEVELOPMENT STRATEGY

Projeyi tek seferde yüzlerce dosya oluşturarak geliştirme.

Aşamalar:

## Phase 1

Backend skeleton.

FastAPI.

Health endpoint.

Configuration.

`.env`.

---

## Phase 2

VirusTotal integration.

Hash analysis.

URL analysis.

Domain/IP analysis.

---

## Phase 3

File upload.

Analysis polling.

Normalization.

---

## Phase 4

Database.

Analysis history.

Cache.

---

## Phase 5

OpenRouter integration.

Structured AI response.

Evidence-based prompt.

---

## Phase 6

Threat scoring.

---

## Phase 7

React dashboard.

---

## Phase 8

Analysis detail UI.

---

## Phase 9

History.

Reports.

PDF.

---

## Phase 10

Testing.

Error handling.

Security hardening.

README.

---

# 37. CODING RULES

Kod yazarken:

- Type safety
- Clean architecture
- SOLID principles where appropriate
- DRY
- Small services
- Small components
- Reusable components
- Meaningful names
- No giant files
- No hardcoded API keys
- No duplicated API logic
- No fake data in production paths
- No unnecessary dependencies

kullan.

Her önemli service için unit test yaz.

---

# 38. FINAL QUALITY BAR

Projeyi bitirdiğinde şu hissi vermeli:

"Bu bir öğrencinin VirusTotal API denemesi."

değil.

Şu hissi vermeli:

"Bu, VirusTotal'dan threat intelligence toplayan ve bunu evidence-based AI analysis ile yorumlayan küçük ama gerçek bir cybersecurity product."

UI modern, sade ve premium olmalı.

Kod production-quality olmaya mümkün olduğunca yaklaşmalı.

---

# 39. FIRST TASK

Önce tüm projeyi analiz et ve implementation planını oluştur.

Ardından Phase 1 ile başla.

İlk aşamada:

1. Backend klasör yapısını oluştur.
2. FastAPI uygulamasını oluştur.
3. Configuration sistemini oluştur.
4. `.env.example` oluştur.
5. Health endpoint oluştur.
6. CORS yapılandır.
7. Logging yapılandır.
8. Basic error handling oluştur.
9. Frontend React + TypeScript + Vite projesini oluştur.
10. Tailwind yapılandır.
11. Ana layout oluştur.
12. Sidebar oluştur.
13. Dashboard placeholder oluştur.
14. Analyze placeholder oluştur.
15. History placeholder oluştur.
16. Reports placeholder oluştur.
17. Modern ThreatLens dark UI tasarımını uygula.

Sonra çalıştır ve herhangi bir hata varsa düzelt.

**Önemli:**

Bir sonraki aşamaya geçmeden önce mevcut aşamanın gerçekten çalıştığını doğrula.

Her aşamada:

- oluşturulan dosyaları açıkla,
- neden oluşturulduğunu açıkla,
- çalıştırma komutlarını ver,
- test sonucunu belirt,
- sonra sonraki aşamaya geç.

Projeyi çalışır halde tut.

Do not sacrifice correctness for speed.