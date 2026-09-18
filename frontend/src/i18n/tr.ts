/**
 * Turkish translation table.
 *
 * Keys are the source (English) strings used in the UI. Anything missing falls
 * back to the key itself, so new copy is never blank — it just stays English
 * until it is translated here. `{name}` placeholders are interpolated by `t()`.
 */
export const tr: Record<string, string> = {
  // --- Navigation & layout ------------------------------------------------- //
  Dashboard: 'Panel',
  Analyze: 'Analiz Et',
  History: 'Geçmiş',
  'IOC Inventory': 'IOC Envanteri',
  Investigations: 'Soruşturmalar',
  Watchlist: 'İzleme Listesi',
  'Watchlist & Alerts': 'İzleme Listesi ve Uyarılar',
  Reports: 'Raporlar',
  Settings: 'Ayarlar',
  'Toggle navigation': 'Gezinmeyi aç/kapat',
  'Close navigation': 'Gezinmeyi kapat',
  Command: 'Komut',
  System: 'Sistem',
  'API Status:': 'API Durumu:',

  // --- API status ----------------------------------------------------------- //
  Unreachable: 'Erişilemiyor',
  'Checking…': 'Kontrol ediliyor…',
  Operational: 'Çalışıyor',
  Degraded: 'Bozuk',
  Ready: 'Hazır',
  Status: 'Durum',
  Version: 'Sürüm',
  Environment: 'Ortam',
  Service: 'Servis',

  // --- Generic -------------------------------------------------------------- //
  'Loading…': 'Yükleniyor…',
  'Unknown error.': 'Bilinmeyen hata.',
  'An unexpected error occurred.': 'Beklenmeyen bir hata oluştu.',
  'Not found': 'Bulunamadı',
  'No matches.': 'Eşleşme yok.',
  Search: 'Ara',
  Back: 'Geri',
  Close: 'Kapat',
  Open: 'Aç',
  Add: 'Ekle',
  Delete: 'Sil',
  Cancel: 'İptal',
  'Mark all seen': 'Tümünü görüldü işaretle',
  'View all': 'Tümünü gör',
  'Copy indicator': 'Göstergeyi kopyala',
  '— copied': '— kopyalandı',

  // --- Indicator type labels ------------------------------------------------ //
  'type.FILE': 'Dosya',
  'type.HASH': 'Hash',
  'type.URL': 'URL',
  'type.DOMAIN': 'Alan Adı',
  'type.IP': 'IP',
  File: 'Dosya',
  Hash: 'Hash',
  URL: 'URL',
  Domain: 'Alan Adı',
  IP: 'IP',

  // --- Threat levels -------------------------------------------------------- //
  clean: 'Temiz',
  suspicious: 'Şüpheli',
  malicious: 'Zararlı',
  critical: 'Kritik',
  undetected: 'Tespit edilmedi',
  harmless: 'Zararsız',
  timeout: 'Zaman aşımı',
  'type-unsupported': 'Desteklenmiyor',
  unknown: 'Bilinmiyor',

  // --- Dashboard ------------------------------------------------------------ //
  'A live overview of the threat intelligence you’ve gathered.':
    'Topladığın tehdit istihbaratına canlı bir bakış.',
  "A live overview of the threat intelligence you've gathered.":
    'Topladığın tehdit istihbaratına canlı bir bakış.',
  'New analysis': 'Yeni analiz',
  'Total analyses': 'Toplam analiz',
  'Across all indicator types': 'Tüm gösterge türleri',
  Flagged: 'İşaretli',
  'Malicious or critical verdicts': 'Zararlı veya kritik sonuçlar',
  Coverage: 'Kapsam',
  'Latest 50 loaded for charts': 'Grafikler için yüklenen son 50',
  'Verdict mix': 'Sonuç dağılımı',
  'Level distribution': 'Seviye dağılımı',
  'Nothing charted yet': 'Henüz grafik yok',
  'Analyze your first indicator to see the verdict mix.':
    'Sonuç dağılımını görmek için ilk göstergeni analiz et.',
  'Recent work': 'Son çalışmalar',
  'Latest analyses': 'Son analizler',
  'No activity yet': 'Henüz etkinlik yok',
  'Your most recent investigations will appear here.':
    'En son soruşturmaların burada görünecek.',
  'Deterministic scoring': 'Deterministik puanlama',
  'Every indicator gets a reproducible 0–100 threat score from detection ratios, reputation and community verdicts.':
    'Her gösterge; tespit oranları, itibar ve topluluk oylarından yeniden üretilebilir 0–100 tehdit puanı alır.',
  'Evidence-based AI': 'Kanıta dayalı AI',
  'AI interpretation is built exclusively from the normalized VirusTotal report — never from guesses.':
    'AI yorumu yalnızca normalize edilmiş VirusTotal raporundan üretilir — asla tahminden değil.',
  'Actionable history': 'İşlenebilir geçmiş',
  'Every analysis is persisted locally so you can search, filter and review findings over time.':
    'Her analiz yerel olarak saklanır; bulguları zaman içinde arayabilir, filtreleyebilir ve inceleyebilirsin.',
  'Quick-analyze as {type}': '{type} olarak hızlı analiz',
  'Global search': 'Genel arama',
  'Find anything': 'Her şeyi bul',
  'Indicator, IOC or note…': 'Gösterge, IOC veya not…',
  'Type at least two characters to search analyses, IOCs and cases.':
    'Analizleri, IOC’leri ve vakaları aramak için en az iki karakter yaz.',
  'Searching…': 'Aranıyor…',
  'Intelligence digest': 'İstihbarat özeti',
  'Period summary': 'Dönem özeti',
  Today: 'Bugün',
  'This week': 'Bu hafta',
  'This month': 'Bu ay',
  'Building digest…': 'Özet hazırlanıyor…',
  Enrichment: 'Zenginleştirme',
  'Provider health': 'Sağlayıcı sağlığı',
  'No enrichment activity recorded yet.':
    'Henüz zenginleştirme etkinliği kaydedilmedi.',

  // --- Analyze page --------------------------------------------------------- //
  'Analyze an Indicator': 'Gösterge Analiz Et',
  'Submit a file, hash, URL, domain or IP address for threat analysis.':
    'Tehdit analizi için bir dosya, hash, URL, alan adı veya IP adresi gönder.',
  'Input type': 'Girdi türü',
  'Select indicator type': 'Gösterge türünü seç',
  'Upload a file to compute its hashes and submit it for analysis.':
    'Hash’lerini hesaplamak ve analize göndermek için bir dosya yükle.',
  'Enter a SHA256, SHA1 or MD5 hash to pull the existing report.':
    'Mevcut raporu çekmek için SHA256, SHA1 veya MD5 hash gir.',
  'Submit a URL for VirusTotal scan and detection.':
    'VirusTotal taraması ve tespiti için bir URL gönder.',
  'Retrieve domain reputation and related intelligence.':
    'Alan adı itibarını ve ilgili istihbaratı getir.',
  'Check IP reputation and associated indicators.':
    'IP itibarını ve ilişkili göstergeleri kontrol et.',
  'What ThreatLens analyzes': 'ThreatLens neleri analiz eder',
  'Hash intelligence': 'Hash istihbaratı',
  'VirusTotal reports for SHA256, SHA1 and MD5.':
    'SHA256, SHA1 ve MD5 için VirusTotal raporları.',
  'URL & Domain': 'URL ve Alan Adı',
  'Reputation, detections and historical signals.':
    'İtibar, tespitler ve geçmiş sinyaller.',
  'IP reputation': 'IP itibarı',
  'ASN, country and detection context.':
    'ASN, ülke ve tespit bağlamı.',
  'File submission': 'Dosya gönderimi',
  'Hashes computed and submitted on the server side.':
    'Hash’ler sunucu tarafında hesaplanır ve gönderilir.',
  'AI interpretation': 'AI yorumu',
  'Evidence-based security narrative generated server-side.':
    'Sunucu tarafında üretilen kanıta dayalı güvenlik anlatısı.',
  'Analysis engine standby': 'Analiz motoru beklemede',
  'Results render here as soon as the backend responds. Enable AI interpretation to include an evidence-based narrative.':
    'Arka uç yanıt verir vermez sonuçlar burada görünür. Kanıta dayalı anlatı için AI yorumunu etkinleştir.',
  'Analysis failed': 'Analiz başarısız',
  'Open full analysis page': 'Tam analiz sayfasını aç',

  // --- Indicator form ------------------------------------------------------- //
  'Enter an indicator to analyze': 'Analiz edilecek bir gösterge gir',
  'That does not look like a valid {mode} indicator.':
    'Bu geçerli bir {mode} göstergesi gibi görünmüyor.',
  'The selected file is empty.': 'Seçilen dosya boş.',
  'Analyzing…': 'Analiz ediliyor…',
  'Choose a file to analyze': 'Analiz için dosya seç',
  'Hashes are computed and submitted server-side. Max 32 MB.':
    'Hash’ler sunucu tarafında hesaplanır ve gönderilir. En fazla 32 MB.',
  'or drop it here': 'veya buraya bırak',
  'Include AI interpretation': 'AI yorumunu dahil et',

  // --- Analysis result ------------------------------------------------------ //
  Result: 'Sonuç',
  'Detection distribution': 'Tespit dağılımı',
  'Detection engines': 'Tespit motorları',
  '{count} engines': '{count} motor',
  'Indicator profile': 'Gösterge profili',
  Metadata: 'Meta veri',
  'model-generated': 'model tarafından üretildi',
  'Evidence-based analysis': 'Kanıta dayalı analiz',
  'Source:': 'Kaynak:',
  'Analyzed {date}': '{date} tarihinde analiz edildi',
  'Threat score': 'Tehdit puanı',
  'Deterministic, evidence-based verdict from the detection ratios.':
    'Tespit oranlarından çıkan deterministik, kanıta dayalı sonuç.',
  'No per-engine detections were returned by VirusTotal.':
    'VirusTotal motor başına tespit döndürmedi.',
  Engine: 'Motor',
  Verdict: 'Sonuç',
  Method: 'Yöntem',
  flag: 'işaret',
  'Verdict scale:': 'Sonuç ölçeği:',
  'from the evidence-based score rubric.':
    'kanıta dayalı puanlama ölçütünden.',

  // --- Metadata rows -------------------------------------------------------- //
  Reputation: 'İtibar',
  Tags: 'Etiketler',
  'Threat names': 'Tehdit adları',
  'Community votes': 'Topluluk oyları',
  'First submitted': 'İlk gönderim',
  'Last analyzed': 'Son analiz',
  Name: 'Ad',
  'Observed names': 'Gözlenen adlar',
  Type: 'Tür',
  Size: 'Boyut',
  'Final URL': 'Nihai URL',
  Title: 'Başlık',
  Registrar: 'Kayıt kuruluşu',
  Registered: 'Kayıt tarihi',
  Country: 'Ülke',
  'AS owner': 'AS sahibi',
  ASN: 'ASN',

  // --- AI analysis ---------------------------------------------------------- //
  'Model:': 'Model:',
  Summary: 'Özet',
  Tactics: 'Taktikler',
  'Threat actor profile': 'Tehdit aktörü profili',
  'Unknown / unprofiled': 'Bilinmiyor / profilsiz',
  'confidence:': 'güven:',
  Campaign: 'Kampanya',
  'Capabilities & impact': 'Yetenekler ve etki',
  Recommendations: 'Öneriler',
  'Intelligence lifecycle': 'İstihbarat yaşam döngüsü',
  Correlations: 'İlişkiler',
  'Evidence cited': 'Atıfta bulunulan kanıtlar',
  'Not assessed from the evidence.': 'Kanıttan değerlendirilemedi.',
  'Currently assessed at the': 'Şu anda tehdit istihbaratı yaşam döngüsünün',
  'stage of the threat intelligence lifecycle.': 'aşamasında değerlendiriliyor.',
  'AI assessment:': 'AI değerlendirmesi:',
  '— reported separately from the deterministic score.':
    '— deterministik puandan ayrı olarak raporlanır.',
  'reported separately from the deterministic score.':
    'deterministik puandan ayrı olarak raporlanır.',

  // --- History -------------------------------------------------------------- //
  'Everything ThreatLens has analyzed, searchable and filterable.':
    'ThreatLens’in analiz ettiği her şey; aranabilir ve filtrelenebilir.',
  'Analysis history': 'Analiz geçmişi',
  'Search by indicator or name…': 'Gösterge veya ada göre ara…',
  'Loading history…': 'Geçmiş yükleniyor…',
  Indicator: 'Gösterge',
  Score: 'Puan',
  Engines: 'Motorlar',
  Analyzed: 'Analiz edildi',
  All: 'Tümü',
  Clean: 'Temiz',
  Suspicious: 'Şüpheli',
  Malicious: 'Zararlı',
  '{count}/{total} flagged': '{count}/{total} işaretli',
  'Showing {from}–{to} of {total} results':
    '{total} sonuçtan {from}–{to} arası gösteriliyor',
  Previous: 'Önceki',
  Next: 'Sonraki',
  'No analyses found': 'Analiz bulunamadı',
  'No results match the current filter. Try a different search or level.':
    'Geçerli filtreyle eşleşen sonuç yok. Farklı bir arama veya seviye dene.',
  'Run your first analysis to start building a history.':
    'Geçmiş oluşturmak için ilk analizini çalıştır.',
  'Analyze an indicator': 'Bir gösterge analiz et',

  // --- IOC inventory -------------------------------------------------------- //
  'Deduplicated indicators ThreatLens has observed, with observation counts and snapshot history.':
    'ThreatLens’in gözlemlediği, tekilleştirilmiş göstergeler; gözlem sayıları ve anlık görüntü geçmişiyle.',
  Registry: 'Kayıt',
  'Distinct indicators': 'Tekil göstergeler',
  'Search indicators…': 'Gösterge ara…',
  'Loading registry…': 'Kayıt yükleniyor…',
  Seen: 'Görülme',
  '{count} indicators tracked': '{count} gösterge izleniyor',
  '{count} indicator tracked': '{count} gösterge izleniyor',
  'No indicators yet': 'Henüz gösterge yok',
  'Run an analysis and its indicator will be registered here automatically.':
    'Bir analiz çalıştır; göstergesi otomatik olarak buraya kaydedilir.',
  Timeline: 'Zaman çizelgesi',
  'Indicator history': 'Gösterge geçmişi',
  'Select an indicator': 'Bir gösterge seç',
  'Pick a row to see its observation timeline and every stored analysis.':
    'Gözlem zaman çizelgesini ve tüm saklanan analizleri görmek için bir satır seç.',
  '{count} observations': '{count} gözlem',
  '{count} observation': '{count} gözlem',
  'Open latest analysis': 'En son analizi aç',
  'This indicator has no stored snapshots.':
    'Bu göstergenin saklanmış anlık görüntüsü yok.',
  Hashes: 'Hash’ler',
  URLs: 'URL’ler',
  Domains: 'Alan Adları',
  IPs: 'IP’ler',

  // --- Investigations ------------------------------------------------------- //
  'Group indicators into cases, pivot across evidence and keep analyst notes.':
    'Göstergeleri vakalarda grupla, kanıtlar arasında gez ve analist notlarını tut.',
  'New case': 'Yeni vaka',
  'Open an investigation': 'Soruşturma aç',
  'Operation …': 'Operasyon …',
  Severity: 'Önem derecesi',
  Description: 'Açıklama',
  'What are you investigating?': 'Neyi soruşturuyorsun?',
  'Create case': 'Vaka oluştur',
  Cases: 'Vakalar',
  'Investigation queue': 'Soruşturma kuyruğu',
  'Loading cases…': 'Vakalar yükleniyor…',
  'status.open': 'Açık',
  'status.active': 'Aktif',
  'status.closed': 'Kapalı',
  'severity.low': 'Düşük',
  'severity.medium': 'Orta',
  'severity.high': 'Yüksek',
  'severity.critical': 'Kritik',
  '{count} indicators': '{count} gösterge',
  '{count} indicator': '{count} gösterge',
  'No cases yet': 'Henüz vaka yok',
  'Open a case to group related indicators and analyses.':
    'İlgili gösterge ve analizleri gruplamak için bir vaka aç.',
  'Case file': 'Vaka dosyası',
  Details: 'Ayrıntılar',
  'Select a case': 'Bir vaka seç',
  'Pick a case to manage its indicators, status and severity.':
    'Göstergelerini, durumunu ve önemini yönetmek için bir vaka seç.',
  'Loading case…': 'Vaka yükleniyor…',
  'Case not found': 'Vaka bulunamadı',
  'Add indicator': 'Gösterge ekle',
  'indicator…': 'gösterge…',
  'Could not add the indicator.': 'Gösterge eklenemedi.',
  Indicators: 'Göstergeler',
  'No indicators linked yet.': 'Henüz bağlı gösterge yok.',
  'opened {date}': '{date} tarihinde açıldı',

  // --- Watchlist & alerts --------------------------------------------------- //
  'Continuously re-check indicators and get notified when alert rules fire.':
    'Göstergeleri sürekli yeniden kontrol et ve uyarı kuralları tetiklendiğinde bilgilendir.',
  'Alert rules': 'Uyarı kuralları',
  'Alert inbox': 'Uyarı gelen kutusu',
  Monitor: 'İzle',
  'Watched indicators': 'İzlenen göstergeler',
  'Rescan all': 'Tümünü yeniden tara',
  'Add an indicator to monitor…': 'İzlemek için bir gösterge ekle…',
  'Could not add.': 'Eklenemedi.',
  'Loading watchlist…': 'İzleme listesi yükleniyor…',
  'Last check': 'Son kontrol',
  State: 'Durum',
  Actions: 'İşlemler',
  Never: 'Hiç',
  Enabled: 'Etkin',
  Paused: 'Duraklatıldı',
  Disabled: 'Devre dışı',
  'Nothing watched yet': 'Henüz hiçbir şey izlenmiyor',
  'Add indicators to re-check them over time and trigger alerts.':
    'Göstergeleri zaman içinde yeniden kontrol etmek ve uyarı tetiklemek için ekle.',
  'Rescanned {value} → score {score} · {count} alerts fired':
    '{value} yeniden tarandı → puan {score} · {count} uyarı tetiklendi',
  'Rescanned {value} → score {score} · {count} alert fired':
    '{value} yeniden tarandı → puan {score} · {count} uyarı tetiklendi',
  'Detection logic': 'Tespit mantığı',
  'Rule name': 'Kural adı',
  'Score ≥ threshold': 'Puan ≥ eşik',
  'Malicious engines ≥ threshold': 'Zararlı motor sayısı ≥ eşik',
  'New detection since last scan': 'Son taramadan beri yeni tespit',
  'Level is critical': 'Seviye kritik',
  'Add rule': 'Kural ekle',
  'Could not save the rule.': 'Kural kaydedilemedi.',
  'Loading rules…': 'Kurallar yükleniyor…',
  'No rules configured': 'Kural yapılandırılmadı',
  'Add a rule to be alerted when watched indicators cross a threshold.':
    'İzlenen göstergeler eşiği aştığında uyarılmak için bir kural ekle.',
  'threshold {value}': 'eşik {value}',
  score_ge: 'Puan ≥ eşik',
  engines_ge: 'Zararlı motor sayısı ≥ eşik',
  new_detection: 'Son taramadan beri yeni tespit',
  level_is: 'Seviye kritik',
  Notifications: 'Bildirimler',
  'Loading alerts…': 'Uyarılar yükleniyor…',
  'No alerts yet': 'Henüz uyarı yok',
  'When a watched indicator trips a rule, the alert lands here.':
    'İzlenen bir gösterge bir kuralı tetiklediğinde uyarı buraya düşer.',

  // --- Reports -------------------------------------------------------------- //
  'Security Reports': 'Güvenlik Raporları',
  'Export professional, evidence-based PDF reports for any stored analysis.':
    'Saklanan her analiz için profesyonel, kanıta dayalı PDF raporları dışa aktar.',
  'Report library': 'Rapor kitaplığı',
  'Available analyses': 'Kullanılabilir analizler',
  'Nothing to report yet': 'Henüz raporlanacak bir şey yok',
  'Run an analysis first; every stored investigation can be exported as a PDF.':
    'Önce bir analiz çalıştır; saklanan her soruşturma PDF olarak dışa aktarılabilir.',
  'Compiling report…': 'Rapor derleniyor…',
  'Report could not be generated': 'Rapor oluşturulamadı',
  Preview: 'Önizleme',
  'Download PDF': 'PDF indir',
  'Select an analysis': 'Bir analiz seç',
  'Pick an investigation from the library to preview and export its report.':
    'Raporunu önizlemek ve dışa aktarmak için kitaplıktan bir soruşturma seç.',

  // --- Graph ---------------------------------------------------------------- //
  'IOC Relationship Graph': 'IOC İlişki Grafiği',
  'Providers, evidence and related indicators connected to the analyzed IOC.':
    'Analiz edilen IOC’ye bağlı sağlayıcılar, kanıtlar ve ilgili göstergeler.',
  'Building graph…': 'Grafik oluşturuluyor…',
  'Graph could not be loaded': 'Grafik yüklenemedi',
  'Not enough evidence yet': 'Henüz yeterli kanıt yok',
  'Run an analysis with multi-provider enrichment enabled to unlock the relationship graph.':
    'İlişki grafiğini açmak için çok sağlayıcılı zenginleştirme etkinken bir analiz çalıştır.',
  'Open analysis': 'Analizi aç',
  Graph: 'Grafik',
  'root indicator': 'kök gösterge',
  'provider source': 'sağlayıcı kaynağı',
  'evidence item': 'kanıt öğesi',
  'related IOC': 'ilgili IOC',
  'kind.root': 'Kök gösterge',
  'kind.source': 'Sağlayıcı kaynağı',
  'kind.evidence': 'Kanıt öğesi',
  'kind.indicator': 'İlgili IOC',

  // --- Analysis detail ------------------------------------------------------ //
  'Analysis Detail': 'Analiz Ayrıntısı',
  'Full intelligence portfolio for a single investigation.':
    'Tek bir soruşturma için tam istihbarat portföyü.',
  PDF: 'PDF',
  Pin: 'Sabitle',
  Pinned: 'Sabitlendi',
  'Exports': 'Dışa aktarımlar',
  'Take the intelligence with you': 'İstihbaratı yanında götür',
  json: 'JSON',
  'STIX 2.1': 'STIX 2.1',
  YARA: 'YARA',
  Sigma: 'Sigma',
  'STIX bundles, YARA and Sigma rules are generated from the stored evidence — ready for your SIEM or detection pipeline.':
    'STIX paketleri, YARA ve Sigma kuralları saklanan kanıtlardan üretilir — SIEM veya tespit hattın için hazır.',
  'Analyst workspace': 'Analist çalışma alanı',
  'Tags & notes': 'Etiketler ve notlar',
  'No tags yet.': 'Henüz etiket yok.',
  'Add tag…': 'Etiket ekle…',
  Notes: 'Notlar',
  'No analyst notes yet.': 'Henüz analist notu yok.',
  'Add a note for the team…': 'Ekip için bir not ekle…',
  'Add note': 'Not ekle',
  'Loading analysis…': 'Analiz yükleniyor…',
  'Analysis could not be loaded': 'Analiz yüklenemedi',
  'Back to history': 'Geçmişe dön',
  'Unlock the evidence-based narrative': 'Kanıta dayalı anlatının kilidini aç',
  'Generating…': 'Üretiliyor…',
  'Generate AI analysis': 'AI analizi oluştur',
  'The AI interpretation explains tactics, capabilities, recommendations and correlations — strictly derived from the evidence already collected. Nothing is sent besides the normalized report.':
    'AI yorumu; taktikleri, yetenekleri, önerileri ve ilişkileri açıklar — yalnızca hâlihazırda toplanan kanıtlardan türetilir. Normalize edilmiş rapordan başka hiçbir şey gönderilmez.',
  'AI generation failed:': 'AI üretimi başarısız:',
  'Interpreting evidence with the configured model…':
    'Kanıtlar yapılandırılmış modelle yorumlanıyor…',
  Regenerate: 'Yeniden üret',

  // --- Settings ------------------------------------------------------------- //
  'Service configuration and platform information.':
    'Servis yapılandırması ve platform bilgileri.',
  'Backend status': 'Arka uç durumu',
  Security: 'Güvenlik',
  'API keys': 'API anahtarları',
  'VirusTotal and OpenRouter keys are stored in the backend {file} file and are never exposed to the browser.':
    'VirusTotal ve OpenRouter anahtarları arka uçtaki {file} dosyasında saklanır ve tarayıcıya asla açılmaz.',
  'Rate limits are enforced server-side; upstream provider errors are surfaced as clean, user-friendly messages.':
    'Hız limitleri sunucu tarafında uygulanır; üst sağlayıcı hataları temiz, kullanıcı dostu mesajlar olarak gösterilir.',
  'All uploaded samples are hashed and sent as metadata only. Raw binaries are not forwarded to the AI layer.':
    'Yüklenen tüm örnekler hash’lenir ve yalnızca meta veri olarak gönderilir. Ham ikili dosyalar AI katmanına iletilmez.',

  // --- Digest section labels (backend) -------------------------------------- //
  Analyses: 'Analizler',
  Detections: 'Tespitler',
  'Critical findings': 'Kritik bulgular',
  'New indicators': 'Yeni göstergeler',
  Alerts: 'Uyarılar',
  'Active cases': 'Aktif vakalar',

  // --- Report block headings (backend) -------------------------------------- //
  'Executive summary': 'Yönetici özeti',
  'Detection breakdown': 'Tespit dökümü',
  'Multi-provider enrichment': 'Çok sağlayıcılı zenginleştirme',
  'Multi-provider enrichment & confidence':
    'Çok sağlayıcılı zenginleştirme ve güven',
  'AI assessment': 'AI değerlendirmesi',
  'Confidence': 'Güven',
  'Overall confidence': 'Genel güven',
  'Per-source confidence': 'Kaynak başına güven',
  'Signals': 'Sinyaller',
  'Sources': 'Kaynaklar',
  'Threat level': 'Tehdit seviyesi',
  'Analysis ID': 'Analiz Kimliği',
  'Generated at': 'Oluşturulma zamanı',
  'Analyzed at': 'Analiz zamanı',
  'Source': 'Kaynak',
  'Evidence': 'Kanıt',
  'Provider': 'Sağlayıcı',
  'Value': 'Değer',
  'Confidence score': 'Güven puanı',
  'Reason': 'Gerekçe',
}
