import type {
  AIAnalysis,
  AlertRule,
  AlertsPage,
  AnalysisResult,
  Campaign,
  CampaignEvidence,
  Digest,
  HealthStatus,
  HistoryPage,
  HistoryParams,
  IOCDetail,
  IOCGraph,
  IOCPage,
  IOCParams,
  IndicatorType,
  Investigation,
  InvestigationNote,
  InvestigationPage,
  MitreAnalysisMapping,
  MitreCatalog,
  Note,
  ProviderHealthReport,
  ReportDocument,
  RescanOutcome,
  RescanReport,
  SearchResponse,
  WatchlistItem,
  WatchlistPage,
} from '../types'

export interface ApiErrorInfo {
  code: string
  message: string
  details?: unknown
}

export interface ApiErrorPayload {
  error: ApiErrorInfo
}

export class ApiRequestError extends Error {
  readonly code: string
  readonly status: number
  readonly details?: unknown

  constructor(status: number, info: ApiErrorInfo) {
    super(info.message)
    this.name = 'ApiRequestError'
    this.code = info.code
    this.status = status
    this.details = info.details
  }
}

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1'

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiUrl(path), init)
  if (!res.ok) {
    let info: ApiErrorInfo | null = null
    try {
      const payload = (await res.json()) as ApiErrorPayload
      if (payload?.error) info = payload.error
    } catch {
      // Non-JSON error body; fall through to generic error.
    }
    throw new ApiRequestError(
      res.status,
      info ?? { code: 'http_error', message: `Request failed (${res.status})` },
    )
  }
  return (await res.json()) as T
}

async function requestVoid(path: string, init?: RequestInit): Promise<void> {
  const res = await fetch(apiUrl(path), init)
  if (!res.ok) {
    let info: ApiErrorInfo | null = null
    try {
      const payload = (await res.json()) as ApiErrorPayload
      if (payload?.error) info = payload.error
    } catch {
      // Non-JSON error body.
    }
    throw new ApiRequestError(
      res.status,
      info ?? { code: 'http_error', message: `Request failed (${res.status})` },
    )
  }
}

function withQuery(path: string, params: object): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    query.set(key, String(value))
  }
  const suffix = query.toString()
  return suffix ? `${path}?${suffix}` : path
}

function analyzeBody(mode: Exclude<IndicatorType, 'FILE'>, value: string, ai: boolean) {
  const field = mode === 'HASH' ? 'hash' : mode.toLowerCase()
  return JSON.stringify({ [field]: value, ai })
}

const JSON_HEADERS: HeadersInit = { 'Content-Type': 'application/json' }

export async function fetchHealth(): Promise<HealthStatus> {
  return request<HealthStatus>('/health')
}

/** Analyze a text indicator (hash, URL, domain, IP). */
export async function analyzeIndicator(
  mode: Exclude<IndicatorType, 'FILE'>,
  value: string,
  ai: boolean,
): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/analyze/${mode.toLowerCase()}`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: analyzeBody(mode, value, ai),
  })
}

/** Analyze an uploaded file (multipart). */
export async function analyzeFile(file: File, ai: boolean): Promise<AnalysisResult> {
  const form = new FormData()
  form.append('file', file)
  form.append('ai', String(ai))
  return request<AnalysisResult>('/analyze/file', { method: 'POST', body: form })
}

export async function fetchAnalysis(analysisId: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/analysis/${analysisId}`)
}

/** Run / refresh the AI interpretation of a stored analysis. */
export async function enrichWithAi(analysisId: string): Promise<AIAnalysis> {
  return request<AIAnalysis>(`/analysis/${analysisId}/ai`, { method: 'POST' })
}

export async function fetchHistory(
  params: HistoryParams,
): Promise<HistoryPage> {
  const query = new URLSearchParams()
  if (params.filter && params.filter !== 'all') query.set('filter', params.filter)
  if (params.search) query.set('search', params.search)
  if (params.limit != null) query.set('limit', String(params.limit))
  if (params.offset != null) query.set('offset', String(params.offset))

  const suffix = query.toString() ? `?${query.toString()}` : ''
  return request<HistoryPage>(`/history${suffix}`)
}

/** Fetch the structured report document of a stored analysis. */
export async function fetchReport(analysisId: string): Promise<ReportDocument> {
  return request<ReportDocument>(`/reports/${analysisId}`)
}

/** Fetch the IOC relationship graph of a stored analysis. */
export async function fetchGraph(analysisId: string): Promise<IOCGraph> {
  return request<IOCGraph>(`/analysis/${analysisId}/graph`)
}

/** Absolute URL of the downloadable PDF report (same-origin or API base). */
export function reportPdfUrl(analysisId: string): string {
  return apiUrl(`/reports/${analysisId}/pdf`)
}

// --- IOC registry ------------------------------------------------------------- //

export async function fetchIOCs(params: IOCParams): Promise<IOCPage> {
  return request<IOCPage>(withQuery('/iocs', params))
}

export async function fetchIOC(value: string): Promise<IOCDetail> {
  return request<IOCDetail>(`/iocs/${encodeURIComponent(value)}`)
}

export async function fetchProviderHealth(
  sinceHours = 24,
): Promise<ProviderHealthReport> {
  return request<ProviderHealthReport>(
    withQuery('/iocs/health/providers', { since_hours: sinceHours }),
  )
}

// --- Digest & global search --------------------------------------------------- //

export async function fetchDigest(window = 'week'): Promise<Digest> {
  return request<Digest>(withQuery('/intel/digest', { window }))
}

export async function globalSearch(query: string): Promise<SearchResponse> {
  return request<SearchResponse>(withQuery('/intel/search', { q: query }))
}

// --- MITRE ATT&CK ------------------------------------------------------------ //

export async function fetchMitreCatalog(): Promise<MitreCatalog> {
  return request<MitreCatalog>('/intel/mitre/catalog')
}

export async function fetchMitreAnalysis(
  analysisId: string,
): Promise<MitreAnalysisMapping> {
  return request<MitreAnalysisMapping>(`/intel/mitre/analysis/${analysisId}`)
}

// --- Investigations ----------------------------------------------------------- //

export interface InvestigationInput {
  title: string
  description?: string | null
  status?: string
  severity?: string
}

export async function fetchInvestigations(params?: {
  limit?: number
  offset?: number
  status?: string
}): Promise<InvestigationPage> {
  return request<InvestigationPage>(withQuery('/investigations', params ?? {}))
}

export async function createInvestigation(
  body: InvestigationInput,
): Promise<Investigation> {
  return request<Investigation>('/investigations', {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function fetchInvestigation(id: string): Promise<Investigation> {
  return request<Investigation>(`/investigations/${id}`)
}

export async function updateInvestigation(
  id: string,
  body: Partial<InvestigationInput>,
): Promise<Investigation> {
  return request<Investigation>(`/investigations/${id}`, {
    method: 'PATCH',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function deleteInvestigation(id: string): Promise<void> {
  return requestVoid(`/investigations/${id}`, { method: 'DELETE' })
}

export async function addInvestigationItem(
  id: string,
  body: { value: string; primary_type?: string; analysis_id?: string },
): Promise<{ id: string; value: string; primary_type: string }> {
  return request(
    withQuery(`/investigations/${id}/items`, {
      value: body.value,
      primary_type: body.primary_type,
      analysis_id: body.analysis_id,
    }),
    { method: 'POST' },
  )
}

export async function fetchNotes(analysisId: string): Promise<Note[]> {
  return request<Note[]>(`/investigations/analysis/${analysisId}/notes`)
}

export async function addNote(
  analysisId: string,
  body: { author: string; body: string },
): Promise<Note> {
  return request<Note>(`/investigations/analysis/${analysisId}/notes`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function fetchTags(analysisId: string): Promise<string[]> {
  return request<string[]>(`/investigations/analysis/${analysisId}/tags`)
}

export async function addTag(
  analysisId: string,
  tag: string,
): Promise<{ tag: string }> {
  return request(`/investigations/analysis/${analysisId}/tags`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ tag }),
  })
}

export async function setPinned(
  analysisId: string,
  pinned: boolean,
): Promise<{ analysis_id: string; pinned: boolean }> {
  return request(
    withQuery(`/investigations/analysis/${analysisId}/pin`, { pinned }),
    { method: 'POST' },
  )
}

export async function fetchPinned(): Promise<string[]> {
  return request<string[]>('/investigations/pinned/list')
}

// --- Investigation workspace (notes / campaigns / evidence) ------------------ //

export async function fetchInvestigationNotes(
  investigationId: string,
): Promise<InvestigationNote[]> {
  return request<InvestigationNote[]>(
    `/investigations/${investigationId}/case-notes`,
  )
}

export async function addInvestigationNote(
  investigationId: string,
  body: { author: string; body: string },
): Promise<InvestigationNote> {
  return request<InvestigationNote>(
    `/investigations/${investigationId}/case-notes`,
    {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    },
  )
}

export async function deleteInvestigationNote(noteId: string): Promise<void> {
  return requestVoid(`/investigations/notes/${noteId}`, { method: 'DELETE' })
}

export async function fetchCampaigns(
  investigationId: string,
): Promise<Campaign[]> {
  return request<Campaign[]>(`/investigations/${investigationId}/campaigns`)
}

export async function createCampaign(
  investigationId: string,
  body: { name: string; color: string },
): Promise<Campaign> {
  return request<Campaign>(`/investigations/${investigationId}/campaigns`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function updateCampaign(
  campaignId: string,
  body: { name?: string; color?: string },
): Promise<Campaign> {
  return request<Campaign>(`/investigations/campaigns/${campaignId}`, {
    method: 'PATCH',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function deleteCampaign(campaignId: string): Promise<void> {
  return requestVoid(`/investigations/campaigns/${campaignId}`, {
    method: 'DELETE',
  })
}

export async function addCampaignEvidence(
  campaignId: string,
  body: {
    analysis_id?: string | null
    value: string
    primary_type: string
    note?: string | null
  },
): Promise<CampaignEvidence> {
  return request<CampaignEvidence>(
    `/investigations/campaigns/${campaignId}/evidence`,
    {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    },
  )
}

export async function updateCampaignEvidence(
  campaignId: string,
  evidenceId: string,
  body: { note?: string | null },
): Promise<CampaignEvidence> {
  return request<CampaignEvidence>(
    `/investigations/campaigns/${campaignId}/evidence/${evidenceId}`,
    {
      method: 'PATCH',
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    },
  )
}

export async function deleteCampaignEvidence(
  campaignId: string,
  evidenceId: string,
): Promise<void> {
  return requestVoid(
    `/investigations/campaigns/${campaignId}/evidence/${evidenceId}`,
    { method: 'DELETE' },
  )
}

// --- Watchlist & alerts ------------------------------------------------------- //

export async function fetchWatchlist(params?: {
  enabled_only?: boolean
  limit?: number
  offset?: number
}): Promise<WatchlistPage> {
  return request<WatchlistPage>(withQuery('/watchlist', params ?? {}))
}

export async function addWatchlistItem(body: {
  value: string
  primary_type: string
  enabled?: boolean
}): Promise<WatchlistItem> {
  return request<WatchlistItem>('/watchlist', {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function removeWatchlistItem(id: string): Promise<void> {
  return requestVoid(`/watchlist/${id}`, { method: 'DELETE' })
}

export async function setWatchlistEnabled(
  id: string,
  enabled: boolean,
): Promise<WatchlistItem> {
  return request<WatchlistItem>(
    withQuery(`/watchlist/${id}`, { enabled }),
    { method: 'PATCH' },
  )
}

export async function fetchRules(): Promise<AlertRule[]> {
  return request<AlertRule[]>('/watchlist/rules')
}

export async function upsertRule(body: {
  id?: string
  name: string
  condition: string
  threshold: number
  enabled?: boolean
}): Promise<AlertRule> {
  return request<AlertRule>('/watchlist/rules', {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })
}

export async function deleteRule(id: string): Promise<void> {
  return requestVoid(`/watchlist/rules/${id}`, { method: 'DELETE' })
}

export async function fetchAlerts(params?: {
  unseen_only?: boolean
  limit?: number
  offset?: number
}): Promise<AlertsPage> {
  return request<AlertsPage>(withQuery('/watchlist/alerts', params ?? {}))
}

export async function markAlertsSeen(): Promise<void> {
  await request('/watchlist/alerts/mark-seen', { method: 'POST' })
}

export async function rescanAll(): Promise<RescanReport> {
  return request<RescanReport>('/watchlist/rescan/all', { method: 'POST' })
}

export async function rescanOne(id: string): Promise<RescanOutcome> {
  return request<RescanOutcome>(`/watchlist/${id}/rescan`, { method: 'POST' })
}

// --- Exports ------------------------------------------------------------------ //

function download(path: string): string {
  return apiUrl(path)
}

export function historyCsvUrl(filter = 'all'): string {
  return download(withQuery('/export/history.csv', { filter }))
}

export function analysisJsonUrl(analysisId: string): string {
  return download(`/export/analyses/${analysisId}.json`)
}

export function stixUrl(analysisId: string): string {
  return download(`/export/analyses/${analysisId}/stix.json`)
}

export function yaraUrl(analysisId: string): string {
  return download(`/export/analyses/${analysisId}/yara`)
}

export function sigmaUrl(analysisId: string): string {
  return download(`/export/analyses/${analysisId}/sigma`)
}