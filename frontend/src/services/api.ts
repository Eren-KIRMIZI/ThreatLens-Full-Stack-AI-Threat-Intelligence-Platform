import type {
  AIAnalysis,
  AnalysisResult,
  HealthStatus,
  HistoryPage,
  HistoryParams,
  IOCGraph,
  IndicatorType,
  ReportDocument,
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