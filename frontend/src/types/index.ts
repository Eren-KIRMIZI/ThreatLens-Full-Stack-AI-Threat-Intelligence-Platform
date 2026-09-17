export type ThreatLevel = 'clean' | 'suspicious' | 'malicious' | 'critical'

export type IndicatorType = 'HASH' | 'URL' | 'DOMAIN' | 'IP' | 'FILE'

export type HistoryFilter = 'all' | 'malicious' | 'suspicious' | 'clean'

export interface HealthStatus {
  status: string
  service: string
  version: string
  environment: string
  timestamp: string
  uptime_seconds: number
  checks: Record<string, string>
}

export interface DetectionStats {
  malicious: number
  suspicious: number
  undetected: number
  harmless: number
  timeout: number
}

export interface DetectionEntry {
  engine: string
  result: string | null
  category: string
  method: string | null
}

interface BaseMetadata {
  kind: MetadataKind
  reputation: number | null
  tags: string[]
  threat_names: string[]
  total_votes: Record<string, number>
  first_submission_date: string | null
  last_analysis_date: string | null
}

export type MetadataKind = 'file' | 'url' | 'domain' | 'ip'

export interface FileMetadata extends BaseMetadata {
  kind: 'file'
  sha256: string | null
  sha1: string | null
  md5: string | null
  names: string[]
  meaningful_name: string | null
  type_description: string | null
  size: number | null
}

export interface UrlMetadata extends BaseMetadata {
  kind: 'url'
  url: string | null
  final_url: string | null
  title: string | null
}

export interface DomainMetadata extends BaseMetadata {
  kind: 'domain'
  registrar: string | null
  creation_date: string | null
}

export interface IpMetadata extends BaseMetadata {
  kind: 'ip'
  country: string | null
  as_owner: string | null
  asn: number | null
}

export type IndicatorMetadata =
  | FileMetadata
  | UrlMetadata
  | DomainMetadata
  | IpMetadata

export type Confidence = 'low' | 'medium' | 'high'

export interface AITactic {
  phase: string
  technique_id: string | null
  technique_name: string | null
  notes: string | null
}

export interface AIThreatActor {
  name: string | null
  campaign: string | null
  description: string | null
  confidence: Confidence | null
}

export interface AICapability {
  capability: string
  description: string
}

export interface AIAnalysis {
  summary: string
  tactics: AITactic[]
  threat_actor_profile: AIThreatActor | null
  capabilities: AICapability[]
  recommendations: string[]
  lifecycle_stage: string | null
  correlations: string[]
  threat_level_assessment: ThreatLevel | null
  evidence_refs: string[]
  model: string | null
  created_at: string
}

export interface AnalysisResult {
  analysis_id: string
  indicator: string
  indicator_type: IndicatorType
  source: 'virustotal'
  submitted_at: string
  analyzed_at: string
  stats: DetectionStats
  detections: DetectionEntry[]
  metadata: IndicatorMetadata
  threat_score: number | null
  threat_level: ThreatLevel | null
  ai: AIAnalysis | null
  enrichment: Enrichment | null
}

export interface HistoryItem {
  analysis_id: string
  indicator: string
  indicator_type: IndicatorType
  meaningful_name: string | null
  stats: DetectionStats
  detected_vendors: number
  threat_score: number | null
  threat_level: ThreatLevel | null
  analyzed_at: string
  created_at: string
}

export interface HistoryPage {
  items: HistoryItem[]
  total: number
  limit: number
  offset: number
  filter: HistoryFilter
}

export interface HistoryParams {
  filter?: HistoryFilter
  search?: string
  limit?: number
  offset?: number
}

export interface ReportRow {
  label: string
  value: string
}

export interface ReportTableSection {
  columns: string[]
  rows: string[][]
}

export interface ReportBlock {
  kind: 'paragraph' | 'facts' | 'table'
  heading: string
  text?: string | null
  facts?: ReportRow[]
  table?: ReportTableSection | null
}

export interface ReportDocument {
  title: string
  subtitle: string
  generated_at: string
  indicator: string
  indicator_type: IndicatorType
  threat_score: number | null
  threat_level: ThreatLevel | null
  blocks: ReportBlock[]
}

export type GraphNodeKind = 'root' | 'source' | 'evidence' | 'indicator'

export interface GraphNode {
  id: string
  kind: GraphNodeKind
  label: string
  indicator_type: IndicatorType | null
  subtitle: string | null
  verdict: string | null
  score: number | null
  url: string | null
  meta: Record<string, unknown>
}

export interface GraphEdge {
  source: string
  target: string
  relation: string
}

export interface IOCGraph {
  root: string
  nodes: GraphNode[]
  edges: GraphEdge[]
  generated_at: string
}

export interface EnrichmentSourceConfidence {
  source: string
  score: number
  verdict: string
  signals: string[]
}

export interface EnrichmentConfidence {
  overall: number
  verdict: string
  sources: EnrichmentSourceConfidence[]
  reasons: string[]
}

export interface EnrichmentEvidence {
  id: string
  provider: string
  evidence_type: string
  title: string
  value: string
  confidence: number
  verdict: string | null
  first_seen: string | null
  last_seen: string | null
  source_ref: string | null
}

export interface ProviderStatus {
  provider: string
  ok: boolean
  latency_ms: number | null
  supported: boolean
  configured: boolean
  error: string | null
}

export interface Enrichment {
  version: string
  sources: string[]
  generated_at: string
  evidence: EnrichmentEvidence[]
  confidence: EnrichmentConfidence | null
  provider_status: ProviderStatus[]
}

// --- IOC registry & timeline -------------------------------------------------- //

export interface IOCItem {
  id: string
  value: string
  primary_type: string
  observations: number
  latest_score: number | null
  latest_level: string | null
  first_seen_at: string | null
  last_seen_at: string | null
}

export interface IOCPage {
  items: IOCItem[]
  total: number
  limit: number
  offset: number
}

export interface SnapshotPoint {
  analysis_id: string
  threat_score: number | null
  threat_level: string | null
  malicious: number
  suspicious: number
  analyzed_at: string | null
}

export interface IOCDetail {
  indicator: IOCItem
  observations: number
  timeline: SnapshotPoint[]
  analyses: AnalysisResult[]
}

export interface IOCParams {
  search?: string
  primary_type?: string
  limit?: number
  offset?: number
}

export interface ProviderHealthRow {
  provider: string
  ok: boolean
  latency_ms: number | null
  indicator_type: string | null
  error: string | null
  checked_at: string | null
  checks: number | null
  availability: number | null
}

export interface ProviderHealthReport {
  since_hours: number
  rows: ProviderHealthRow[]
}

// --- Investigations ----------------------------------------------------------- //

export type InvestigationStatus = 'open' | 'active' | 'closed'
export type InvestigationSeverity = 'low' | 'medium' | 'high' | 'critical'

export interface InvestigationItem {
  id: string
  value: string
  primary_type: string
  analysis_id: string | null
  added_at: string | null
}

export interface Investigation {
  id: string
  title: string
  description: string | null
  status: InvestigationStatus
  severity: InvestigationSeverity
  created_at: string | null
  updated_at: string | null
  items: InvestigationItem[]
}

export interface InvestigationPage {
  items: Investigation[]
  total: number
  limit: number
  offset: number
}

export interface Note {
  id: string
  analysis_id: string
  author: string
  body: string
  created_at: string | null
}

// --- Watchlist & alerts ------------------------------------------------------- //

export interface WatchlistItem {
  id: string
  value: string
  primary_type: string
  enabled: boolean
  last_checked_at: string | null
  created_at: string | null
}

export interface WatchlistPage {
  items: WatchlistItem[]
  total: number
  limit: number
  offset: number
  enabled_only: boolean
}

export interface AlertRule {
  id: string
  name: string
  condition: string
  threshold: number
  enabled: boolean
}

export interface Alert {
  id: string
  watchlist_id: string
  rule_id: string | null
  analysis_id: string | null
  indicator: string
  level: string
  message: string
  seen: boolean
  triggered_at: string | null
}

export interface AlertsPage {
  items: Alert[]
  total: number
  limit: number
  offset: number
  unseen_only: boolean
}

export interface RescanOutcome {
  watchlist_id: string
  value: string
  primary_type: string
  analysis_id: string | null
  threat_score: number | null
  threat_level: string | null
  alerts: Alert[]
  error: string | null
}

export interface RescanReport {
  checked: number
  outcomes: RescanOutcome[]
}

// --- Digest & search ---------------------------------------------------------- //

export interface SearchResult {
  kind: string
  id: string
  title: string
  subtitle: string
  score: number | null
  level: string | null
  analyzed_at: string | null
}

export interface SearchResponse {
  query: string
  total: number
  results: SearchResult[]
}

export interface DigestSection {
  label: string
  value: string
}

export interface Digest {
  period: string
  generated_at: string
  sections: DigestSection[]
}