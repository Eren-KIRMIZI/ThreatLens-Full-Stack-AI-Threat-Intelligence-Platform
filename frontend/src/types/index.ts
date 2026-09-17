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