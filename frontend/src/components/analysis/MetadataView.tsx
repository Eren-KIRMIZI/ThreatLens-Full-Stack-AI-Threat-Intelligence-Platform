import type { IndicatorMetadata } from '../../types'
import { formatDate } from './level'

interface Row {
  label: string
  value: React.ReactNode
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function votesText(votes: Record<string, number>): string {
  const entries = Object.entries(votes)
  if (entries.length === 0) return '—'
  return entries.map(([k, v]) => `${k}: ${v}`).join(' · ')
}

function commonRows(metadata: IndicatorMetadata): Row[] {
  const rows: Row[] = []
  if (metadata.reputation != null)
    rows.push({ label: 'Reputation', value: metadata.reputation })
  if (metadata.tags.length > 0)
    rows.push({ label: 'Tags', value: metadata.tags.join(', ') })
  if (metadata.threat_names.length > 0)
    rows.push({
      label: 'Threat names',
      value: (
        <span className="font-mono">{metadata.threat_names.join(', ')}</span>
      ),
    })
  if (Object.keys(metadata.total_votes).length > 0)
    rows.push({ label: 'Community votes', value: votesText(metadata.total_votes) })
  if (metadata.first_submission_date)
    rows.push({
      label: 'First submitted',
      value: formatDate(metadata.first_submission_date),
    })
  if (metadata.last_analysis_date)
    rows.push({
      label: 'Last analyzed',
      value: formatDate(metadata.last_analysis_date),
    })
  return rows
}

function buildRows(metadata: IndicatorMetadata): Row[] {
  const rows: Row[] = []
  switch (metadata.kind) {
    case 'file': {
      if (metadata.meaningful_name)
        rows.push({ label: 'Name', value: metadata.meaningful_name })
      if (metadata.names.length > 0)
        rows.push({ label: 'Observed names', value: metadata.names.join(', ') })
      if (metadata.type_description)
        rows.push({ label: 'Type', value: metadata.type_description })
      if (metadata.size != null)
        rows.push({ label: 'Size', value: formatBytes(metadata.size) })
      rows.push({ label: 'SHA256', value: <span className="font-mono">{metadata.sha256 ?? '—'}</span> })
      rows.push({ label: 'SHA1', value: <span className="font-mono">{metadata.sha1 ?? '—'}</span> })
      rows.push({ label: 'MD5', value: <span className="font-mono">{metadata.md5 ?? '—'}</span> })
      break
    }
    case 'url': {
      rows.push({ label: 'URL', value: <span className="font-mono">{metadata.url ?? '—'}</span> })
      if (metadata.final_url)
        rows.push({ label: 'Final URL', value: <span className="font-mono break-all">{metadata.final_url}</span> })
      if (metadata.title) rows.push({ label: 'Title', value: metadata.title })
      break
    }
    case 'domain': {
      if (metadata.registrar) rows.push({ label: 'Registrar', value: metadata.registrar })
      if (metadata.creation_date)
        rows.push({ label: 'Registered', value: formatDate(metadata.creation_date) })
      break
    }
    case 'ip': {
      if (metadata.country) rows.push({ label: 'Country', value: metadata.country })
      if (metadata.as_owner) rows.push({ label: 'AS owner', value: metadata.as_owner })
      if (metadata.asn != null) rows.push({ label: 'ASN', value: metadata.asn })
      break
    }
  }
  rows.push(...commonRows(metadata))
  return rows
}

interface MetadataViewProps {
  metadata: IndicatorMetadata
}

export function MetadataView({ metadata }: MetadataViewProps) {
  const rows = buildRows(metadata)
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {rows.map((row) => (
        <div key={row.label} className="min-w-0">
          <dt className="eyebrow mb-0.5">{row.label}</dt>
          <dd className="truncate text-[13px] text-ink" title={String(row.value)}>
            {row.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}