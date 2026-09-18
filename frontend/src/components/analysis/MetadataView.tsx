import type { IndicatorMetadata } from '../../types'
import { formatDate } from './level'
import { useI18n } from '../../i18n'
import type { I18nContextValue } from '../../i18n'

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

function commonRows(
  metadata: IndicatorMetadata,
  t: I18nContextValue['t'],
): Row[] {
  const rows: Row[] = []
  if (metadata.reputation != null)
    rows.push({ label: t('Reputation'), value: metadata.reputation })
  if (metadata.tags.length > 0)
    rows.push({ label: t('Tags'), value: metadata.tags.join(', ') })
  if (metadata.threat_names.length > 0)
    rows.push({
      label: t('Threat names'),
      value: (
        <span className="font-mono">{metadata.threat_names.join(', ')}</span>
      ),
    })
  if (Object.keys(metadata.total_votes).length > 0)
    rows.push({
      label: t('Community votes'),
      value: votesText(metadata.total_votes),
    })
  if (metadata.first_submission_date)
    rows.push({
      label: t('First submitted'),
      value: formatDate(metadata.first_submission_date),
    })
  if (metadata.last_analysis_date)
    rows.push({
      label: t('Last analyzed'),
      value: formatDate(metadata.last_analysis_date),
    })
  return rows
}

function buildRows(
  metadata: IndicatorMetadata,
  t: I18nContextValue['t'],
): Row[] {
  const rows: Row[] = []
  switch (metadata.kind) {
    case 'file': {
      if (metadata.meaningful_name)
        rows.push({ label: t('Name'), value: metadata.meaningful_name })
      if (metadata.names.length > 0)
        rows.push({ label: t('Observed names'), value: metadata.names.join(', ') })
      if (metadata.type_description)
        rows.push({ label: t('Type'), value: metadata.type_description })
      if (metadata.size != null)
        rows.push({ label: t('Size'), value: formatBytes(metadata.size) })
      rows.push({ label: 'SHA256', value: <span className="font-mono">{metadata.sha256 ?? '—'}</span> })
      rows.push({ label: 'SHA1', value: <span className="font-mono">{metadata.sha1 ?? '—'}</span> })
      rows.push({ label: 'MD5', value: <span className="font-mono">{metadata.md5 ?? '—'}</span> })
      break
    }
    case 'url': {
      rows.push({ label: 'URL', value: <span className="font-mono">{metadata.url ?? '—'}</span> })
      if (metadata.final_url)
        rows.push({ label: t('Final URL'), value: <span className="font-mono break-all">{metadata.final_url}</span> })
      if (metadata.title) rows.push({ label: t('Title'), value: metadata.title })
      break
    }
    case 'domain': {
      if (metadata.registrar)
        rows.push({ label: t('Registrar'), value: metadata.registrar })
      if (metadata.creation_date)
        rows.push({ label: t('Registered'), value: formatDate(metadata.creation_date) })
      break
    }
    case 'ip': {
      if (metadata.country)
        rows.push({ label: t('Country'), value: metadata.country })
      if (metadata.as_owner)
        rows.push({ label: t('AS owner'), value: metadata.as_owner })
      if (metadata.asn != null)
        rows.push({ label: t('ASN'), value: metadata.asn })
      break
    }
  }
  rows.push(...commonRows(metadata, t))
  return rows
}

interface MetadataViewProps {
  metadata: IndicatorMetadata
}

export function MetadataView({ metadata }: MetadataViewProps) {
  const { t } = useI18n()
  const rows = buildRows(metadata, t)
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