import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  FileWarning,
  Image,
  Link2,
  Paperclip,
  ShieldCheck,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import { LEVEL_STYLE, formatDate, shortId } from '../analysis/level'
import { ThreatGauge } from '../analysis/ThreatGauge'
import { Button } from '../ui/Button'
import { Panel } from '../ui/Panel'
import { analyzeIndicator } from '../../services/api'
import { useI18n } from '../../i18n'
import { cn } from '../../utils/cn'
import type { EmailForensicOut, ForensicLink } from '../../types'

interface EmailForensicReportProps {
  report: EmailForensicOut
}

export function EmailForensicReport({ report }: EmailForensicReportProps) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [pending, setPending] = useState<string | null>(null)

  const analyzeUrl = useMutation({
    mutationFn: (url: string) => analyzeIndicator('URL', url, false),
    onMutate: (url: string) => setPending(url),
    onSettled: () => setPending(null),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['history'] })
      navigate(`/analysis/${result.analysis_id}`)
    },
  })

  const level = report.risk_level
  const style = LEVEL_STYLE[level] ?? LEVEL_STYLE.suspicious

  return (
    <div className="space-y-5">
      <Panel title={t('Forensic verdict')}>
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <ThreatGauge score={report.risk_score} level={report.risk_level} />

          <div className="min-w-0 flex-1 lg:max-w-xl">
            <h3 className="truncate text-[16px] font-semibold tracking-tight text-ink">
              {report.brief.subject ?? t('(no subject)')}
            </h3>
            <div className="mt-1.5 space-y-1 font-mono text-[12px] text-ink-2">
              <p>
                <span className="text-ink-3">From</span> {report.brief.sender_display ?? '—'}{' '}
                <span className={cn('rounded px-1.5 py-0.5', 'bg-surface-3 text-ink-2')}>
                  {report.brief.sender_email ?? report.brief.sender_domain ?? '—'}
                </span>
              </p>
              <p>
                <span className="text-ink-3">Reply-To</span> {report.brief.reply_to ?? t('none')}
              </p>
              <p>
                <span className="text-ink-3">Date</span>{' '}
                {formatDate(report.brief.date)}
              </p>
              {report.brief.message_id && (
                <p className="truncate">
                  <span className="text-ink-3">Message-ID</span> {report.brief.message_id}
                </p>
              )}
            </div>

            {report.rule_hits.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {report.rule_hits.map((rule) => (
                  <span
                    key={rule}
                    className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 font-mono text-[10.5px] text-critical"
                  >
                    {rule}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title={t('Key findings')} eyebrow={t('Summary')}>
          <ul className="space-y-2.5">
            {report.summary_points.map((point) => (
              <li key={point} className="flex items-start gap-2.5 text-[13px] leading-relaxed text-ink-2">
                <span
                  className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: style.ring }}
                />
                {point}
              </li>
            ))}
          </ul>
          {report.summary_points.length === 0 && (
            <p className="text-[13px] text-ink-3">—</p>
          )}
        </Panel>

        <Panel title={t('Header findings')} eyebrow={t('Weights')}>
          <div className="space-y-3">
            {report.header_findings.map((finding) => (
              <div key={`${finding.label}-${finding.detail}`} className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="flex items-center gap-2 text-[13px] font-medium text-ink">
                    {finding.risk > 0 ? (
                      <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-critical" />
                    ) : (
                      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-ok" />
                    )}
                    {finding.label}
                  </p>
                  <p className="mt-0.5 text-[12.5px] leading-snug text-ink-3">{finding.detail}</p>
                </div>
                <span
                  className={cn(
                    'shrink-0 rounded px-1.5 py-0.5 font-mono text-[11px]',
                    finding.risk > 0 ? 'bg-critical/10 text-critical' : 'bg-ok/10 text-ok',
                  )}
                >
                  {finding.risk > 0 ? `+${finding.risk}` : finding.risk}
                </span>
              </div>
            ))}
            {report.header_findings.length === 0 && (
              <p className="text-[13px] text-ink-3">{t('No header anomalies found.')}</p>
            )}
          </div>
        </Panel>
      </div>

      <Panel
        title={t('Extracted links')}
        eyebrow={t('Each URL is scored independently')}
        action={
          <span className="text-[12px] text-ink-3">
            {report.urls.length} {t('links')}
          </span>
        }
      >
        {report.urls.length === 0 ? (
          <p className="text-[13px] text-ink-3">{t('No URLs found in the message.')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-[13px]">
              <thead>
                <tr className="border-b border-border text-[11px] uppercase tracking-wider text-ink-3">
                  <th className="py-2 pr-4 font-medium">{t('Link')}</th>
                  <th className="py-2 pr-4 font-medium">{t('Domain')}</th>
                  <th className="py-2 pr-4 font-medium">{t('Brand')}</th>
                  <th className="py-2 pr-4 font-medium">{t('Flags')}</th>
                  <th className="py-2 pr-4 font-medium">{t('Risk')}</th>
                  <th className="py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {report.urls.map((link) => (
                  <UrlRow
                    key={link.url}
                    link={link}
                    pending={pending === link.url}
                    onAnalyze={() => analyzeUrl.mutate(link.url)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title={t('Tracking pixels')} eyebrow={t('Open counters')}>
          {report.tracking_pixels.length === 0 ? (
            <p className="text-[13px] text-ink-3">{t('No tracking pixels detected.')}</p>
          ) : (
            <ul className="space-y-2">
              {report.tracking_pixels.map((pixel, index) => (
                <li key={index} className="flex items-center gap-2.5 font-mono text-[12px] text-ink-2">
                  <Image className="h-3.5 w-3.5 shrink-0 text-ink-3" />
                  <span className="truncate">{pixel.url ?? t('inline pixel')}</span>
                  <span className="ml-auto shrink-0 rounded bg-surface-3 px-1.5 py-0.5 text-[10.5px] text-ink-3">
                    {pixel.width}×{pixel.height}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title={t('Attachments')} eyebrow={t('Bytes are never stored')}>
          {report.attachments.length === 0 ? (
            <p className="text-[13px] text-ink-3">{t('No attachments.')}</p>
          ) : (
            <ul className="space-y-2.5">
              {report.attachments.map((attachment, index) => (
                <li key={attachment.sha256 ?? `${index}-${attachment.filename}`} className="flex items-center gap-2.5">
                  <Paperclip className="h-3.5 w-3.5 shrink-0 text-ink-3" />
                  <div className="min-w-0 flex-1">
                    <p className="flex items-center gap-2 truncate font-mono text-[12.5px] text-ink">
                      {attachment.filename ?? attachment.content_type ?? '—'}
                      {attachment.risky_extension && (
                        <span className="inline-flex items-center gap-1 rounded bg-critical/10 px-1.5 py-0.5 text-[10.5px] text-critical">
                          <FileWarning className="h-3 w-3" />
                          {t('risky')}
                        </span>
                      )}
                    </p>
                    <p className="truncate font-mono text-[11px] text-ink-3">
                      {attachment.content_type ?? ''} · {attachment.size_bytes ?? 0} B ·{' '}
                      {attachment.sha256 ? shortId(attachment.sha256) : '—'}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title={t('Recommended actions')} eyebrow={t('Mitigations')}>
        <div className="space-y-2">
          {report.mitigations.map((item) => (
            <div key={item} className="flex items-start gap-2.5 text-[13px] leading-relaxed text-ink-2">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ok" />
              {item}
            </div>
          ))}
        </div>
      </Panel>

      {(report.html_source || report.text_body) && (
        <Panel title={t('Message source')} eyebrow={t('Immutable excerpt')}>
          <div className="space-y-3">
            {report.text_body && (
              <details className="group rounded-lg border border-border bg-surface-2">
                <summary className="cursor-pointer select-none px-3 py-2 text-[12.5px] font-medium text-ink-2">
                  {t('Plain text body')}
                </summary>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap border-t border-border px-3 py-2.5 font-mono text-[12px] leading-relaxed text-ink-2">
                  {report.text_body}
                </pre>
              </details>
            )}
            {report.html_source && (
              <details className="group rounded-lg border border-border bg-surface-2">
                <summary className="cursor-pointer select-none px-3 py-2 text-[12.5px] font-medium text-ink-2">
                  {t('HTML source')}
                </summary>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap border-t border-border px-3 py-2.5 font-mono text-[12px] leading-relaxed text-ink-2">
                  {report.html_source}
                </pre>
              </details>
            )}
          </div>
        </Panel>
      )}
    </div>
  )
}

interface UrlRowProps {
  link: ForensicLink
  pending: boolean
  onAnalyze: () => void
}

function UrlRow({ link, pending, onAnalyze }: UrlRowProps) {
  const { t } = useI18n()
  const flags: string[] = []
  if (!link.https) flags.push('http')
  if (link.ip_host) flags.push('raw-ip')
  if (link.shortener) flags.push('shortener')
  if (link.suspicious_tld) flags.push('tld')

  return (
    <tr className="border-b border-border/50 last:border-0">
      <td className="max-w-[240px] py-2.5 pr-4">
        <p className="truncate font-mono text-[12px] text-ink">{link.url}</p>
      </td>
      <td className="py-2.5 pr-4 font-mono text-[12px] text-ink-2">{link.domain}</td>
      <td className="py-2.5 pr-4">
        {link.brand ? (
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px]',
              link.brand_risk ? 'bg-critical/10 text-critical' : 'bg-ok/10 text-ok',
            )}
          >
            <ShieldAlert className="h-3 w-3" />
            {link.brand}
          </span>
        ) : (
          <span className="text-[12px] text-ink-3">—</span>
        )}
      </td>
      <td className="py-2.5 pr-4">
        <div className="flex flex-wrap gap-1">
          {flags.map((flag) => (
            <span key={flag} className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[10.5px] text-ink-3">
              {flag}
            </span>
          ))}
          {flags.length === 0 && <span className="text-[12px] text-ink-3">—</span>}
        </div>
      </td>
      <td className="py-2.5 pr-4">
        <span className="font-mono text-[12px] text-ink-2">{link.risk}</span>
      </td>
      <td className="py-2.5 text-right">
        <Button
          variant="secondary"
          size="sm"
          disabled={pending}
          onClick={onAnalyze}
        >
          <Link2 className="h-3.5 w-3.5" />
          {pending ? t('Analyzing…') : t('Analyze')}
        </Button>
      </td>
    </tr>
  )
}