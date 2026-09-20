import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowUpRight, Plus } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import { SegmentedControl } from '../ui/SegmentedControl'
import { Button } from '../ui/Button'
import { Spinner } from '../ui/Spinner'
import { addInvestigationItem, createInvestigation } from '../../services/api'
import { useI18n } from '../../i18n'
import { cn } from '../../utils/cn'
import type { EmailForensicOut } from '../../types'
import type { InvestigationSeverity } from '../../types'

interface EscalateToCaseProps {
  report: EmailForensicOut
}

interface CandidateItem {
  key: string
  value: string
  primaryType: string
  source: string
  risk: number
  suggested: boolean
}

const DEFAULT_SEVERITY: Record<
  EmailForensicOut['risk_level'],
  InvestigationSeverity
> = {
  clean: 'low',
  suspicious: 'medium',
  malicious: 'high',
  critical: 'critical',
}

const SEVERITY_OPTIONS = (
  ['low', 'medium', 'high', 'critical'] as InvestigationSeverity[]
).map((value) => ({ value, label: value }))

function buildCandidates(report: EmailForensicOut): CandidateItem[] {
  const items: CandidateItem[] = []
  const seen = new Set<string>()

  const push = (candidate: Omit<CandidateItem, 'key'>) => {
    const key = `${candidate.primaryType}:${candidate.value}`
    if (seen.has(key)) return
    seen.add(key)
    items.push({ ...candidate, key })
  }

  for (const link of report.urls) {
    push({
      value: link.url,
      primaryType: 'URL',
      source: 'url',
      risk: link.risk,
      suggested: link.risk >= 20,
    })
    if (link.domain) {
      push({
        value: link.domain,
        primaryType: 'DOMAIN',
        source: 'domain',
        risk: link.brand_risk ? 40 : 10,
        suggested: link.brand_risk,
      })
    }
  }

  const senderDomain = report.brief.sender_domain
  if (senderDomain) {
    const impersonated = report.header_findings.some(
      (finding) => finding.risk > 0 && /impersonat/i.test(finding.label),
    )
    push({
      value: senderDomain,
      primaryType: 'DOMAIN',
      source: 'sender',
      risk: impersonated ? 40 : 10,
      suggested: true,
    })
  }

  for (const attachment of report.attachments) {
    if (!attachment.sha256) continue
    push({
      value: attachment.sha256,
      primaryType: 'HASH',
      source: 'attachment',
      risk: attachment.risky_extension ? 40 : 10,
      suggested: attachment.risky_extension,
    })
  }

  return items
}

export function EscalateToCase({ report }: EscalateToCaseProps) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)

  const candidates = useMemo(() => buildCandidates(report), [report])
  const defaultTitle = useMemo(() => {
    const subject = report.brief.subject ?? 'unsolicited email'
    const title = `Phishing: ${subject}`
    return title.length > 60 ? `${title.slice(0, 57)}…` : title
  }, [report.brief.subject])

  const [title, setTitle] = useState(defaultTitle)
  const [severity, setSeverity] = useState<InvestigationSeverity>(
    DEFAULT_SEVERITY[report.risk_level],
  )
  const [selected, setSelected] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(candidates.map((candidate) => [candidate.key, candidate.suggested])),
  )

  const description = useMemo(() => {
    const urlCount = report.urls.length
    const domainCount = new Set(
      report.urls.map((link) => link.domain).filter(Boolean),
    ).size
    const hashCount = report.attachments.filter((att) => att.sha256).length
    const lines = [
      `Risk score ${report.risk_score}/100 (${report.risk_level}).`,
      `Sender: ${report.brief.sender_display ?? '—'} <${report.brief.sender_email ?? report.brief.sender_domain ?? '—'}>.`,
      `Extracted: ${urlCount} URL(s), ${domainCount} domain(s), ${hashCount} attachment hash(es).`,
    ]
    if (report.rule_hits.length > 0) {
      lines.push(`Rule hits: ${report.rule_hits.join(', ')}.`)
    }
    return lines.join('\n')
  }, [report])

  useEffect(() => {
    if (!open) return
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [open])

  const mutation = useMutation({
    mutationFn: async (): Promise<string> => {
      const investigation = await createInvestigation({
        title: title.trim() || defaultTitle,
        description,
        status: 'open',
        severity,
      })
      const picks = candidates.filter((candidate) => selected[candidate.key])
      await Promise.all(
        picks.map((candidate) =>
          addInvestigationItem(investigation.id, {
            value: candidate.value,
            primary_type: candidate.primaryType,
          }),
        ),
      )
      return investigation.id
    },
    onSuccess: (id) => {
      qc.invalidateQueries({ queryKey: ['investigations'] })
      setOpen(false)
      navigate(`/investigations/${id}/workspace`)
    },
  })

  const toggle = (key: string) =>
    setSelected((prev) => ({ ...prev, [key]: !prev[key] }))

  const pickedCount = candidates.filter(
    (candidate) => selected[candidate.key],
  ).length

  return (
    <>
      <Button variant="secondary" size="sm" onClick={() => setOpen(true)}>
        <Plus className="h-3.5 w-3.5" />
        {t('Escalate to case')}
      </Button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-bg/70 p-4 backdrop-blur-sm"
          onClick={() => {
            if (!mutation.isPending) setOpen(false)
          }}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-label={t('Escalate to case')}
            className="panel max-h-[85vh] w-full max-w-2xl overflow-y-auto p-0"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="flex items-center justify-between gap-3 border-b border-border/70 px-5 py-4">
              <div>
                <p className="eyebrow mb-1">{t('Open a case from this verdict')}</p>
                <h3 className="text-[16px] font-semibold tracking-tight text-ink">
                  {t('Escalate to investigation')}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                disabled={mutation.isPending}
                className="focus-ring rounded-lg px-2.5 py-1.5 text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink"
                aria-label={t('Close')}
              >
                ✕
              </button>
            </header>

            <div className="space-y-5 px-5 py-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">
                  <span className="eyebrow mb-1.5 block">{t('Case title')}</span>
                  <input
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    className="focus-ring w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-[13.5px] text-ink placeholder:text-ink-3"
                  />
                </label>
                <div>
                  <span className="eyebrow mb-1.5 block">{t('Severity')}</span>
                  <SegmentedControl
                    options={SEVERITY_OPTIONS}
                    value={severity}
                    onChange={setSeverity}
                  />
                </div>
              </div>

              <div>
                <span className="eyebrow mb-1.5 block">{t('Description')}</span>
                <textarea
                  value={description}
                  readOnly
                  rows={4}
                  className="w-full resize-none rounded-lg border border-border bg-surface-2 px-3 py-2 font-mono text-[12.5px] leading-relaxed text-ink-2"
                />
              </div>

              <div>
                <div className="mb-2 flex items-center justify-between">
                  <span className="eyebrow">{t('Evidence to carry over')}</span>
                  <span className="text-[12px] text-ink-3">
                    {pickedCount} / {candidates.length} {t('selected')}
                  </span>
                </div>
                {candidates.length === 0 ? (
                  <p className="text-[13px] text-ink-3">
                    {t('No indicators were extracted from this message.')}
                  </p>
                ) : (
                  <ul className="divide-y divide-border/60 overflow-hidden rounded-lg border border-border bg-surface-2">
                    {candidates.map((candidate) => (
                      <li key={candidate.key}>
                        <label className="flex cursor-pointer items-center gap-3 px-3 py-2.5 transition-colors hover:bg-surface-3">
                          <input
                            type="checkbox"
                            checked={Boolean(selected[candidate.key])}
                            onChange={() => toggle(candidate.key)}
                            className="h-3.5 w-3.5 shrink-0 accent-[var(--color-accent)]"
                          />
                          <span className="w-20 shrink-0">
                            <span
                              className={cn(
                                'rounded px-1.5 py-0.5 font-mono text-[10px]',
                                candidate.risk >= 40
                                  ? 'bg-critical/10 text-critical'
                                  : 'bg-surface-3 text-ink-3',
                              )}
                            >
                              {candidate.primaryType}
                            </span>
                          </span>
                          <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink">
                            {candidate.value}
                          </span>
                          <span className="shrink-0 text-[10.5px] text-ink-3">
                            {candidate.source} · {candidate.risk}
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {mutation.isError && (
                <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-[12.5px] text-critical">
                  {mutation.error?.message ?? t('Failed to open the case')}
                </p>
              )}
            </div>

            <footer className="flex items-center justify-end gap-3 border-t border-border/70 px-5 py-4">
              <Button
                variant="secondary"
                onClick={() => setOpen(false)}
                disabled={mutation.isPending}
              >
                {t('Cancel')}
              </Button>
              <Button
                onClick={() => mutation.mutate()}
                disabled={
                  mutation.isPending ||
                  title.trim().length === 0 ||
                  pickedCount === 0
                }
              >
                {mutation.isPending ? (
                  <>
                    <Spinner className="h-4 w-4" />
                    {t('Opening case…')}
                  </>
                ) : (
                  <>
                    <ArrowUpRight className="h-4 w-4" />
                    {t('Open case & workspace')}
                  </>
                )}
              </Button>
            </footer>
          </div>
        </div>
      )}
    </>
  )
}