import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FolderOpen, History, ListChecks, Network } from 'lucide-react'

import { Panel } from '../ui/Panel'
import { Button } from '../ui/Button'
import { Spinner } from '../ui/Spinner'
import { LevelBadge } from './LevelBadge'
import { useIOC } from '../../hooks/useIntel'
import { useI18n } from '../../i18n'
import type { SnapshotPoint, ThreatLevel } from '../../types'
import { cn } from '../../utils/cn'

const DOT_CLASS: Record<ThreatLevel | 'unknown', string> = {
  clean: 'bg-ok',
  suspicious: 'bg-elevated',
  malicious: 'bg-high',
  critical: 'bg-critical',
  unknown: 'bg-ink-3',
}

const LEVEL_ORDER = ['clean', 'suspicious', 'malicious', 'critical'] as const

function levelKey(value: string | null | undefined): ThreatLevel | 'unknown' {
  return LEVEL_ORDER.includes(value as ThreatLevel)
    ? (value as ThreatLevel)
    : 'unknown'
}

function VerdictBadge({ value }: { value: string | null | undefined }) {
  const { t } = useI18n()
  const key = levelKey(value)
  if (key === 'unknown') {
    return (
      <span className="rounded-full border border-border-strong bg-surface-3 px-2 py-0.5 font-mono text-[10px] tracking-wider text-ink-3 uppercase">
        {t('No verdict')}
      </span>
    )
  }
  return <LevelBadge level={key} />
}

function datePart(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function eventLabel(
  prev: SnapshotPoint | null,
  current: SnapshotPoint,
  t: (key: string, vars?: Record<string, string | number>) => string,
): string | null {
  if (!prev) return t('First observed')
  const prevLevel = levelKey(prev.threat_level)
  const curLevel = levelKey(current.threat_level)
  if (prevLevel !== curLevel) {
    return t('Verdict changed: {from} → {to}', {
      from: t(prevLevel),
      to: t(curLevel),
    })
  }
  const prevScore = prev.threat_score
  const curScore = current.threat_score
  if (prevScore != null && curScore != null) {
    const delta = curScore - prevScore
    if (delta >= 15) {
      return t('Threat score climbed: {a} → {b}', { a: prevScore, b: curScore })
    }
    if (delta <= -15) {
      return t('Threat score dropped: {a} → {b}', { a: prevScore, b: curScore })
    }
  }
  if (current.malicious > prev.malicious) {
    return t('Malicious detections: {a} → {b}', {
      a: prev.malicious,
      b: current.malicious,
    })
  }
  if (current.suspicious > prev.suspicious) {
    return t('Suspicious detections: {a} → {b}', {
      a: prev.suspicious,
      b: current.suspicious,
    })
  }
  return null
}

function checklistFor(level: ThreatLevel | null | undefined): string[] {
  switch (level) {
    case 'malicious':
    case 'critical':
      return [
        'Block the indicator at the perimeter.',
        'Search endpoints and EDR for the related hashes or hosts.',
        'Review DNS and firewall logs for outbound contact.',
        'Open an investigation and attach this evidence.',
      ]
    case 'suspicious':
      return [
        'Add the indicator to the watchlist for automated rescan.',
        'Monitor outbound connections toward it over the next 24 hours.',
        'Gather passive enrichment: RDAP, DNS and certificates.',
      ]
    case 'clean':
      return [
        'Document the indicator as benign in the investigation notes.',
      ]
    default:
      return [
        'Re-analyze the indicator to capture a fresh snapshot.',
        'Add it to the watchlist so changes are caught automatically.',
      ]
  }
}

interface IocStoryProps {
  indicator: string
  currentAnalysisId?: string
}

export function IocStory({ indicator, currentAnalysisId }: IocStoryProps) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const detail = useIOC(indicator)

  const [checked, setChecked] = useState<ReadonlySet<number>>(new Set())

  const points = useMemo(() => {
    const list = detail.data?.timeline ?? []
    return [...list].reverse()
  }, [detail.data])

  const first = points[0]
  const last = points.at(-1)

  const narrative = useMemo(() => {
    if (!first || !last) return null
    const firstScore = first.threat_score
    const lastScore = last.threat_score
    const malFirst = first.malicious
    const malLast = last.malicious
    const lines: string[] = []

    lines.push(t('First observed {date}.', { date: datePart(first.analyzed_at) }))

    if (points.length > 1) {
      lines.push(
        t('Re-analyzed {n} more times since; the latest pass was {date}.', {
          n: points.length - 1,
          date: datePart(last.analyzed_at),
        }),
      )
    } else {
      lines.push(t('Observed once — there is no longitudinal history yet.'))
    }

    if (firstScore != null && lastScore != null) {
      const delta = lastScore - firstScore
      if (delta >= 15) {
        lines.push(
          t('The threat score climbed from {a} to {b}.', {
            a: firstScore,
            b: lastScore,
          }),
        )
      } else if (delta <= -15) {
        lines.push(
          t('The threat score dropped from {a} to {b}.', {
            a: firstScore,
            b: lastScore,
          }),
        )
      } else {
        lines.push(
          t('The threat score has remained stable at {b}.', {
            b: lastScore,
          }),
        )
      }
    } else {
      lines.push(t('The registry holds no threat score for this indicator yet.'))
    }

    if (malLast > malFirst) {
      lines.push(
        t('Malicious engine detections rose from {a} to {b}.', {
          a: malFirst,
          b: malLast,
        }),
      )
    } else if (malLast < malFirst) {
      lines.push(
        t('Malicious engine detections fell from {a} to {b}.', {
          a: malFirst,
          b: malLast,
        }),
      )
    } else if (points.length > 1) {
      lines.push(
        t('The malicious engine count stayed at {b}.', { b: malLast }),
      )
    }

    const lastLevel = levelKey(last.threat_level)
    if (lastLevel !== 'unknown') {
      lines.push(
        t('Current verdict: {level} ({score} of 100), seen at {date}.', {
          level: t(lastLevel).toLowerCase(),
          score: lastScore ?? '—',
          date: datePart(last.analyzed_at),
        }),
      )
    } else {
      lines.push(t('No deterministic verdict yet — the evidence is thin.'))
    }

    if (points.length === 1) {
      lines.push(
        t('A single observation anchors limited confidence — keep monitoring.'),
      )
    }
    return lines
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [points, t])

  if (detail.isLoading) {
    return (
      <Panel eyebrow={t('IOC story')} title={t('The story so far')}>
        <div className="flex items-center gap-3 py-4 text-ink-2">
          <Spinner />
          {t('Building the story…')}
        </div>
      </Panel>
    )
  }

  if (detail.isError || !detail.data || points.length === 0) {
    return null
  }

  if (!first || !last) return null

  const checklist = checklistFor(last.threat_level as ThreatLevel | null)

  const toggle = (index: number) => {
    setChecked((prev) => {
      const next = new Set(prev)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })
  }

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Panel
        eyebrow={t('IOC story')}
        title={t('The story so far')}
        className="lg:col-span-3"
        action={<History className="h-4 w-4 text-ink-3" aria-hidden />}
      >
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <MetricChip
            label={t('First seen')}
            value={datePart(first.analyzed_at)}
          />
          <MetricChip label={t('Observations')} value={`${points.length}`} />
          <MetricChip
            label={t('Latest score')}
            value={last.threat_score == null ? '—' : `${last.threat_score}`}
          />
          <div className="rounded-lg border border-border bg-surface px-3 py-2">
            <p className="eyebrow mb-1">{t('Latest verdict')}</p>
            <VerdictBadge value={last.threat_level} />
          </div>
        </div>

        {narrative && (
          <p className="mt-4 text-[13.5px] leading-relaxed text-ink-2">
            {narrative.join(' ')}
          </p>
        )}

        <div className="mt-5 border-t border-border/60 pt-4">
          <p className="eyebrow mb-3">{t('Snapshot history')}</p>
          <ul>
            {points.map((point, index) => {
              const prev = index > 0 ? (points[index - 1] ?? null) : null
              const label = eventLabel(prev, point, t)
              const isCurrent = point.analysis_id === currentAnalysisId
              return (
                <li key={point.analysis_id} className="flex gap-4 pb-5 last:pb-0">
                  <div className="flex w-[86px] shrink-0 flex-col items-end pt-2">
                    <span className="font-mono text-[11px] text-ink-3 tabular-nums">
                      {datePart(point.analyzed_at)}
                    </span>
                    <span className="font-mono text-[10px] text-ink-3/70 tabular-nums">
                      {point.analyzed_at
                        ? new Date(point.analyzed_at)
                            .toLocaleTimeString(undefined, {
                              hour: '2-digit',
                              minute: '2-digit',
                            })
                            .toLowerCase()
                        : '—'}
                    </span>
                  </div>

                  <div className="relative flex shrink-0 flex-col items-center">
                    {index < points.length - 1 && (
                      <span className="absolute top-2 bottom-0 w-px bg-border" />
                    )}
                    <span
                      className={cn(
                        'relative mt-3 h-2.5 w-2.5 rounded-full ring-4 ring-bg',
                        DOT_CLASS[levelKey(point.threat_level)],
                      )}
                    />
                  </div>

                  <button
                    type="button"
                    onClick={() => navigate(`/analysis/${point.analysis_id}`)}
                    className={cn(
                      'min-w-0 flex-1 rounded-lg border bg-surface px-3 py-2.5 text-left transition-colors hover:bg-surface-2',
                      isCurrent
                        ? 'border-accent/50'
                        : 'border-border',
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="font-mono text-[13px] text-ink">
                        {point.threat_score == null ? '—' : point.threat_score}
                        <span className="text-ink-3">/100</span>
                      </span>
                      <VerdictBadge value={point.threat_level} />
                      <span className="font-mono text-[10.5px] text-ink-3">
                        {point.malicious} m · {point.suspicious} s
                      </span>
                      {isCurrent && (
                        <span className="ml-auto rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-accent-strong uppercase">
                          {t('This analysis')}
                        </span>
                      )}
                    </div>
                    {label && (
                      <p className="mt-1.5 border-t border-border/50 pt-1.5 text-[11.5px] text-ink-2">
                        {label}
                      </p>
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        </div>
      </Panel>

      <div className="space-y-4 lg:col-span-2">
        <Panel
          eyebrow={t('Next actions')}
          title={t('What should an analyst do next?')}
          action={<ListChecks className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          <ul className="space-y-1">
            {checklist.map((item, index) => (
              <li key={item}>
                <button
                  type="button"
                  onClick={() => toggle(index)}
                  className="group flex w-full items-start gap-2.5 rounded-lg px-2 py-2 text-left transition-colors hover:bg-surface-2"
                >
                  <span
                    className={cn(
                      'mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded border text-[10px]',
                      checked.has(index)
                        ? 'border-ok bg-ok/20 text-ok'
                        : 'border-border-strong bg-surface-3 text-transparent',
                    )}
                  >
                    ✓
                  </span>
                  <span
                    className={cn(
                      'text-[12.5px] leading-snug',
                      checked.has(index)
                        ? 'text-ink-3 line-through'
                        : 'text-ink-2',
                    )}
                  >
                    {t(item)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap gap-2 border-t border-border/60 pt-3">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => navigate('/investigations')}
            >
              <FolderOpen className="h-3.5 w-3.5" />
              {t('Open investigations')}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              disabled={!currentAnalysisId}
              onClick={() =>
                currentAnalysisId &&
                navigate(`/analysis/${currentAnalysisId}/graph`)
              }
            >
              <Network className="h-3.5 w-3.5" />
              {t('View relationship graph')}
            </Button>
          </div>
        </Panel>
      </div>
    </div>
  )
}

function MetricChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2">
      <p className="eyebrow mb-1">{label}</p>
      <p className="truncate font-mono text-[13px] tabular-nums text-ink">
        {value}
      </p>
    </div>
  )
}