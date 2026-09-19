import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  BellRing,
  CalendarRange,
  Crosshair,
  LayoutGrid,
  Radar,
  Server,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { StatCard } from '../components/ui/StatCard'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { LEVEL_ORDER, formatRelative, statsTotal } from '../components/analysis/level'
import { useHistoryPage } from '../hooks/useAnalyses'
import {
  useAlerts,
  useDigest,
  useIOCs,
  useProviderHealth,
} from '../hooks/useIntel'
import { useI18n } from '../i18n'
import type { Alert, HistoryItem, ThreatLevel } from '../types'
import { cn } from '../utils/cn'

const DIGEST_WINDOWS = [
  { value: 'day', label: 'Today' },
  { value: 'week', label: 'This week' },
  { value: 'month', label: 'This month' },
]

const BAR_CLASS: Record<ThreatLevel | 'unknown', string> = {
  clean: 'bg-clean',
  suspicious: 'bg-elevated',
  malicious: 'bg-high',
  critical: 'bg-critical',
  unknown: 'bg-ink-3',
}

const FEED_ICON: Record<ThreatLevel | 'unknown', string> = {
  clean: 'text-ok',
  suspicious: 'text-elevated',
  malicious: 'text-high',
  critical: 'text-critical',
  unknown: 'text-ink-3',
}

interface FeedItem {
  key: string
  kind: 'analysis' | 'alert'
  level: ThreatLevel | null
  title: string
  detail: string
  at: string | null
  href: string
}

function trackingFor(item: HistoryItem) {
  if (item.threat_level === 'malicious' || item.threat_level === 'critical') {
    return 'detected by {count} engines'
  }
  if (item.threat_level === 'suspicious') {
    return 'suspicious across {count} of {total} engines'
  }
  return 'clean across {count} engines'
}

function levelOf(value: string | null | undefined): ThreatLevel | null {
  if (
    value === 'clean' ||
    value === 'suspicious' ||
    value === 'malicious' ||
    value === 'critical'
  ) {
    return value
  }
  return null
}

function alertLevel(alert: Alert): ThreatLevel | null {
  return levelOf(alert.level)
}

export function Dashboard() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const history = useHistoryPage({ filter: 'all', limit: 50 })
  const iocs = useIOCs({ limit: 1 })
  const alerts = useAlerts(true)
  const [digestWindow, setDigestWindow] = useState('week')
  const digest = useDigest(digestWindow)
  const providers = useProviderHealth()

  const items = history.data?.items ?? []
  const total = history.data?.total ?? 0

  const counts: Record<ThreatLevel | 'unknown', number> = {
    clean: 0,
    suspicious: 0,
    malicious: 0,
    critical: 0,
    unknown: 0,
  }
  for (const item of items) {
    const key = item.threat_level ?? 'unknown'
    counts[key] = (counts[key] ?? 0) + 1
  }

  const flagged = counts.malicious + counts.critical
  const alertCount = alerts.data?.total ?? 0
  const iocCount = iocs.data?.total ?? 0

  const feed: FeedItem[] = (() => {
    const analysisEvents: FeedItem[] = items.map((item) => ({
      key: `a-${item.analysis_id}`,
      kind: 'analysis',
      level: item.threat_level,
      title: item.indicator,
      detail: t(trackingFor(item), {
        count: item.detected_vendors,
        total: statsTotal(item.stats),
      }),
      at: item.created_at,
      href: `/analysis/${item.analysis_id}`,
    }))
    const alertEvents: FeedItem[] = (alerts.data?.items ?? [])
      .filter((alert) => !alert.seen)
      .map((alert) => ({
        key: `al-${alert.id}`,
        kind: 'alert',
        level: alertLevel(alert),
        title: alert.indicator,
        detail: alert.message,
        at: alert.triggered_at,
        href: alert.analysis_id
          ? `/analysis/${alert.analysis_id}`
          : '/watchlist',
      }))
    return [...analysisEvents, ...alertEvents]
      .filter((event) => event.at != null)
      .sort((a, b) => (a.at! < b.at! ? 1 : -1))
      .slice(0, 8)
  })()

  const distribution = (
    ['unknown', ...LEVEL_ORDER] as (ThreatLevel | 'unknown')[]
  ).filter((level) => counts[level] > 0)

  const providersOk = providers.data?.rows.filter((row) => row.ok).length ?? 0
  const providersTotal = providers.data?.rows.length ?? 0

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('Security Operations Center')}
        description={t(
          'Live threat posture across analyses, IOCs, watchlist alerts and provider health.',
        )}
        action={
          <Button onClick={() => navigate('/analyze')}>
            {t('New analysis')}
            <ArrowRight className="h-4 w-4" />
          </Button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label={t('Total analyses')}
          value={history.isLoading ? '—' : total}
          hint={t('Across all indicator types')}
        />
        <StatCard
          label={t('Flagged findings')}
          value={history.isLoading ? '—' : flagged}
          hint={t('Malicious or critical verdicts in the latest set')}
          valueClass={flagged > 0 ? 'text-critical' : 'text-ink'}
        />
        <StatCard
          label={t('Active IOCs')}
          value={iocs.isLoading ? '—' : iocCount}
          hint={t('Distinct indicators tracked')}
        />
        <StatCard
          label={t('Unseen alerts')}
          value={alerts.isLoading ? '—' : alertCount}
          hint={t('Watchlist rules that need attention')}
          valueClass={alertCount > 0 ? 'text-elevated' : 'text-ink'}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel
          eyebrow={t('Live intelligence')}
          title={t('Activity feed')}
          className="lg:col-span-3"
          action={
            <span className="flex items-center gap-1.5 rounded-full border border-ok/30 bg-ok/10 px-2 py-0.5 font-mono text-[10px] tracking-widest text-ok uppercase">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-50" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-ok" />
              </span>
              {t('Live')}
            </span>
          }
        >
          {history.isLoading || alerts.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : feed.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-5 w-5" />}
              title={t('No activity yet')}
              description={t(
                'Recent analyses and watchlist alerts will stream in here.',
              )}
              className="py-10"
            />
          ) : (
            <ul className="divide-y divide-border/70">
              {feed.map((event) => (
                <li key={event.key}>
                  <button
                    type="button"
                    onClick={() => navigate(event.href)}
                    className="group flex w-full items-center gap-3 py-3 text-left"
                  >
                    <span
                      className={cn(
                        'grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-border bg-surface-3',
                        event.kind === 'alert'
                          ? 'text-critical'
                          : FEED_ICON[event.level ?? 'unknown'],
                      )}
                    >
                      {event.kind === 'alert' ? (
                        <BellRing className="h-3.5 w-3.5" />
                      ) : (
                        <Radar className="h-3.5 w-3.5" />
                      )}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-[12.5px] text-ink group-hover:text-accent-strong">
                        {event.title}
                      </p>
                      <p className="truncate text-[11.5px] text-ink-3">
                        {event.detail}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2.5">
                      {event.level && <LevelBadge level={event.level} />}
                      <span className="w-16 text-right text-[11px] text-ink-3 tabular-nums">
                        {formatRelative(event.at)}
                      </span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          eyebrow={t('Enrichment')}
          title={t('Provider health')}
          className="lg:col-span-2"
          action={
            <span className="flex items-center gap-1.5 text-[12px] text-ink-3">
              <Server className="h-3.5 w-3.5" aria-hidden />
              <span className="font-mono">
                {providers.isLoading ? '…' : `${providersOk}/${providersTotal}`}
              </span>
            </span>
          }
        >
          {providers.isLoading ? (
            <div className="flex items-center gap-2 text-[12.5px] text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : providers.data && providers.data.rows.length > 0 ? (
            <ul className="space-y-1.5">
              {providers.data.rows.map((row) => (
                <li
                  key={row.provider}
                  className="flex items-center justify-between rounded-lg border border-border/70 bg-surface px-3 py-2.5"
                >
                  <span className="flex items-center gap-2.5">
                    <span
                      className={cn(
                        'relative flex h-2 w-2',
                        row.ok ? 'text-ok' : 'text-critical',
                      )}
                    >
                      {row.ok && (
                        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-40" />
                      )}
                      <span
                        className={cn(
                          'relative inline-flex h-2 w-2 rounded-full bg-current',
                        )}
                      />
                    </span>
                    <span className="font-mono text-[13px] text-ink">
                      {row.provider}
                    </span>
                  </span>
                  <span className="text-[11.5px] text-ink-3">
                    {row.ok
                      ? row.availability != null
                        ? `${row.availability}%`
                        : t('Online')
                      : t('Offline')}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12.5px] text-ink-3">
              {t('No enrichment activity recorded yet.')}
            </p>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="mt-3 w-full"
            onClick={() => navigate('/settings')}
          >
            {t('Backend status')}
            <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          eyebrow={t('Verdict mix')}
          title={t('Threat level distribution')}
          action={
            <ShieldCheck className="h-4 w-4 text-ink-3" aria-hidden />
          }
        >
          {history.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : items.length === 0 ? (
            <EmptyState
              icon={<ShieldQuestion className="h-5 w-5" />}
              title={t('Nothing charted yet')}
              description={t(
                'Analyze your first indicator to see the verdict mix.',
              )}
              className="py-10"
            />
          ) : (
            <>
              <div className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full">
                {distribution.map((level) => (
                  <div
                    key={level}
                    className={cn(
                      'h-full transition-all duration-700 ease-out',
                      BAR_CLASS[level],
                    )}
                    style={{
                      width: `${(counts[level] / items.length) * 100}%`,
                    }}
                  />
                ))}
              </div>
              <ul className="mt-4 space-y-2">
                {distribution.map((level) => {
                  const pct = Math.round((counts[level] / items.length) * 100)
                  return (
                    <li
                      key={level}
                      className="flex items-center justify-between text-[12.5px]"
                    >
                      <span className="flex items-center gap-2 text-ink-2">
                        <span
                          className={cn('h-2.5 w-2.5 rounded-sm', BAR_CLASS[level])}
                        />
                        <span className="capitalize">{t(level)}</span>
                      </span>
                      <span className="flex items-center gap-3">
                        <span className="font-mono tabular-nums text-ink">
                          {counts[level]}
                        </span>
                        <span className="w-9 text-right font-mono tabular-nums text-ink-3">
                          %{pct}
                        </span>
                      </span>
                    </li>
                  )
                })}
              </ul>
            </>
          )}
        </Panel>

        <Panel
          eyebrow={t('Analyst toolkit')}
          title={t('Jump to a workflow')}
          className="lg:col-span-1"
        >
          <div className="space-y-1.5">
            {[
              {
                to: '/hunt',
                icon: <Crosshair className="h-4 w-4" />,
                label: 'Threat Hunting',
                desc: 'Search indicators across analyses and IOCs with type filters.',
              },
              {
                to: '/mitre',
                icon: <LayoutGrid className="h-4 w-4" />,
                label: 'MITRE ATT&CK',
                desc: 'Map stored evidence to techniques and inspect coverage.',
              },
              {
                to: '/watchlist',
                icon: <BellRing className="h-4 w-4" />,
                label: 'Watchlist',
                desc: 'Automated rescan rules and the alert queue.',
              },
            ].map((tool) => (
              <button
                key={tool.to}
                type="button"
                onClick={() => navigate(tool.to)}
                className="group flex w-full items-center gap-3 rounded-lg border border-border/70 bg-surface px-3 py-3 text-left transition-colors hover:border-accent/40 hover:bg-surface-2"
              >
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-surface-3 text-accent">
                  {tool.icon}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[13px] font-semibold text-ink group-hover:text-accent-strong">
                    {t(tool.label)}
                  </span>
                  <span className="block truncate text-[11.5px] text-ink-3">
                    {t(tool.desc)}
                  </span>
                </span>
                <ArrowRight className="h-4 w-4 shrink-0 text-ink-3 group-hover:text-accent" />
              </button>
            ))}
          </div>
        </Panel>

        <Panel
          eyebrow={t('Intelligence digest')}
          title={t('Period summary')}
          action={<CalendarRange className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          <div className="mb-3 flex gap-1">
            {DIGEST_WINDOWS.map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => setDigestWindow(option.value)}
                className={cn(
                  'focus-ring rounded-md px-2.5 py-1 text-[12px] font-medium transition-colors',
                  digestWindow === option.value
                    ? 'bg-surface-4 text-ink'
                    : 'text-ink-2 hover:text-ink',
                )}
              >
                {t(option.label)}
              </button>
            ))}
          </div>
          {digest.isLoading ? (
            <div className="flex items-center gap-2 text-[12.5px] text-ink-2">
              <Spinner />
              {t('Building digest…')}
            </div>
          ) : (
            <ul className="space-y-2">
              {(digest.data?.sections ?? []).map((section) => (
                <li
                  key={section.label}
                  className="flex items-center justify-between border-b border-border/60 pb-2 last:border-0"
                >
                  <span className="text-[12.5px] text-ink-2">
                    {t(section.label)}
                  </span>
                  <span className="max-w-[55%] truncate font-mono text-[13px] tabular-nums text-ink">
                    {section.value}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface px-4 py-3 md:px-5">
        <p className="text-[12.5px] leading-relaxed text-ink-2">
          {t(
            'Every score is computed from detection ratios, reputation and community verdicts — then interpreted by a free, evidence-locked AI model.',
          )}
        </p>
        <Button variant="secondary" size="sm" onClick={() => navigate('/analyze')}>
          <Radar className="h-3.5 w-3.5" />
          {t('Analyze an indicator')}
        </Button>
      </div>
    </div>
  )
}