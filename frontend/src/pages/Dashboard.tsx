import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  BellRing,
  CalendarRange,
  FolderOpen,
  Radar,
  Server,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react'

import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { useCountUp } from '../hooks/useCountUp'
import {
  LEVEL_ORDER,
  formatRelative,
  shortId,
  statsTotal,
} from '../components/analysis/level'
import { useHistoryPage } from '../hooks/useAnalyses'
import {
  useAlerts,
  useDigest,
  useIOCs,
  useInvestigations,
  useProviderHealth,
  useWatchlist,
} from '../hooks/useIntel'
import { useI18n } from '../i18n'
import type {
  Alert,
  HistoryItem,
  InvestigationSeverity,
  ThreatLevel,
} from '../types'
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

const SEVERITY_DOT: Record<InvestigationSeverity, string> = {
  low: 'bg-ok',
  medium: 'bg-elevated',
  high: 'bg-warn',
  critical: 'bg-critical',
}

const LEVEL_ICON: Record<ThreatLevel | 'unknown', string> = {
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

function UtcClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])
  const time = now.toISOString().slice(11, 19)
  return (
    <span className="font-mono text-[12px] tracking-widest text-ink-2 tabular-nums">
      {time} UTC
    </span>
  )
}

function StatusDot({
  tone,
  ping = false,
}: {
  tone: 'ok' | 'warn' | 'critical' | 'muted'
  ping?: boolean
}) {
  const color =
    tone === 'ok'
      ? 'bg-ok text-ok'
      : tone === 'warn'
        ? 'bg-warn text-warn'
        : tone === 'critical'
          ? 'bg-critical text-critical'
          : 'bg-ink-3 text-ink-3'
  return (
    <span className={cn('relative flex h-2 w-2 shrink-0', color)}>
      {ping && (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-40" />
      )}
      <span className="relative inline-flex h-2 w-2 rounded-full bg-current" />
    </span>
  )
}

export function Dashboard() {
  const navigate = useNavigate()
  const { t } = useI18n()

  const history = useHistoryPage({ filter: 'all', limit: 50 })
  const iocs = useIOCs({ limit: 1 })
  const alerts = useAlerts(true)
  const providers = useProviderHealth(24)
  const watchlist = useWatchlist(true)
  const investigations = useInvestigations()
  const [digestWindow, setDigestWindow] = useState('week')
  const digest = useDigest(digestWindow)

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
  const watchCount = watchlist.data?.total ?? 0

  const openInvestigations = useMemo(
    () =>
      (investigations.data?.items ?? [])
        .filter((inv) => inv.status === 'open' || inv.status === 'active')
        .sort((a, b) =>
          ((b.updated_at ?? b.created_at) ?? '').localeCompare(
            (a.updated_at ?? a.created_at) ?? '',
          ),
        ),
    [investigations.data],
  )

  const feed: FeedItem[] = useMemo(() => {
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, alerts.data])

  const distribution = (
    ['unknown', ...LEVEL_ORDER] as (ThreatLevel | 'unknown')[]
  ).filter((level) => counts[level] > 0)

  const providersOk = providers.data?.rows.filter((row) => row.ok).length ?? 0
  const providersTotal = providers.data?.rows.length ?? 0
  const pipelineReady = history.data && total > 0

  const sourcesTone =
    providersTotal === 0
      ? 'muted'
      : providersOk === providersTotal
        ? 'ok'
        : providersOk === 0
          ? 'critical'
          : 'warn'

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="eyebrow mb-1.5">
            THREATLENS / {t('operations').toUpperCase()}
          </p>
          <h1 className="text-[24px] font-semibold tracking-tight text-ink md:text-[27px]">
            {t('Mission Control')}
          </h1>
          <p className="mt-1.5 max-w-xl text-pretty text-[13.5px] leading-relaxed text-ink-2">
            {providers.isLoading
              ? t('Checking the intelligence pipeline…')
              : providersOk === providersTotal
                ? t(
                    'Your intelligence environment is stable — {ok} of {total} sources are operational.',
                    { ok: providersOk, total: providersTotal },
                  )
                : t(
                    'Some intelligence sources are unavailable — {ok} of {total} operational. Confidence adjusts accordingly.',
                    { ok: providersOk, total: providersTotal },
                  )}
          </p>
        </div>
        <Button onClick={() => navigate('/analyze')}>
          <Radar className="h-4 w-4" />
          {t('Analyze an indicator')}
        </Button>
      </div>

      <Panel
        eyebrow={t('System telemetry')}
        title={t('System status')}
        action={<UtcClock />}
      >
        <div className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-6 lg:divide-x lg:divide-border/60">
          <TelemetryCell
            label={t('Pipeline')}
            dot={<StatusDot tone={pipelineReady ? 'ok' : 'muted'} ping={pipelineReady} />}
            value={pipelineReady ? t('Operational') : t('Standby')}
            valueClass={pipelineReady ? 'text-ok' : 'text-ink-3'}
          />
          <TelemetryCell
            label={t('Sources')}
            dot={<StatusDot tone={sourcesTone} ping={sourcesTone === 'ok'} />}
            value={`${providers.isLoading ? '—' : providersOk}/${providersTotal} ${t('online')}`}
            valueClass={
              sourcesTone === 'ok'
                ? 'text-ok'
                : sourcesTone === 'critical'
                  ? 'text-critical'
                  : 'text-warn'
            }
          />
          <TelemetryCell
            label={t('Watchlist')}
            dot={<StatusDot tone={watchCount > 0 ? 'ok' : 'muted'} />}
            value={`${watchCount} ${t('active').toLowerCase()}`}
          />
          <TelemetryCell
            label={t('Investigations')}
            dot={<StatusDot tone={openInvestigations.length > 0 ? 'warn' : 'muted'} />}
            value={`${openInvestigations.length.toString().padStart(2, '0')} ${t('open').toLowerCase()}`}
            valueClass={openInvestigations.length > 0 ? 'text-warn' : undefined}
          />
          <TelemetryCell
            label={t('Unseen alerts')}
            dot={
              <StatusDot
                tone={alertCount > 0 ? 'critical' : 'muted'}
                ping={alertCount > 0}
              />
            }
            value={`${alertCount} ${t('unseen').toLowerCase()}`}
            valueClass={alertCount > 0 ? 'text-critical' : undefined}
          />
          <TelemetryCell
            label={t('IOC registry')}
            dot={<StatusDot tone={iocCount > 0 ? 'ok' : 'muted'} />}
            value={`${iocCount} ${t('tracked').toLowerCase()}`}
          />
        </div>
      </Panel>

      <section className="rounded-xl border border-border bg-surface">
        <div className="grid grid-cols-2 divide-x divide-border lg:grid-cols-4">
          <ThreatStat
            label={t('New detections')}
            value={history.isLoading ? null : flagged}
            note={t('malicious or critical verdicts')}
            valueClass={flagged > 0 ? 'text-critical' : 'text-ink'}
          />
          <ThreatStat
            label={t('Active IOCs')}
            value={iocs.isLoading ? null : iocCount}
            note={t('distinct indicators tracked')}
          />
          <ThreatStat
            label={t('Open investigations')}
            value={investigations.isLoading ? null : openInvestigations.length}
            note={t('awaiting analyst attention')}
            valueClass={openInvestigations.length > 0 ? 'text-warn' : 'text-ink'}
          />
          <ThreatStat
            label={t('Unseen alerts')}
            value={alerts.isLoading ? null : alertCount}
            note={t('watchlist rules firing')}
            valueClass={alertCount > 0 ? 'text-critical' : 'text-ink'}
          />
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel
          eyebrow={t('Cases')}
          title={t('Active investigations')}
          className="lg:col-span-2"
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate('/investigations')}
            >
              {t('View all')}
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          }
        >
          {investigations.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : openInvestigations.length === 0 ? (
            <EmptyState
              icon={<FolderOpen className="h-5 w-5" />}
              title={t('No open investigations')}
              description={t(
                'Investigations appear here when evidence gets organized around an indicator.',
              )}
              className="py-10"
            />
          ) : (
            <ul className="space-y-1">
              {openInvestigations.slice(0, 6).map((inv) => (
                <li key={inv.id}>
                  <button
                    type="button"
                    onClick={() => navigate('/investigations')}
                    className="group flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left transition-colors hover:bg-surface-2"
                  >
                    <span
                      className={cn(
                        'h-2 w-2 shrink-0 rounded-full',
                        SEVERITY_DOT[inv.severity],
                      )}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] font-medium text-ink group-hover:text-accent-strong">
                        {inv.title}
                      </span>
                      <span className="block truncate font-mono text-[11px] text-ink-3">
                        #{shortId(inv.id)}
                        {inv.items.length > 0
                          ? ` · ${inv.items.length} ${t('indicators').toLowerCase()}`
                          : ''}
                      </span>
                    </span>
                    <span
                      className={cn(
                        'rounded-md border px-1.5 py-0.5 font-mono text-[10px] tracking-wider uppercase',
                        inv.status === 'open'
                          ? 'border-accent/30 bg-accent/10 text-accent-strong'
                          : 'border-ok/30 bg-ok/10 text-ok',
                      )}
                    >
                      {inv.status}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          eyebrow={t('Live intelligence')}
          title={t('Recent activity')}
          className="lg:col-span-3"
          action={
            <span className="flex items-center gap-1.5 rounded-full border border-ok/30 bg-ok/10 px-2 py-0.5 font-mono text-[10px] tracking-widest text-ok uppercase">
              <StatusDot tone="ok" ping />
              {t('Live')}
            </span>
          }
        >
          {history.isLoading || alerts.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
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
                    <span className="w-12 shrink-0 text-right font-mono text-[11px] text-ink-3 tabular-nums">
                      {formatRelative(event.at)}
                    </span>
                    <span
                      className={cn(
                        'grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-border bg-surface-3',
                        event.kind === 'alert'
                          ? 'text-critical'
                          : LEVEL_ICON[event.level ?? 'unknown'],
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
                    {event.level && <LevelBadge level={event.level} />}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          eyebrow={t('Verdict mix')}
          title={t('Threat level distribution')}
          action={<ShieldCheck className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          {history.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
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
              className="py-8"
            />
          ) : (
            <>
              <div className="flex h-2 w-full gap-0.5 overflow-hidden rounded-full">
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
              <ul className="mt-4 space-y-1.5">
                {distribution.map((level) => {
                  const pct = Math.round((counts[level] / items.length) * 100)
                  return (
                    <li
                      key={level}
                      className="flex items-center justify-between text-[12.5px]"
                    >
                      <span className="flex items-center gap-2 text-ink-2">
                        <span
                          className={cn(
                            'h-2 w-2 rounded-sm',
                            BAR_CLASS[level],
                          )}
                        />
                        <span className="capitalize">{t(level)}</span>
                      </span>
                      <span className="flex items-center gap-3">
                        <span className="font-mono tabular-nums text-ink">
                          {counts[level]}
                        </span>
                        <span className="w-8 text-right font-mono tabular-nums text-ink-3">
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
          eyebrow={t('Source telemetry')}
          title={t('Intelligence sources')}
          action={
            <span className="flex items-center gap-1.5 text-[12px] text-ink-3">
              <Server className="h-3.5 w-3.5" aria-hidden />
              <span className="font-mono">
                {providers.isLoading
                  ? '…'
                  : `${providersOk}/${providersTotal}`}
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
            <ul className="space-y-1">
              {providers.data.rows.map((row) => (
                <li
                  key={row.provider}
                  className="flex items-center justify-between rounded-lg px-2 py-2 transition-colors hover:bg-surface-2"
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <StatusDot
                      tone={row.ok ? 'ok' : 'critical'}
                      ping={row.ok}
                    />
                    <span className="truncate font-mono text-[13px] text-ink">
                      {row.provider}
                    </span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2 font-mono text-[11px] text-ink-3 tabular-nums">
                    {row.ok ? (
                      <>
                        {row.availability != null && (
                          <span>{row.availability}%</span>
                        )}
                        {row.latency_ms != null && (
                          <span>{row.latency_ms}ms</span>
                        )}
                      </>
                    ) : (
                      <span className="text-critical">{t('Offline')}</span>
                    )}
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
        <p className="font-mono text-[12px] leading-relaxed text-ink-3">
          from IOC to investigation — every score is computed from detection
          ratios, reputation and community verdicts, then reviewed by an
          evidence-locked AI model.
        </p>
        <Button variant="secondary" size="sm" onClick={() => navigate('/analyze')}>
          <Radar className="h-3.5 w-3.5" />
          {t('Analyze an indicator')}
        </Button>
      </div>
    </div>
  )
}

function TelemetryCell({
  label,
  dot,
  value,
  valueClass,
  className,
}: {
  label: string
  dot: React.ReactNode
  value: string
  valueClass?: string
  className?: string
}) {
  return (
    <div
      className={cn(
        'min-w-0 py-1 first:pl-0 sm:first:pl-0 lg:pl-6 lg:first:pl-0',
        className,
      )}
    >
      <p className="eyebrow mb-2">{label}</p>
      <div className="flex items-center gap-2">
        {dot}
        <span
          className={cn(
            'font-mono text-[13px] tracking-tight text-ink',
            valueClass,
          )}
        >
          {value}
        </span>
      </div>
    </div>
  )
}

function ThreatStat({
  label,
  value,
  note,
  valueClass,
}: {
  label: string
  value: number | null
  note: string
  valueClass?: string
}) {
  const animated = useCountUp(value ?? 0)
  return (
    <div className="min-w-0 px-4 py-5 md:px-6">
      <p className="eyebrow mb-1.5">{label}</p>
      <p
        className={cn(
          'text-[34px] leading-none font-semibold tracking-tight text-ink tabular-nums md:text-[40px]',
          valueClass,
        )}
      >
        {value == null ? '—' : animated}
      </p>
      <p className="mt-1.5 text-[11.5px] text-ink-3">{note}</p>
    </div>
  )
}