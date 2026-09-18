import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  BarChart3,
  CalendarRange,
  Search,
  Server,
  ShieldCheck,
  ShieldQuestion,
  Sparkles,
} from 'lucide-react'
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { StatCard } from '../components/ui/StatCard'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate, shortId, statsTotal } from '../components/analysis/level'
import { useHistoryPage } from '../hooks/useAnalyses'
import { useDigest, useGlobalSearch, useProviderHealth } from '../hooks/useIntel'
import { guessIndicatorType } from '../utils/validate'
import { useI18n } from '../i18n'
import type { ThreatLevel } from '../types'

const DIGEST_WINDOWS = [
  { value: 'day', label: 'Today' },
  { value: 'week', label: 'This week' },
  { value: 'month', label: 'This month' },
]

const LEVEL_COLORS: Record<ThreatLevel, string> = {
  clean: '#34d399',
  suspicious: '#fbbf24',
  malicious: '#fb923c',
  critical: '#fb7185',
}

interface DistributionEntry {
  name: ThreatLevel | 'unknown'
  value: number
  color: string
}

function toDistribution(
  items: { threat_level: ThreatLevel | null }[],
): DistributionEntry[] {
  const counts = new Map<ThreatLevel | 'unknown', number>()
  for (const item of items) {
    const key = item.threat_level ?? 'unknown'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return Array.from(counts.entries()).map(([name, value]) => ({
    name,
    value,
    color: name === 'unknown' ? '#5c6675' : LEVEL_COLORS[name],
  }))
}

export function Dashboard() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const history = useHistoryPage({ filter: 'all', limit: 50 })
  const [digestWindow, setDigestWindow] = useState('week')
  const [searchQuery, setSearchQuery] = useState('')
  const digest = useDigest(digestWindow)
  const search = useGlobalSearch(searchQuery)
  const providers = useProviderHealth()

  const items = history.data?.items ?? []
  const total = history.data?.total ?? 0
  const distribution = toDistribution(items)

  const flagged =
    history.isLoading || items.length === 0
      ? 0
      : items.filter(
          (item) =>
            item.threat_level === 'malicious' || item.threat_level === 'critical',
        ).length

  const recent = items.slice(0, 6)

  const quickAnalyze = (value: string) => {
    const type = guessIndicatorType(value) ?? 'HASH'
    navigate(
      `/analyze?type=${type}&input=${encodeURIComponent(value)}`,
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('Dashboard')}
        description={t("A live overview of the threat intelligence you've gathered.")}
        action={
          <Button onClick={() => navigate('/analyze')}>
            {t('New analysis')}
            <ArrowRight className="h-4 w-4" />
          </Button>
        }
      />

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard
          label={t('Total analyses')}
          value={history.isLoading ? '—' : total}
          hint={t('Across all indicator types')}
        />
        <StatCard
          label={t('Flagged')}
          value={history.isLoading ? '—' : flagged}
          hint={t('Malicious or critical verdicts')}
          valueClass={
            flagged > 0 ? 'text-critical' : 'text-ink'
          }
        />
        <StatCard
          label={t('Coverage')}
          value={history.isLoading ? '—' : items.length}
          hint={t('Latest 50 loaded for charts')}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel
          eyebrow={t('Verdict mix')}
          title={t('Level distribution')}
          className="lg:col-span-2"
          action={<BarChart3 className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          {history.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : distribution.length === 0 ? (
            <EmptyState
              icon={<ShieldQuestion className="h-5 w-5" />}
              title={t('Nothing charted yet')}
              description={t('Analyze your first indicator to see the verdict mix.')}
              className="py-10"
            />
          ) : (
            <>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={distribution}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={52}
                      outerRadius={78}
                      paddingAngle={3}
                      strokeWidth={0}
                    >
                      {distribution.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: 'var(--color-surface-3)',
                        border: '1px solid var(--color-border)',
                        borderRadius: 8,
                        fontSize: 12.5,
                      }}
                      formatter={(value, name) => [
                        value as number,
                        t(String(name)),
                      ]}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="mt-2 space-y-1.5">
                {distribution.map((entry) => (
                  <li
                    key={entry.name}
                    className="flex items-center justify-between text-[12.5px]"
                  >
                    <span className="flex items-center gap-2 text-ink-2">
                      <span
                        className="h-2.5 w-2.5 rounded-sm"
                        style={{ backgroundColor: entry.color }}
                      />
                      <span className="capitalize">{t(entry.name)}</span>
                    </span>
                    <span className="font-mono tabular-nums text-ink">
                      {entry.value}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>

        <Panel
          eyebrow={t('Recent work')}
          title={t('Latest analyses')}
          className="lg:col-span-3"
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate('/history')}
            >
              {t('View all')}
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          }
        >
          {history.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : recent.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-5 w-5" />}
              title={t('No activity yet')}
              description={t('Your most recent investigations will appear here.')}
              className="py-10"
            />
          ) : (
            <ul className="divide-y divide-border/70">
              {recent.map((item) => (
                <li key={item.analysis_id}>
                  <button
                    type="button"
                    className="group flex w-full items-center gap-3 py-3 text-left"
                    onClick={() => navigate(`/analysis/${item.analysis_id}`)}
                  >
                    <LevelBadge level={item.threat_level} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-[13px] text-ink group-hover:text-accent-strong">
                        {item.indicator}
                      </p>
                      <p className="truncate text-[11.5px] text-ink-3">
                        {item.meaningful_name ?? shortId(item.analysis_id)} ·{' '}
                        {t('{count}/{total} flagged', {
                          count: item.detected_vendors,
                          total: statsTotal(item.stats),
                        })}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="font-mono text-[13px] tabular-nums text-ink">
                        {item.threat_score ?? '—'}
                      </p>
                      <p className="text-[11px] text-ink-3">
                        {formatDate(item.created_at)}
                      </p>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          eyebrow={t('Global search')}
          title={t('Find anything')}
          action={<Search className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          <input
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder={t('Indicator, IOC or note…')}
            spellCheck={false}
            className="focus-ring h-10 w-full rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink placeholder:text-ink-3 focus:border-accent/50"
          />
          <div className="mt-3">
            {searchQuery.trim().length < 2 ? (
              <p className="text-[12.5px] text-ink-3">
                {t('Type at least two characters to search analyses, IOCs and cases.')}
              </p>
            ) : search.isLoading ? (
              <div className="flex items-center gap-2 text-[12.5px] text-ink-2">
                <Spinner />
                {t('Searching…')}
              </div>
            ) : search.data && search.data.results.length > 0 ? (
              <ul className="max-h-64 space-y-1.5 overflow-y-auto">
                {search.data.results.slice(0, 8).map((result) => (
                  <li key={`${result.kind}-${result.id}`}>
                    <button
                      type="button"
                      onClick={() =>
                        result.kind === 'analysis'
                          ? navigate(`/analysis/${result.id}`)
                          : navigate('/iocs')
                      }
                      className="group w-full rounded-lg border border-border bg-surface px-3 py-2 text-left transition-colors hover:bg-surface-2"
                    >
                      <p className="truncate font-mono text-[12px] text-ink group-hover:text-accent-strong">
                        {result.title}
                      </p>
                      <p className="truncate text-[11px] text-ink-3">
                        {result.kind} · {result.subtitle}
                      </p>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[12.5px] text-ink-3">{t('No matches.')}</p>
            )}
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
                className={`rounded-md px-2.5 py-1 text-[12px] font-medium transition-colors ${
                  digestWindow === option.value
                    ? 'bg-surface-4 text-ink'
                    : 'text-ink-2 hover:text-ink'
                }`}
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
                  <span className="font-mono text-[13px] tabular-nums text-ink">
                    {section.value}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          eyebrow={t('Enrichment')}
          title={t('Provider health')}
          action={<Server className="h-4 w-4 text-ink-3" aria-hidden />}
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
                  className="flex items-center justify-between text-[12.5px]"
                >
                  <span className="flex items-center gap-2 text-ink-2">
                    <span
                      className={`h-2 w-2 rounded-full ${
                        row.ok ? 'bg-ok' : 'bg-critical'
                      }`}
                    />
                    <span className="font-mono">{row.provider}</span>
                  </span>
                  <span className="text-ink-3">
                    {row.availability != null
                      ? `${row.availability}%`
                      : row.checks != null
                        ? `${row.checks} checks`
                        : '—'}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12.5px] text-ink-3">
              {t('No enrichment activity recorded yet.')}
            </p>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {[
          {
            icon: <ShieldCheck className="h-4 w-4" />,
            title: 'Deterministic scoring',
            text: 'Every indicator gets a reproducible 0–100 threat score from detection ratios, reputation and community verdicts.',
          },
          {
            icon: <Sparkles className="h-4 w-4" />,
            title: 'Evidence-based AI',
            text: 'AI interpretation is built exclusively from the normalized VirusTotal report — never from guesses.',
          },
          {
            icon: <BarChart3 className="h-4 w-4" />,
            title: 'Actionable history',
            text: 'Every analysis is persisted locally so you can search, filter and review findings over time.',
          },
        ].map((feature) => (
          <div
            key={feature.title}
            className="panel flex gap-3 px-4 py-4 md:px-5"
          >
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-surface-3 text-accent">
              {feature.icon}
            </span>
            <div>
              <p className="text-[13.5px] font-semibold text-ink">
                {t(feature.title)}
              </p>
              <p className="mt-1 text-[12.5px] leading-relaxed text-ink-2">
                {t(feature.text)}
              </p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {(
          [
            { value: 'DLL side-loading in persistent services', type: 'Hash' },
            { value: 'phishingmybank.com', type: 'Domain' },
            { value: 'https://secure-login.example.com/verify', type: 'URL' },
          ] as const
        ).map((quick) => (
          <button
            key={quick.value}
            type="button"
            onClick={() => quickAnalyze(quick.value)}
            className="panel group flex items-center justify-between gap-3 px-4 py-4 text-left transition-colors hover:bg-surface-2 md:px-5"
          >
            <div>
              <p className="font-mono text-[12.5px] text-ink group-hover:text-accent-strong">
                {quick.value}
              </p>
              <p className="mt-0.5 text-[11.5px] text-ink-3">
                {t('Quick-analyze as {type}', { type: t(quick.type) })}
              </p>
            </div>
            <ArrowRight className="h-4 w-4 shrink-0 text-ink-3 group-hover:text-accent" />
          </button>
        ))}
      </div>
    </div>
  )
}