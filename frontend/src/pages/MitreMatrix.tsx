import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  ArrowRight,
  CheckCircle2,
  Crosshair,
  LayoutGrid,
  ShieldQuestion,
  Sparkles,
} from 'lucide-react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { shortId } from '../components/analysis/level'
import { useHistoryPage } from '../hooks/useAnalyses'
import { useMitreAnalysis, useMitreCatalog } from '../hooks/useIntel'
import { useI18n } from '../i18n'
import type { MitreMappedTechnique, MitreTechnique } from '../types'
import { cn } from '../utils/cn'

export function MitreMatrix() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [searchParams] = useSearchParams()
  const paramId = searchParams.get('analysis') ?? undefined

  const history = useHistoryPage({ filter: 'all', limit: 40 })
  const catalog = useMitreCatalog()
  const [analysisId, setAnalysisId] = useState<string | undefined>(paramId)

  const effectiveId =
    analysisId ?? history.data?.items[0]?.analysis_id ?? undefined
  const mapping = useMitreAnalysis(effectiveId)

  const byTactic: Record<string, MitreTechnique[]> = {}
  for (const technique of catalog.data?.techniques ?? []) {
    const tactics = byTactic[technique.tactic]
    if (tactics) tactics.push(technique)
    else byTactic[technique.tactic] = [technique]
  }

  const tacticOrder = (() => {
    const display = new Set(Object.keys(byTactic))
    const ordered: string[] = []
    for (const name of Object.values(catalog.data?.tactics ?? {})) {
      if (display.has(name)) ordered.push(name)
    }
    for (const name of display) if (!ordered.includes(name)) ordered.push(name)
    return ordered
  })()

  const mapped = mapping.data?.mapped ?? []

  const mappedById = new Map<string, MitreMappedTechnique>()
  for (const item of mapped) mappedById.set(item.id, item)

  const tacticsCovered = new Set(mapped.map((item) => item.tactic)).size
  const aiCount = mapped.filter((item) => item.source === 'ai').length
  const evidenceCount = mapped.length - aiCount

  const groupedMapping: [string, MitreMappedTechnique[]][] = []
  for (const item of mapped) {
    let group = groupedMapping.find(([tactic]) => tactic === item.tactic)
    if (!group) {
      group = [item.tactic, []]
      groupedMapping.push(group)
    }
    group[1].push(item)
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('MITRE ATT&CK')}
        description={t(
          'Every stored analysis is mapped to tactics and techniques from its normalized evidence — corroborated with AI-disclosed techniques.',
        )}
      />

      <Panel title={t('Analysis to inspect')} eyebrow={t('Mapping target')}>
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={effectiveId ?? ''}
            onChange={(event) => setAnalysisId(event.target.value || undefined)}
            className="focus-ring h-10 min-w-[240px] flex-1 rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink focus:border-accent/50"
          >
            {(history.data?.items ?? []).length === 0 && (
              <option value="">{t('No analyses yet')}</option>
            )}
            {history.data?.items.map((item) => (
              <option key={item.analysis_id} value={item.analysis_id}>
                {`${item.indicator.substring(0, 42)} · ${item.threat_level ?? '—'}`}
              </option>
            ))}
          </select>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <SummaryChip label={t('Techniques')} value={mapped.length} />
            <SummaryChip label={t('Tactics')} value={tacticsCovered} />
            {mapped.length > 0 && (
              <SummaryChip
                label={t('AI corroborated')}
                value={aiCount > 0 ? `${aiCount}/${mapped.length}` : '—'}
              />
            )}
          </div>
        </div>
        {mapping.data?.indicator && (
          <p className="mt-3 truncate font-mono text-[12px] text-ink-3">
            {mapping.data.indicator} · {shortId(effectiveId ?? '')}
          </p>
        )}
      </Panel>

      {catalog.isLoading ? (
        <Panel>
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner />
            {t('Loading catalog…')}
          </div>
        </Panel>
      ) : catalog.isError || !catalog.data ? (
        <Panel>
          <EmptyState
            icon={<ShieldQuestion className="h-5 w-5" />}
            title={t('Catalog could not be loaded')}
            description={
              catalog.error instanceof Error
                ? catalog.error.message
                : t('Unknown error.')
            }
          />
        </Panel>
      ) : effectiveId ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <Panel
            eyebrow={t('Coverage heatmap')}
            title={t('Tactic matrix')}
            className="lg:col-span-2"
            action={<LayoutGrid className="h-4 w-4 text-ink-3" aria-hidden />}
          >
            {mapping.isLoading ? (
              <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
                <Spinner />
                {t('Mapping techniques…')}
              </div>
            ) : (
              <div className="overflow-x-auto pb-1">
                <div className="flex min-w-max gap-2">
                  {tacticOrder.map((tactic) => (
                    <div
                      key={tactic}
                      className="w-[150px] shrink-0 rounded-lg border border-border/70 bg-surface-2"
                    >
                      <div className="border-b border-border/70 px-2.5 py-2">
                        <p className="text-[11px] leading-tight font-semibold text-ink">
                          {t(tactic)}
                        </p>
                        <p className="mt-0.5 font-mono text-[9.5px] text-ink-3">
                          {byTactic[tactic]!.length}{' '}
                          {t(
                            byTactic[tactic]!.length === 1
                              ? 'technique'
                              : 'techniques',
                          )}
                        </p>
                      </div>
                      <div className="space-y-1 p-2">
                        {byTactic[tactic]!.map((technique) => {
                          const hit = mappedById.get(technique.id)
                          return (
                            <div
                              key={technique.id}
                              title={`${technique.id} · ${technique.name}${
                                hit ? ` · ${hit.source}` : ''
                              }`}
                              className={cn(
                                'rounded-md border px-2 py-1.5 transition-colors',
                                hit
                                  ? 'border-accent/50 bg-accent/10'
                                  : 'border-border bg-surface',
                              )}
                            >
                              <div className="flex items-center justify-between gap-1">
                                <span
                                  className={cn(
                                    'font-mono text-[10px] font-semibold',
                                    hit ? 'text-accent-strong' : 'text-ink-3',
                                  )}
                                >
                                  {technique.id}
                                </span>
                                {hit && (
                                  <CheckCircle2 className="h-3 w-3 shrink-0 text-accent-strong" />
                                )}
                              </div>
                              <p
                                className={cn(
                                  'mt-0.5 truncate text-[10px] leading-tight',
                                  hit ? 'text-ink' : 'text-ink-3',
                                )}
                              >
                                {technique.name}
                              </p>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Panel>

          <Panel
            eyebrow={t('Observed techniques')}
            title={`${mapped.length} ${t(
              mapped.length === 1 ? 'technique' : 'techniques',
            )}`}
            action={
              mapped.length > 0 ? (
                <div className="flex items-center gap-3 text-[11.5px] text-ink-3">
                  <span className="flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-accent" />
                    {evidenceCount} {t('evidence')}
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-violet-400" />
                    {aiCount} AI
                  </span>
                </div>
              ) : (
                <Sparkles className="h-4 w-4 text-ink-3" aria-hidden />
              )
            }
          >
            {mapping.isLoading ? (
              <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
                <Spinner />
                {t('Mapping techniques…')}
              </div>
            ) : mapped.length === 0 ? (
              <EmptyState
                icon={<ShieldQuestion className="h-5 w-5" />}
                title={t('Nothing mapped yet')}
                description={t(
                  'This analysis produced no ATT&CK-correlating evidence. Run an enrichment or ask the AI to reinterpret it.',
                )}
                className="py-10"
                action={
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => navigate(`/analysis/${effectiveId}`)}
                  >
                    {t('Open analysis')}
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Button>
                }
              />
            ) : (
              <ul className="space-y-3">
                {groupedMapping.map(([tactic, items]) => (
                  <li key={tactic}>
                    <p className="eyebrow mb-1.5">{t(tactic)}</p>
                    <div className="space-y-1.5">
                      {items.map((item) => (
                        <div
                          key={`${item.source}-${item.id}`}
                          className="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-3 py-2"
                        >
                          <span
                            className={cn(
                              'shrink-0 rounded px-1.5 py-0.5 font-mono text-[10.5px] font-semibold',
                              item.source === 'ai'
                                ? 'bg-violet-400/15 text-violet-300'
                                : 'bg-accent/15 text-accent-strong',
                            )}
                          >
                            {item.id}
                          </span>
                          <span className="min-w-0 flex-1 truncate text-[12.5px] text-ink">
                            {item.name ?? t('Unmapped technique')}
                          </span>
                          <span className="flex shrink-0 items-center gap-1 text-[10px] tracking-wide text-ink-3 uppercase">
                            {item.source === 'ai' ? (
                              <Sparkles className="h-3 w-3" />
                            ) : (
                              <Crosshair className="h-3 w-3" />
                            )}
                            {t(item.source)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      ) : (
        <Panel>
          <EmptyState
            icon={<LayoutGrid className="h-5 w-5" />}
            title={t('No analyses to map')}
            description={t(
              'Run an analysis first — the matrix will light up with its ATT&CK techniques.',
            )}
            action={
              <Button onClick={() => navigate('/analyze')}>
                {t('New analysis')}
                <ArrowRight className="h-4 w-4" />
              </Button>
            }
          />
        </Panel>
      )}
    </div>
  )
}

function SummaryChip({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-baseline gap-1.5 rounded-lg border border-border-strong bg-surface px-2.5 py-1.5">
      <span className="font-mono text-[14px] font-semibold text-ink tabular-nums">
        {value}
      </span>
      <span className="text-[10.5px] text-ink-3 uppercase tracking-wide">
        {label}
      </span>
    </div>
  )
}