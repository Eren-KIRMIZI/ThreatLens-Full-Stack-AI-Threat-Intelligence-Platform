import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowRight,
  Boxes,
  Crosshair,
  FileCode2,
  Fingerprint,
  Globe,
  Globe2,
  Link2,
  Radar,
  Search,
  ShieldQuestion,
  X,
} from 'lucide-react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatRelative } from '../components/analysis/level'
import { useGlobalSearch } from '../hooks/useIntel'
import { guessIndicatorType } from '../utils/validate'
import { useI18n } from '../i18n'
import type { SearchResult, ThreatLevel } from '../types'
import { cn } from '../utils/cn'

const TYPE_ICONS: Record<string, typeof Fingerprint> = {
  HASH: Fingerprint,
  IP: Globe,
  URL: Link2,
  DOMAIN: Globe2,
  FILE: FileCode2,
}

const FILTERS = ['', 'HASH', 'IP', 'URL', 'DOMAIN', 'FILE'] as const

const SAMPLE_QUERIES = ['example.com', '1.1.1.1', 'Trojan']

function inferType(result: SearchResult): string | null {
  const upper = (result.subtitle ?? '').toUpperCase()
  if (['HASH', 'IP', 'URL', 'DOMAIN', 'FILE'].includes(upper)) return upper
  const guessed = guessIndicatorType(result.title)
  return guessed ?? null
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

export function Hunt() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [debounced, setDebounced] = useState('')
  const [filter, setFilter] = useState<string>('')

  useEffect(() => {
    const timeout = window.setTimeout(() => setDebounced(query.trim()), 300)
    return () => window.clearTimeout(timeout)
  }, [query])

  const search = useGlobalSearch(debounced)

  const results = useMemo(() => {
    if (!search.data) return []
    const all = search.data.results
    if (!filter) return all
    return all.filter((result) => inferType(result) === filter)
  }, [search.data, filter])

  const counts = useMemo(() => {
    const map: Record<string, number> = { HASH: 0, IP: 0, URL: 0, DOMAIN: 0, FILE: 0 }
    for (const result of search.data?.results ?? []) {
      const type = inferType(result)
      if (type) map[type] = (map[type] ?? 0) + 1
    }
    return map
  }, [search.data])

  const analyses = results.filter((result) => result.kind === 'analysis')
  const iocs = results.filter((result) => result.kind === 'ioc')

  const openResult = (result: SearchResult) => {
    if (result.kind === 'analysis') navigate(`/analysis/${result.id}`)
    else navigate(`/iocs?search=${encodeURIComponent(result.title)}`)
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('Threat Hunting')}
        description={t(
          'Search analyses and the IOC registry, then pivot into verdicts, graphs and reports.',
        )}
      />

      <Panel className="!p-4 md:!p-5">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-ink-3" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t('Hash, domain, IP, URL or file name…')}
            spellCheck={false}
            autoFocus
            className="focus-ring h-12 w-full rounded-xl border border-border bg-surface-3 pr-11 pl-10 text-[14px] text-ink placeholder:text-ink-3 focus:border-accent/50"
          />
          {query && (
            <button
              type="button"
              aria-label={t('Clear search')}
              onClick={() => setQuery('')}
              className="absolute top-1/2 right-3 -translate-y-1/2 rounded-md p-1 text-ink-3 hover:bg-surface-4 hover:text-ink"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          {FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setFilter(value)}
              className={cn(
                'focus-ring flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11.5px] font-medium transition-colors',
                filter === value
                  ? 'border-accent/50 bg-accent/10 text-accent-strong'
                  : 'border-border-strong bg-surface text-ink-2 hover:text-ink',
              )}
            >
              {value === '' ? t('All types') : t(value)}
              {value !== '' && (counts[value] ?? 0) > 0 && (
                <span className="font-mono text-[10px] tabular-nums opacity-70">
                  {counts[value]}
                </span>
              )}
            </button>
          ))}
        </div>
      </Panel>

      {debounced.length < 2 ? (
        <Panel>
          <EmptyState
            icon={<Crosshair className="h-5 w-5" />}
            title={t('Start a hunt')}
            description={t(
              'Type at least two characters. Every match links straight to its analysis or IOC profile.',
            )}
            className="py-12"
          />
          <div className="flex flex-wrap items-center justify-center gap-2">
            {SAMPLE_QUERIES.map((sample) => (
              <Button
                key={sample}
                variant="secondary"
                size="sm"
                onClick={() => setQuery(sample)}
              >
                {sample}
              </Button>
            ))}
          </div>
        </Panel>
      ) : search.isLoading ? (
        <Panel>
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner />
            {t('Hunting…')}
          </div>
        </Panel>
      ) : results.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<ShieldQuestion className="h-5 w-5" />}
            title={t('No matches')}
            description={t('Nothing matched the query and active filters.')}
            className="py-12"
          />
        </Panel>
      ) : (
        <>
          <p className="text-[12.5px] text-ink-3">
            {t('{count} results for “{query}”', {
              count: search.data?.total ?? results.length,
              query: debounced,
            })}
          </p>
          <div className="grid gap-4 lg:grid-cols-2">
            {[
              { kind: 'analysis', items: analyses, title: t('Analyses') },
              { kind: 'ioc', items: iocs, title: t('IOC registry') },
            ]
              .filter((group) => group.items.length > 0)
              .map((group) => (
                <Panel
                  key={group.kind}
                  eyebrow={group.title}
                  title={`${group.items.length} ${group.kind === 'analysis' ? t('analyses') : t('IOCs')}`}
                  action={
                    group.kind === 'ioc' ? (
                      <Boxes className="h-4 w-4 text-ink-3" aria-hidden />
                    ) : (
                      <Radar className="h-4 w-4 text-ink-3" aria-hidden />
                    )
                  }
                >
                  <ul className="divide-y divide-border/70">
                    {group.items.slice(0, 12).map((result) => {
                      const type = inferType(result)
                      const Icon = (type && TYPE_ICONS[type]) || Radar
                      return (
                        <li key={`${group.kind}-${result.id}`}>
                          <button
                            type="button"
                            onClick={() => openResult(result)}
                            className="group flex w-full items-center gap-3 py-3 text-left"
                          >
                            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-border bg-surface-3 text-accent">
                              <Icon className="h-4 w-4" />
                            </span>
                            <div className="min-w-0 flex-1">
                              <p className="truncate font-mono text-[12.5px] text-ink group-hover:text-accent-strong">
                                {result.title}
                              </p>
                              <p className="truncate text-[11px] text-ink-3">
                                {type ? t(type) : result.subtitle}
                                {result.analyzed_at
                                  ? ` · ${formatRelative(result.analyzed_at)}`
                                  : ''}
                              </p>
                            </div>
                            {result.level && (
                              <LevelBadge level={levelOf(result.level)} />
                            )}
                            {result.score != null && (
                              <span className="w-10 shrink-0 text-right font-mono text-[13px] tabular-nums text-ink">
                                {result.score}
                              </span>
                            )}
                            <ArrowRight className="h-4 w-4 shrink-0 text-ink-3 opacity-0 transition-opacity group-hover:opacity-100" />
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                </Panel>
              ))}
          </div>
        </>
      )}
    </div>
  )
}