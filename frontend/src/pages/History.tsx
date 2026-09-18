import { Search, ShieldOff } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { EmptyState } from '../components/ui/EmptyState'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate, shortId, statsTotal } from '../components/analysis/level'
import { useHistoryPage } from '../hooks/useAnalyses'
import { useI18n } from '../i18n'
import type { HistoryFilter } from '../types'

const FILTERS: { value: HistoryFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'clean', label: 'Clean' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'malicious', label: 'Malicious' },
]

const PAGE_SIZE = 10

export function HistoryPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [filter, setFilter] = useState<HistoryFilter>('all')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const searchInput = useRef<HTMLInputElement>(null)
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current)
    debounce.current = setTimeout(() => {
      setPage(0)
    }, 300)
    return () => {
      if (debounce.current) clearTimeout(debounce.current)
    }
  }, [search])

  const history = useHistoryPage({
    filter,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const data = history.data
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('History')}
        description={t(
          'Everything ThreatLens has analyzed, searchable and filterable.',
        )}
      />

      <Panel eyebrow={t('Investigations')} title={t('Analysis history')}>
        <div className="mb-4 grid gap-3 lg:grid-cols-[auto_1fr]">
          <SegmentedControl
            options={FILTERS.map((filterOption) => ({
              ...filterOption,
              label: t(filterOption.label),
            }))}
            value={filter}
            onChange={(value) => {
              setFilter(value)
              setPage(0)
            }}
          />
          <div className="relative">
            <Search className="pointer-events-none absolute inset-y-0 left-3 m-auto h-4 w-4 text-ink-3" />
            <input
              ref={searchInput}
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={t('Search by indicator or name…')}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              className="focus-ring h-10 w-full rounded-lg border border-border bg-surface-3 pr-3 pl-9 font-mono text-[13px] text-ink placeholder:font-sans placeholder:text-ink-3 focus:border-accent/50"
            />
          </div>
        </div>

        {history.isLoading ? (
          <div className="flex items-center justify-center gap-3 py-16 text-ink-2">
            <Spinner className="h-5 w-5" />
            {t('Loading history…')}
          </div>
        ) : data && data.items.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-border bg-surface">
                    <th className="eyebrow px-4 py-2.5 font-normal">{t('Indicator')}</th>
                    <th className="eyebrow px-4 py-2.5 font-normal">{t('Type')}</th>
                    <th className="eyebrow px-4 py-2.5 font-normal">{t('Verdict')}</th>
                    <th className="eyebrow px-4 py-2.5 font-normal">{t('Score')}</th>
                    <th className="eyebrow px-4 py-2.5 font-normal">{t('Engines')}</th>
                    <th className="eyebrow px-4 py-2.5 font-normal">{t('Analyzed')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr
                      key={item.analysis_id}
                      className="cursor-pointer border-b border-border/60 transition-colors last:border-0 hover:bg-surface-2"
                      onClick={() => navigate(`/analysis/${item.analysis_id}`)}
                    >
                      <td className="max-w-[360px] px-4 py-3">
                        <span className="block truncate font-mono text-[12.5px] text-ink">
                          {item.indicator}
                        </span>
                        <span className="block truncate text-[11.5px] text-ink-3">
                          {item.meaningful_name ?? shortId(item.analysis_id)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded border border-border-strong bg-surface-3 px-2 py-0.5 text-[11px] font-semibold text-ink-2 uppercase">
                          {t(`type.${item.indicator_type}`)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <LevelBadge level={item.threat_level} />
                      </td>
                      <td className="px-4 py-3 font-mono text-[13px] tabular-nums text-ink">
                        {item.threat_score ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-[13px] text-ink-2">
                        {t('{count}/{total} flagged', {
                          count: item.detected_vendors,
                          total: statsTotal(item.stats),
                        })}
                      </td>
                      <td className="px-4 py-3 text-[12.5px] whitespace-nowrap text-ink-2">
                        {formatDate(item.analyzed_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4 flex items-center justify-between pt-2">
              <p className="text-[12.5px] text-ink-3">
                {t('Showing {from}–{to} of {total} results', {
                  from: data.offset + 1,
                  to: Math.min(data.offset + data.items.length, data.total),
                  total: data.total,
                })}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                >
                  {t('Previous')}
                </Button>
                <span className="w-16 text-center text-[12.5px] text-ink-2">
                  {page + 1} / {totalPages}
                </span>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={page + 1 >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  {t('Next')}
                </Button>
              </div>
            </div>
          </>
        ) : (
          <EmptyState
            icon={<ShieldOff className="h-5 w-5" />}
            title={t('No analyses found')}
            description={
              search || filter !== 'all'
                ? t(
                    'No results match the current filter. Try a different search or level.',
                  )
                : t('Run your first analysis to start building a history.')
            }
            className="py-14"
            action={
              <Button
                variant="secondary"
                onClick={() => navigate('/analyze')}
              >
                {t('Analyze an indicator')}
              </Button>
            }
          />
        )}
      </Panel>
    </div>
  )
}