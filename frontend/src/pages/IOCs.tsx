import { useState } from 'react'
import { Boxes, Search, ShieldOff, TrendingUp } from 'lucide-react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate, shortId } from '../components/analysis/level'
import { useIOC, useIOCs } from '../hooks/useIntel'
import { useI18n } from '../i18n'
import type { ThreatLevel } from '../types'

const TYPE_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'HASH', label: 'Hashes' },
  { value: 'URL', label: 'URLs' },
  { value: 'DOMAIN', label: 'Domains' },
  { value: 'IP', label: 'IPs' },
]

const PAGE_SIZE = 25

export function IOCsPage() {
  const { t } = useI18n()
  const [type, setType] = useState('all')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)

  const iocs = useIOCs({
    search: search.trim() || undefined,
    primary_type: type === 'all' ? undefined : type,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const data = iocs.data
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <div className="space-y-5">
<PageHeader
        title={t('IOC Inventory')}
        description={t(
          'Deduplicated indicators ThreatLens has observed, with observation counts and snapshot history.',
        )}
      />

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel
          eyebrow={t('Registry')}
          title={t('Distinct indicators')}
          className="lg:col-span-3"
        >
          <div className="mb-4 grid gap-3 lg:grid-cols-[auto_1fr]">
            <SegmentedControl
              options={TYPE_OPTIONS.map((option) => ({
                ...option,
                label: t(option.label),
              }))}
              value={type}
              onChange={(value) => {
                setType(value)
                setPage(0)
              }}
            />
            <div className="relative">
              <Search className="pointer-events-none absolute inset-y-0 left-3 m-auto h-4 w-4 text-ink-3" />
              <input
                type="search"
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value)
                  setPage(0)
                }}
                placeholder={t('Search indicators…')}
                spellCheck={false}
                className="focus-ring h-10 w-full rounded-lg border border-border bg-surface-3 pr-3 pl-9 font-mono text-[13px] text-ink placeholder:font-sans placeholder:text-ink-3 focus:border-accent/50"
              />
            </div>
          </div>

          {iocs.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-16 text-ink-2">
<Spinner className="h-5 w-5" />
              {t('Loading registry…')}
            </div>
          ) : data && data.items.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-border bg-surface">
<th className="eyebrow px-3 py-2.5 font-normal">{t('Indicator')}</th>
                      <th className="eyebrow px-3 py-2.5 font-normal">{t('Type')}</th>
                      <th className="eyebrow px-3 py-2.5 font-normal">{t('Verdict')}</th>
                      <th className="eyebrow px-3 py-2.5 font-normal">{t('Score')}</th>
                      <th className="eyebrow px-3 py-2.5 font-normal">{t('Seen')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((item) => (
                      <tr
                        key={item.id}
                        onClick={() => setSelected(item.value)}
                        className="cursor-pointer border-b border-border/60 transition-colors last:border-0 hover:bg-surface-2"
                      >
                        <td className="max-w-[280px] px-3 py-2.5">
                          <span className="block truncate font-mono text-[12.5px] text-ink">
                            {item.value}
                          </span>
                        </td>
<td className="px-3 py-2.5 text-[11px] font-semibold text-ink-2 uppercase">
                          {t(`type.${item.primary_type}`)}
                        </td>
                        <td className="px-3 py-2.5">
                          <LevelBadge level={item.latest_level as ThreatLevel | null} />
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[13px] tabular-nums text-ink">
                          {item.latest_score ?? '—'}
                        </td>
<td className="px-3 py-2.5 text-[12.5px] text-ink-2">
                          {item.observations}×
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="mt-4 flex items-center justify-between pt-2">
<p className="text-[12.5px] text-ink-3">
                  {t(
                    data.total === 1
                      ? '{count} indicator tracked'
                      : '{count} indicators tracked',
                    { count: data.total },
                  )}
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
              title={t('No indicators yet')}
              description={t(
                'Run an analysis and its indicator will be registered here automatically.',
              )}
              className="py-14"
            />
          )}
        </Panel>

        <div className="lg:col-span-2">
          {selected ? (
            <IOCDetailPanel value={selected} onClose={() => setSelected(null)} />
          ) : (
<Panel eyebrow={t('Timeline')} title={t('Indicator history')}>
              <EmptyState
                icon={<TrendingUp className="h-5 w-5" />}
                title={t('Select an indicator')}
                description={t(
                  'Pick a row to see its observation timeline and every stored analysis.',
                )}
                className="py-12"
              />
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}

function IOCDetailPanel({
  value,
  onClose,
}: {
  value: string
  onClose: () => void
}) {
  const detail = useIOC(value)
  const { t } = useI18n()

  return (
    <Panel
      eyebrow={t('Timeline')}
      title={t('Indicator history')}
      action={
        <Button variant="ghost" size="sm" onClick={onClose}>
          {t('Close')}
        </Button>
      }
    >
      {detail.isLoading ? (
        <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
          <Spinner />
          {t('Loading…')}
        </div>
      ) : detail.data ? (
        <div className="space-y-4">
          <div>
            <p className="font-mono text-[12.5px] break-all text-ink">{value}</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <LevelBadge level={detail.data.indicator.latest_level as ThreatLevel | null} />
              <span className="text-[12px] text-ink-3">
                {t(
                  detail.data.observations === 1
                    ? '{count} observation'
                    : '{count} observations',
                  { count: detail.data.observations },
                )}
              </span>
            </div>
          </div>

          <ul className="space-y-2">
            {detail.data.timeline.map((point) => (
              <li
                key={point.analysis_id}
                className="rounded-lg border border-border bg-surface px-3 py-2.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <LevelBadge level={point.threat_level as ThreatLevel | null} />
                  <span className="font-mono text-[13px] tabular-nums text-ink">
                    {point.threat_score ?? '—'}
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[11.5px] text-ink-3">
                  <span className="font-mono">{shortId(point.analysis_id)}</span>
                  <span>{formatDate(point.analyzed_at)}</span>
                </div>
<p className="mt-1 text-[11.5px] text-ink-3">
                  {point.malicious} {t('malicious')} · {point.suspicious} {t('suspicious')}
                </p>
              </li>
            ))}
          </ul>

          <Button
            variant="secondary"
            onClick={() =>
              window.open(`/analysis/${detail.data!.timeline[0]?.analysis_id}`, '_self')
            }
            disabled={!detail.data.timeline[0]}
            className="w-full"
          >
<Boxes className="h-4 w-4" />
            {t('Open latest analysis')}
          </Button>
        </div>
      ) : (
<EmptyState
          icon={<ShieldOff className="h-5 w-5" />}
          title={t('Not found')}
          description={t('This indicator has no stored snapshots.')}
          className="py-10"
        />
      )}
    </Panel>
  )
}
