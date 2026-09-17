import { useState } from 'react'
import {
  Bell,
  BellOff,
  Eye,
  Plus,
  RefreshCw,
  Trash2,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate } from '../components/analysis/level'
import {
  useAddWatchlistItem,
  useAlerts,
  useDeleteRule,
  useMarkAlertsSeen,
  useRemoveWatchlistItem,
  useRescanAll,
  useRescanOne,
  useRules,
  useSetWatchlistEnabled,
  useUpsertRule,
  useWatchlist,
} from '../hooks/useIntel'
import type { ThreatLevel } from '../types'

const TABS = [
  { value: 'items', label: 'Watchlist' },
  { value: 'rules', label: 'Alert rules' },
  { value: 'alerts', label: 'Alert inbox' },
]

const CONDITIONS = [
  { value: 'score_ge', label: 'Score ≥ threshold' },
  { value: 'engines_ge', label: 'Malicious engines ≥ threshold' },
  { value: 'new_detection', label: 'New detection since last scan' },
  { value: 'level_is', label: 'Level is critical' },
]

export function WatchlistPage() {
  const [tab, setTab] = useState('items')

  return (
    <div className="space-y-5">
      <PageHeader
        title="Watchlist & Alerts"
        description="Continuously re-check indicators and get notified when alert rules fire."
      />

      <SegmentedControl options={TABS} value={tab} onChange={setTab} />

      {tab === 'items' && <WatchlistItems />}
      {tab === 'rules' && <AlertRules />}
      {tab === 'alerts' && <AlertInbox />}
    </div>
  )
}

function WatchlistItems() {
  const navigate = useNavigate()
  const watchlist = useWatchlist()
  const add = useAddWatchlistItem()
  const remove = useRemoveWatchlistItem()
  const toggle = useSetWatchlistEnabled()
  const rescanAll = useRescanAll()
  const rescanOne = useRescanOne()

  const [value, setValue] = useState('')
  const [type, setType] = useState('HASH')

  const data = watchlist.data

  return (
    <div className="space-y-4">
      <Panel
        eyebrow="Monitor"
        title="Watched indicators"
        action={
          <Button
            variant="secondary"
            size="sm"
            disabled={rescanAll.isPending}
            onClick={() => rescanAll.mutate()}
          >
            {rescanAll.isPending ? (
              <Spinner />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            Rescan all
          </Button>
        }
      >
        <div className="mb-4 flex flex-wrap gap-2">
          <select
            value={type}
            onChange={(event) => setType(event.target.value)}
            className="h-10 rounded-lg border border-border bg-surface-3 px-2 text-[12.5px] text-ink"
          >
            {['HASH', 'URL', 'DOMAIN', 'IP'].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <input
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder="Add an indicator to monitor…"
            className="h-10 min-w-[220px] flex-1 rounded-lg border border-border bg-surface-3 px-3 font-mono text-[12.5px] text-ink focus:border-accent/60 focus:outline-none"
          />
          <Button
            disabled={!value.trim() || add.isPending}
            onClick={() =>
              add.mutate(
                { value: value.trim(), primary_type: type },
                { onSuccess: () => setValue('') },
              )
            }
          >
            <Plus className="h-4 w-4" />
            Add
          </Button>
        </div>

        {add.isError && (
          <p className="mb-3 text-[12.5px] text-critical">
            {add.error instanceof Error ? add.error.message : 'Could not add.'}
          </p>
        )}

        {watchlist.isLoading ? (
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner />
            Loading watchlist…
          </div>
        ) : data && data.items.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-border bg-surface">
                  <th className="eyebrow px-3 py-2.5 font-normal">Indicator</th>
                  <th className="eyebrow px-3 py-2.5 font-normal">Type</th>
                  <th className="eyebrow px-3 py-2.5 font-normal">Last check</th>
                  <th className="eyebrow px-3 py-2.5 font-normal">State</th>
                  <th className="eyebrow px-3 py-2.5 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-border/60 last:border-0"
                  >
                    <td className="max-w-[280px] px-3 py-2.5">
                      <span className="block truncate font-mono text-[12.5px] text-ink">
                        {item.value}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-[11px] font-semibold text-ink-2 uppercase">
                      {item.primary_type}
                    </td>
                    <td className="px-3 py-2.5 text-[12.5px] whitespace-nowrap text-ink-2">
                      {item.last_checked_at
                        ? formatDate(item.last_checked_at)
                        : 'Never'}
                    </td>
                    <td className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() =>
                          toggle.mutate({ id: item.id, enabled: !item.enabled })
                        }
                        className={`rounded-md border px-2 py-0.5 text-[11.5px] font-semibold ${
                          item.enabled
                            ? 'border-clean/30 bg-clean/12 text-clean'
                            : 'border-border bg-surface-3 text-ink-3'
                        }`}
                      >
                        {item.enabled ? 'Enabled' : 'Paused'}
                      </button>
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={rescanOne.isPending}
                          onClick={() => rescanOne.mutate(item.id)}
                        >
                          <RefreshCw className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-critical"
                          onClick={() => remove.mutate(item.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={<Eye className="h-5 w-5" />}
            title="Nothing watched yet"
            description="Add indicators to re-check them over time and trigger alerts."
            className="py-14"
          />
        )}

        {rescanOne.isSuccess && rescanOne.data && (
          <div className="mt-4 rounded-lg border border-border bg-surface px-3 py-2.5 text-[12.5px] text-ink-2">
            Rescanned <span className="font-mono">{rescanOne.data.value}</span> →
            score {rescanOne.data.threat_score ?? '—'} ·{' '}
            {rescanOne.data.alerts.length} alert
            {rescanOne.data.alerts.length === 1 ? '' : 's'} fired
            {rescanOne.data.analysis_id && (
              <Button
                variant="ghost"
                size="sm"
                className="ml-2"
                onClick={() =>
                  navigate(`/analysis/${rescanOne.data!.analysis_id}`)
                }
              >
                Open analysis
              </Button>
            )}
          </div>
        )}
      </Panel>
    </div>
  )
}

function AlertRules() {
  const rules = useRules()
  const upsert = useUpsertRule()
  const remove = useDeleteRule()

  const [name, setName] = useState('')
  const [condition, setCondition] = useState('score_ge')
  const [threshold, setThreshold] = useState(70)

  return (
    <Panel eyebrow="Detection logic" title="Alert rules">
      <div className="mb-4 grid gap-2 md:grid-cols-[1.4fr_1.4fr_auto_auto]">
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Rule name"
          className="h-10 rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink focus:border-accent/60 focus:outline-none"
        />
        <select
          value={condition}
          onChange={(event) => setCondition(event.target.value)}
          className="h-10 rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink focus:border-accent/60 focus:outline-none"
        >
          {CONDITIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <input
          type="number"
          min={0}
          max={100}
          value={threshold}
          onChange={(event) => setThreshold(Number(event.target.value))}
          className="h-10 w-24 rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink focus:border-accent/60 focus:outline-none"
        />
        <Button
          disabled={!name.trim() || upsert.isPending}
          onClick={() =>
            upsert.mutate(
              { name: name.trim(), condition, threshold, enabled: true },
              { onSuccess: () => setName('') },
            )
          }
        >
          <Plus className="h-4 w-4" />
          Add rule
        </Button>
      </div>

      {upsert.isError && (
        <p className="mb-3 text-[12.5px] text-critical">
          {upsert.error instanceof Error
            ? upsert.error.message
            : 'Could not save the rule.'}
        </p>
      )}

      {rules.isLoading ? (
        <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
          <Spinner />
          Loading rules…
        </div>
      ) : rules.data && rules.data.length > 0 ? (
        <ul className="divide-y divide-border/70">
          {rules.data.map((rule) => (
            <li
              key={rule.id}
              className="flex items-center justify-between gap-3 py-3"
            >
              <div>
                <p className="text-[13.5px] font-medium text-ink">{rule.name}</p>
                <p className="font-mono text-[11.5px] text-ink-3">
                  {rule.condition} · threshold {rule.threshold}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`rounded-md border px-2 py-0.5 text-[11.5px] font-semibold ${
                    rule.enabled
                      ? 'border-clean/30 bg-clean/12 text-clean'
                      : 'border-border bg-surface-3 text-ink-3'
                  }`}
                >
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-critical"
                  onClick={() => remove.mutate(rule.id)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState
          icon={<BellOff className="h-5 w-5" />}
          title="No rules configured"
          description="Add a rule to be alerted when watched indicators cross a threshold."
          className="py-12"
        />
      )}
    </Panel>
  )
}

function AlertInbox() {
  const navigate = useNavigate()
  const alerts = useAlerts()
  const markSeen = useMarkAlertsSeen()

  const data = alerts.data

  return (
    <Panel
      eyebrow="Notifications"
      title="Alert inbox"
      action={
        <Button
          variant="secondary"
          size="sm"
          disabled={markSeen.isPending}
          onClick={() => markSeen.mutate()}
        >
          Mark all seen
        </Button>
      }
    >
      {alerts.isLoading ? (
        <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
          <Spinner />
          Loading alerts…
        </div>
      ) : data && data.items.length > 0 ? (
        <ul className="divide-y divide-border/70">
          {data.items.map((alert) => (
            <li
              key={alert.id}
              className="flex items-start gap-3 py-3"
            >
              <span
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                  alert.seen ? 'bg-surface-4' : 'bg-critical'
                }`}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <LevelBadge level={alert.level as ThreatLevel | null} />
                  <span className="text-[13px] text-ink">{alert.message}</span>
                </div>
                <p className="mt-1 truncate font-mono text-[11.5px] text-ink-3">
                  {alert.indicator} · {formatDate(alert.triggered_at)}
                </p>
              </div>
              {alert.analysis_id && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => navigate(`/analysis/${alert.analysis_id}`)}
                >
                  Open
                </Button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState
          icon={<Bell className="h-5 w-5" />}
          title="No alerts yet"
          description="When a watched indicator trips a rule, the alert lands here."
          className="py-14"
        />
      )}
    </Panel>
  )
}