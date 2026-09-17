import { useState } from 'react'
import { FolderOpen, Plus, Trash2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { formatDate, shortId } from '../components/analysis/level'
import {
  useAddInvestigationItem,
  useCreateInvestigation,
  useDeleteInvestigation,
  useInvestigation,
  useInvestigations,
  useUpdateInvestigation,
} from '../hooks/useIntel'
import type {
  InvestigationSeverity,
  InvestigationStatus,
} from '../types'

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'open', label: 'Open' },
  { value: 'active', label: 'Active' },
  { value: 'closed', label: 'Closed' },
]

const SEVERITIES: InvestigationSeverity[] = ['low', 'medium', 'high', 'critical']

const SEVERITY_CLASS: Record<InvestigationSeverity, string> = {
  low: 'text-clean',
  medium: 'text-elevated',
  high: 'text-high',
  critical: 'text-critical',
}

export function InvestigationsPage() {
  const [status, setStatus] = useState('all')
  const [selected, setSelected] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  const investigations = useInvestigations({
    status: status === 'all' ? undefined : status,
  })
  const create = useCreateInvestigation()

  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<InvestigationSeverity>('medium')
  const [description, setDescription] = useState('')

  const submit = () => {
    if (!title.trim()) return
    create.mutate(
      { title: title.trim(), description: description.trim() || null, severity },
      {
        onSuccess: (created) => {
          setTitle('')
          setDescription('')
          setSeverity('medium')
          setShowForm(false)
          setSelected(created.id)
        },
      },
    )
  }

  const data = investigations.data

  return (
    <div className="space-y-5">
      <PageHeader
        title="Investigations"
        description="Group indicators into cases, pivot across evidence and keep analyst notes."
        action={
          <Button onClick={() => setShowForm((value) => !value)}>
            <Plus className="h-4 w-4" />
            New case
          </Button>
        }
      />

      {showForm && (
        <Panel eyebrow="New case" title="Open an investigation">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="space-y-1.5">
              <span className="eyebrow">Title</span>
              <input
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                placeholder="Operation â€¦"
                className="h-10 w-full rounded-lg border border-border bg-surface-3 px-3 text-[13.5px] text-ink focus:border-accent/60 focus:ring-2 focus:ring-accent/20 focus:outline-none"
              />
            </label>
            <label className="space-y-1.5">
              <span className="eyebrow">Severity</span>
              <select
                value={severity}
                onChange={(event) =>
                  setSeverity(event.target.value as InvestigationSeverity)
                }
                className="h-10 w-full rounded-lg border border-border bg-surface-3 px-3 text-[13.5px] text-ink focus:border-accent/60 focus:outline-none"
              >
                {SEVERITIES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1.5 md:col-span-2">
              <span className="eyebrow">Description</span>
              <textarea
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                rows={3}
                placeholder="What are you investigating?"
                className="w-full rounded-lg border border-border bg-surface-3 px-3 py-2 text-[13.5px] text-ink focus:border-accent/60 focus:ring-2 focus:ring-accent/20 focus:outline-none"
              />
            </label>
          </div>
          <div className="mt-4 flex items-center gap-2">
            <Button onClick={submit} disabled={create.isPending || !title.trim()}>
              {create.isPending ? <Spinner /> : <Plus className="h-4 w-4" />}
              Create case
            </Button>
            <Button variant="ghost" onClick={() => setShowForm(false)}>
              Cancel
            </Button>
          </div>
        </Panel>
      )}

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel eyebrow="Cases" title="Investigation queue" className="lg:col-span-3">
          <SegmentedControl
            options={STATUS_OPTIONS}
            value={status}
            onChange={setStatus}
            className="mb-4"
          />

          {investigations.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-16 text-ink-2">
              <Spinner className="h-5 w-5" />
              Loading casesâ€¦
            </div>
          ) : data && data.items.length > 0 ? (
            <ul className="divide-y divide-border/70">
              {data.items.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    onClick={() => setSelected(item.id)}
                    className={`flex w-full items-center gap-3 py-3 text-left transition-colors ${
                      selected === item.id ? 'bg-surface-2' : 'hover:bg-surface'
                    }`}
                  >
                    <span
                      className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-border bg-surface-3 text-[11px] font-semibold uppercase ${SEVERITY_CLASS[item.severity]}`}
                    >
                      {item.severity.slice(0, 1)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13.5px] font-medium text-ink">
                        {item.title}
                      </p>
                      <p className="truncate text-[11.5px] text-ink-3">
                        {item.status} Â· {item.items.length} indicator
                        {item.items.length === 1 ? '' : 's'} Â·{' '}
                        {formatDate(item.updated_at ?? item.created_at)}
                      </p>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              icon={<FolderOpen className="h-5 w-5" />}
              title="No cases yet"
              description="Open a case to group related indicators and analyses."
              className="py-14"
            />
          )}
        </Panel>

        <div className="lg:col-span-2">
          {selected ? (
            <CaseDetailPanel caseId={selected} onClose={() => setSelected(null)} />
          ) : (
            <Panel eyebrow="Case file" title="Details">
              <EmptyState
                icon={<FolderOpen className="h-5 w-5" />}
                title="Select a case"
                description="Pick a case to manage its indicators, status and severity."
                className="py-12"
              />
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}

function CaseDetailPanel({
  caseId,
  onClose,
}: {
  caseId: string
  onClose: () => void
}) {
  const navigate = useNavigate()
  const detail = useInvestigation(caseId)
  const update = useUpdateInvestigation(caseId)
  const remove = useDeleteInvestigation()
  const addItem = useAddInvestigationItem(caseId)

  const [value, setValue] = useState('')
  const [type, setType] = useState('HASH')

  if (detail.isLoading) {
    return (
      <Panel>
        <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
          <Spinner />
          Loading caseâ€¦
        </div>
      </Panel>
    )
  }
  if (!detail.data) {
    return (
      <Panel>
        <EmptyState title="Case not found" className="py-10" />
      </Panel>
    )
  }

  const item = detail.data

  return (
    <Panel
      eyebrow="Case file"
      title={item.title}
      action={
        <Button variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={item.status}
            onChange={(event) =>
              update.mutate({ status: event.target.value as InvestigationStatus })
            }
            className="h-8 rounded-md border border-border bg-surface-3 px-2 text-[12.5px] text-ink"
          >
            {(['open', 'active', 'closed'] as InvestigationStatus[]).map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={item.severity}
            onChange={(event) =>
              update.mutate({
                severity: event.target.value as InvestigationSeverity,
              })
            }
            className="h-8 rounded-md border border-border bg-surface-3 px-2 text-[12.5px] text-ink"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <Button
            variant="ghost"
            size="sm"
            className="text-critical"
            onClick={() =>
              remove.mutate(caseId, { onSuccess: () => onClose() })
            }
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete
          </Button>
        </div>

        {item.description && (
          <p className="text-[13px] leading-relaxed text-ink-2">
            {item.description}
          </p>
        )}

        <div className="space-y-2">
          <span className="eyebrow">Add indicator</span>
          <div className="flex gap-2">
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
              placeholder="indicatorâ€¦"
              className="h-10 min-w-0 flex-1 rounded-lg border border-border bg-surface-3 px-3 font-mono text-[12.5px] text-ink focus:border-accent/60 focus:outline-none"
            />
            <Button
              size="md"
              disabled={!value.trim() || addItem.isPending}
              onClick={() =>
                addItem.mutate(
                  { value: value.trim(), primary_type: type },
                  { onSuccess: () => setValue('') },
                )
              }
            >
              <Plus className="h-4 w-4" />
            </Button>
          </div>
          {addItem.isError && (
            <p className="text-[12px] text-critical">
              {addItem.error instanceof Error
                ? addItem.error.message
                : 'Could not add the indicator.'}
            </p>
          )}
        </div>

        <div>
          <span className="eyebrow">Indicators</span>
          {item.items.length === 0 ? (
            <p className="mt-2 text-[12.5px] text-ink-3">
              No indicators linked yet.
            </p>
          ) : (
            <ul className="mt-2 space-y-2">
              {item.items.map((entry) => (
                <li
                  key={entry.id}
                  className="flex items-center justify-between gap-2 rounded-lg border border-border bg-surface px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[12px] text-ink">
                      {entry.value}
                    </p>
                    <p className="text-[11px] text-ink-3">
                      {entry.primary_type}
                      {entry.analysis_id
                        ? ` Â· ${shortId(entry.analysis_id)}`
                        : ''}
                    </p>
                  </div>
                  {entry.analysis_id && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigate(`/analysis/${entry.analysis_id}`)}
                    >
                      Open
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="flex items-center gap-2 border-t border-border pt-3">
          <span
            className={`text-[12px] font-semibold uppercase ${SEVERITY_CLASS[item.severity]}`}
          >
            {item.severity}
          </span>
          <span className="text-[11.5px] text-ink-3">
            opened {formatDate(item.created_at)}
          </span>
        </div>
      </div>
    </Panel>
  )
}
