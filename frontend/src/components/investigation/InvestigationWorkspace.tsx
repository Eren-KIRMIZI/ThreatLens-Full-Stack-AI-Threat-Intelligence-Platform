import { useMemo, useState } from 'react'
import { ArrowLeft, FolderOpen, Layers, Plus, StickyNote, Trash2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useQueries } from '@tanstack/react-query'

import { useI18n } from '../../i18n'
import { cn } from '../../utils/cn'
import { LEVEL_ORDER, formatDate, shortId } from '../analysis/level'
import { LevelBadge } from '../analysis/LevelBadge'
import { Button } from '../ui/Button'
import { EmptyState } from '../ui/EmptyState'
import { Panel } from '../ui/Panel'
import { Spinner } from '../ui/Spinner'
import { fetchIOC, fetchMitreAnalysis } from '../../services/api'
import {
  useAddCampaignEvidence,
  useAddInvestigationNote,
  useCampaigns,
  useCreateCampaign,
  useDeleteCampaign,
  useDeleteCampaignEvidence,
  useDeleteInvestigationNote,
  useInvestigation,
  useInvestigationNotes,
  useUpdateCampaign,
  useUpdateCampaignEvidence,
  useUpdateInvestigation,
} from '../../hooks/useIntel'
import type {
  Campaign,
  CampaignEvidence,
  InvestigationSeverity,
  InvestigationStatus,
  ThreatLevel,
} from '../../types'

const STATUSES: InvestigationStatus[] = ['open', 'active', 'closed']
const SEVERITIES: InvestigationSeverity[] = ['low', 'medium', 'high', 'critical']

const CAMPAIGN_COLORS: Record<string, string> = {
  info: 'bg-accent',
  success: 'bg-success',
  elevated: 'bg-warn',
  high: 'bg-warning',
  critical: 'bg-danger',
  ink: 'bg-ink-2',
}

function campaignColor(color: string): string {
  return CAMPAIGN_COLORS[color] ?? 'bg-ink-2'
}

function evidenceIdentity(entry: {
  primary_type: string
  value: string
}): string {
  return `${entry.primary_type}:${entry.value}`
}

type AssignableEntry = {
  analysis_id: string | null
  primary_type: string
  value: string
}

export default function InvestigationWorkspace({
  caseId,
}: {
  caseId: string
}) {
  const { t } = useI18n()
  const navigate = useNavigate()

  const detail = useInvestigation(caseId)
  const notesQuery = useInvestigationNotes(caseId)
  const campaignsQuery = useCampaigns(caseId)

  const update = useUpdateInvestigation(caseId)
  const addNote = useAddInvestigationNote(caseId)
  const deleteNote = useDeleteInvestigationNote()
  const createCampaign = useCreateCampaign(caseId)
  const updateCampaign = useUpdateCampaign(caseId)
  const deleteCampaign = useDeleteCampaign(caseId)
  const addEvidence = useAddCampaignEvidence(caseId)
  const updateEvidence = useUpdateCampaignEvidence(caseId)
  const deleteEvidence = useDeleteCampaignEvidence(caseId)

  const [noteDraft, setNoteDraft] = useState('')
  const [campaignName, setCampaignName] = useState('')
  const [campaignColorValue, setCampaignColorValue] = useState('info')
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null)
  const [assignTargets, setAssignTargets] = useState<Record<string, string>>({})

  const item = detail.data

  if (detail.isLoading) {
    return (
      <div className="flex items-center justify-center gap-3 py-24 text-ink-2">
        <Spinner className="h-5 w-5" />
        {t('Loading case…')}
      </div>
    )
  }

  if (!item) {
    return (
      <Panel>
        <EmptyState title={t('Case not found')} className="py-12" />
      </Panel>
    )
  }

  const campaigns = campaignsQuery.data ?? []
  const notes = notesQuery.data ?? []
  const selectedCampaign =
    campaigns.find((campaign) => campaign.id === selectedCampaignId) ?? null

  const submitNote = () => {
    const value = noteDraft.trim()
    if (!value) return
    addNote.mutate(
      { author: 'analyst', body: value },
      { onSuccess: () => setNoteDraft('') },
    )
  }

  const submitCampaign = () => {
    const name = campaignName.trim()
    if (!name) return
    createCampaign.mutate(
      { name, color: campaignColorValue },
      {
        onSuccess: (created) => {
          setCampaignName('')
          setSelectedCampaignId(created.id)
        },
      },
    )
  }

  const assignItem = (campaignId: string, entry: AssignableEntry) => {
    addEvidence.mutate({
      campaignId,
      body: {
        analysis_id: entry.analysis_id,
        value: entry.value,
        primary_type: entry.primary_type,
      },
    })
  }

  return (
    <div className="space-y-5">
      <button
        type="button"
        onClick={() => navigate('/investigations')}
        className="inline-flex items-center gap-1.5 text-[12.5px] text-ink-3 transition-colors hover:text-ink-2"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        {t('Back to investigations')}
      </button>

      <Panel eyebrow={t('Investigation workspace')}>
        <div className="space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <EditableField
                as="input"
                value={item.title}
                onSave={(value) => {
                  if (value !== item.title) update.mutate({ title: value })
                }}
                className="w-full truncate bg-transparent text-[22px] font-semibold text-ink focus:outline-none"
              />
              <EditableField
                as="textarea"
                value={item.description ?? ''}
                onSave={(value) => {
                  if (value !== (item.description ?? '')) {
                    update.mutate({ description: value || null })
                  }
                }}
                placeholder={t('Add a description…')}
                className="mt-2 w-full resize-none bg-transparent text-[13px] leading-relaxed text-ink-2 focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                value={item.status}
                onChange={(event) =>
                  update.mutate({
                    status: event.target.value as InvestigationStatus,
                  })
                }
                className="h-8 rounded-md border border-border bg-surface-3 px-2 text-[12.5px] text-ink"
              >
                {STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {t(`status.${status}`)}
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
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {t(`severity.${severity}`)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 border-t border-border pt-4 sm:grid-cols-4">
            <MetricCell label={t('Indicators')} value={String(item.items.length)} />
            <MetricCell label={t('Campaigns')} value={String(campaigns.length)} />
            <MetricCell
              label={t('Evidence')}
              value={String(
                campaigns.reduce(
                  (sum, campaign) => sum + campaign.evidence.length,
                  0,
                ),
              )}
            />
            <MetricCell label={t('Notes')} value={String(notes.length)} />
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-3">
          <Panel eyebrow={t('Campaigns')} title={t('Campaign board')}>
            <div className="mb-3 flex flex-wrap gap-2 border-b border-border pb-3">
              <CampaignTab
                label={t('All evidence')}
                color="ink"
                count={campaigns.reduce(
                  (sum, campaign) => sum + campaign.evidence.length,
                  0,
                )}
                active={selectedCampaign === null}
                onClick={() => setSelectedCampaignId(null)}
              />
              {campaigns.map((campaign) => (
                <CampaignTab
                  key={campaign.id}
                  label={campaign.name}
                  color={campaign.color}
                  count={campaign.evidence.length}
                  active={selectedCampaign?.id === campaign.id}
                  onClick={() => setSelectedCampaignId(campaign.id)}
                />
              ))}
            </div>

            <div className="mb-4 flex gap-2">
              <input
                value={campaignName}
                onChange={(event) => setCampaignName(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    submitCampaign()
                  }
                }}
                placeholder={t('Campaign name…')}
                className="h-9 flex-1 rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink focus:border-accent/60 focus:outline-none"
              />
              <select
                value={campaignColorValue}
                onChange={(event) => setCampaignColorValue(event.target.value)}
                className="h-9 rounded-lg border border-border bg-surface-3 px-2 text-[12.5px] text-ink"
              >
                {Object.keys(CAMPAIGN_COLORS).map((color) => (
                  <option key={color} value={color}>
                    {color}
                  </option>
                ))}
              </select>
              <Button
                size="sm"
                disabled={!campaignName.trim() || createCampaign.isPending}
                onClick={submitCampaign}
              >
                <Plus className="h-3.5 w-3.5" />
                {t('Create')}
              </Button>
            </div>

            {selectedCampaign ? (
              <CampaignDetail
                campaign={selectedCampaign}
                onRename={(name) =>
                  updateCampaign.mutate({
                    campaignId: selectedCampaign.id,
                    body: { name },
                  })
                }
                onDelete={() => {
                  deleteCampaign.mutate(selectedCampaign.id, {
                    onSuccess: () => setSelectedCampaignId(null),
                  })
                }}
                onAddEvidence={(entry) => assignItem(selectedCampaign.id, entry)}
                onUpdateNote={(evidenceId, note) =>
                  updateEvidence.mutate({
                    campaignId: selectedCampaign.id,
                    evidenceId,
                    body: { note },
                  })
                }
                onRemoveEvidence={(evidenceId) =>
                  deleteEvidence.mutate({
                    campaignId: selectedCampaign.id,
                    evidenceId,
                  })
                }
              />
            ) : campaigns.length === 0 && item.items.length === 0 ? (
              <EmptyState
                icon={<FolderOpen className="h-5 w-5" />}
                title={t('No campaigns yet')}
                description={t(
                  'Group evidence into named campaigns to build the operation picture.',
                )}
                className="py-10"
              />
            ) : (
              <EmptyState
                icon={<Layers className="h-5 w-5" />}
                title={t('All evidence')}
                description={t(
                  'Pick a campaign to inspect its timeline, ATT&CK coverage and evidence.',
                )}
                className="py-10"
              />
            )}
          </Panel>
        </div>

        <div className="space-y-4 lg:col-span-2">
          <Panel eyebrow={t('Evidence register')} title={t('Case indicators')}>
            {item.items.length === 0 ? (
              <EmptyState
                icon={<FolderOpen className="h-5 w-5" />}
                title={t('No indicators linked yet.')}
                description={t('Add indicators from the case file page.')}
                className="py-8"
              />
            ) : (
              <ul className="space-y-2">
                {item.items.map((entry) => {
                  const identity = evidenceIdentity(entry)
                  const inCampaigns = campaigns.filter((campaign) =>
                    campaign.evidence.some(
                      (evidence) => evidenceIdentity(evidence) === identity,
                    ),
                  )
                  const assigned = assignTargets[identity]
                  const targetAlreadyAssigned = assigned
                    ? campaigns
                        .find((campaign) => campaign.id === assigned)
                        ?.evidence.some(
                          (evidence) =>
                            evidenceIdentity(evidence) === identity,
                        )
                    : false
                  return (
                    <li
                      key={entry.id}
                      className="rounded-lg border border-border bg-surface px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <p
                            className={cn(
                              'truncate font-mono text-[12px]',
                              inCampaigns.length === 0
                                ? 'text-ink-2'
                                : 'text-ink',
                            )}
                          >
                            {entry.value}
                          </p>
                          <p className="text-[11px] text-ink-3">
                            {t(`type.${entry.primary_type}`)}
                            {entry.analysis_id
                              ? ` · ${shortId(entry.analysis_id)}`
                              : ''}
                          </p>
                        </div>
                        {entry.analysis_id && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              navigate(`/analysis/${entry.analysis_id}`)
                            }
                          >
                            {t('Open')}
                          </Button>
                        )}
                      </div>
                      {inCampaigns.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {inCampaigns.map((campaign) => {
                            const record = campaign.evidence.find(
                              (evidence) =>
                                evidenceIdentity(evidence) === identity,
                            )
                            return (
                              <span
                                key={campaign.id}
                                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-3 px-2 py-0.5 text-[11px] text-ink-2"
                              >
                                <span
                                  className={cn(
                                    'h-1.5 w-1.5 rounded-full',
                                    campaignColor(campaign.color),
                                  )}
                                />
                                {campaign.name}
                                {record && (
                                  <button
                                    type="button"
                                    aria-label={t('Remove')}
                                    className="text-ink-3 transition-colors hover:text-critical"
                                    onClick={() =>
                                      deleteEvidence.mutate({
                                        campaignId: campaign.id,
                                        evidenceId: record.id,
                                      })
                                    }
                                  >
                                    <Trash2 className="h-3 w-3" />
                                  </button>
                                )}
                              </span>
                            )
                          })}
                        </div>
                      )}
                      <select
                        value={assigned ?? ''}
                        onChange={(event) => {
                          const campaignId = event.target.value
                          setAssignTargets((prev) => ({
                            ...prev,
                            [identity]: campaignId,
                          }))
                          if (campaignId && !targetAlreadyAssigned) {
                            assignItem(campaignId, entry)
                          }
                        }}
                        className="mt-2 h-7 w-full rounded-md border border-border bg-surface-3 px-2 text-[11.5px] text-ink-2"
                      >
                        <option value="">{t('Assign to campaign…')}</option>
                        {campaigns.map((campaign) => (
                          <option key={campaign.id} value={campaign.id}>
                            {campaign.name}
                          </option>
                        ))}
                      </select>
                    </li>
                  )
                })}
              </ul>
            )}
          </Panel>

          <Panel eyebrow={t('Analyst notes')} action={<StickyNote className="h-4 w-4 text-ink-3" />}>
            <div className="mb-3 flex gap-2">
              <input
                value={noteDraft}
                onChange={(event) => setNoteDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    submitNote()
                  }
                }}
                placeholder={t('Add a note…')}
                className="h-9 min-w-0 flex-1 rounded-lg border border-border bg-surface-3 px-3 text-[13px] text-ink focus:border-accent/60 focus:outline-none"
              />
              <Button
                size="sm"
                disabled={!noteDraft.trim() || addNote.isPending}
                onClick={submitNote}
              >
                <Plus className="h-3.5 w-3.5" />
              </Button>
            </div>
            {notes.length === 0 ? (
              <p className="py-4 text-center text-[12.5px] text-ink-3">
                {t('No notes yet.')}
              </p>
            ) : (
              <ul className="space-y-2.5">
                {notes.map((note) => (
                  <li
                    key={note.id}
                    className="rounded-lg border border-border bg-surface px-3 py-2"
                  >
                    <p className="whitespace-pre-wrap text-[12.5px] leading-relaxed text-ink">
                      {note.body}
                    </p>
                    <div className="mt-1.5 flex items-center justify-between gap-2">
                      <span className="text-[10.5px] text-ink-3">
                        {note.author} · {formatDate(note.created_at)}
                      </span>
                      <button
                        type="button"
                        aria-label={t('Delete')}
                        className="text-ink-3 transition-colors hover:text-critical"
                        onClick={() => deleteNote.mutate(note.id)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </div>
  )
}

function EditableField({
  as,
  value,
  onSave,
  placeholder,
  className,
}: {
  as: 'input' | 'textarea'
  value: string
  onSave: (value: string) => void
  placeholder?: string
  className?: string
}) {
  const commit = (
    next: string,
    normalize: (current: string) => string,
  ) => {
    const normalized = normalize(next)
    if (normalized !== value) onSave(normalized)
  }

  if (as === 'textarea') {
    return (
      <textarea
        key={`desc:${value}`}
        defaultValue={value}
        onBlur={(event) =>
          commit(event.currentTarget.value, (current) =>
            current.trim() ? current.trim() : '',
          )
        }
        rows={2}
        placeholder={placeholder}
        className={cn(
          'border-b border-transparent transition-colors focus:border-accent/50',
          className,
        )}
      />
    )
  }

  return (
    <input
      key={`title:${value}`}
      defaultValue={value}
      onBlur={(event) =>
        commit(event.currentTarget.value, (current) => current.trim())
      }
      placeholder={placeholder}
      className={cn(
        'border-b border-transparent transition-colors focus:border-accent/50',
        className,
      )}
    />
  )
}

function MetricCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface-2 px-3 py-2.5">
      <p className="font-mono text-[19px] font-semibold text-ink">{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-ink-3">{label}</p>
    </div>
  )
}

function CampaignTab({
  label,
  color,
  count,
  active,
  onClick,
}: {
  label: string
  color: string
  count: number
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[12.5px] transition-colors',
        active
          ? 'border-accent/40 bg-accent/10 text-ink'
          : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', campaignColor(color))} />
      {label}
      <span className="rounded-full bg-surface-3 px-1.5 font-mono text-[10.5px] text-ink-3">
        {count}
      </span>
    </button>
  )
}

function CampaignDetail({
  campaign,
  onRename,
  onDelete,
  onAddEvidence,
  onUpdateNote,
  onRemoveEvidence,
}: {
  campaign: Campaign
  onRename: (name: string) => void
  onDelete: () => void
  onAddEvidence: (entry: AssignableEntry) => void
  onUpdateNote: (evidenceId: string, note: string) => void
  onRemoveEvidence: (evidenceId: string) => void
}) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [nameDraft, setNameDraft] = useState(campaign.name)
  const [addValue, setAddValue] = useState('')
  const [addType, setAddType] = useState('HASH')

  const evidence = campaign.evidence

  const submitAdd = () => {
    const value = addValue.trim()
    if (!value) return
    onAddEvidence({ analysis_id: null, primary_type: addType, value })
    setAddValue('')
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={cn(
              'h-2 w-2 shrink-0 rounded-full',
              campaignColor(campaign.color),
            )}
          />
          <input
            value={nameDraft}
            onChange={(event) => setNameDraft(event.target.value)}
            onBlur={() => {
              const value = nameDraft.trim()
              if (value && value !== campaign.name) onRename(value)
            }}
            className="min-w-0 flex-1 truncate bg-transparent text-[15px] font-semibold text-ink focus:outline-none"
          />
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="text-critical"
          onClick={onDelete}
        >
          <Trash2 className="h-3.5 w-3.5" />
          {t('Delete')}
        </Button>
      </div>

      <CampaignTimeline evidences={evidence} />

      <div className="flex gap-2">
        <select
          value={addType}
          onChange={(event) => setAddType(event.target.value)}
          className="h-9 rounded-lg border border-border bg-surface-3 px-2 text-[12px] text-ink"
        >
          {['HASH', 'URL', 'DOMAIN', 'IP'].map((type) => (
            <option key={type} value={type}>
              {t(`type.${type}`)}
            </option>
          ))}
        </select>
        <input
          value={addValue}
          onChange={(event) => setAddValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') submitAdd()
          }}
          placeholder={t('Add indicator as evidence…')}
          className="h-9 min-w-0 flex-1 rounded-lg border border-border bg-surface-3 px-3 font-mono text-[12.5px] text-ink focus:border-accent/60 focus:outline-none"
        />
        <Button size="sm" disabled={!addValue.trim()} onClick={submitAdd}>
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>

      <CampaignMitre evidences={evidence} />

      <div>
        <p className="eyebrow mb-2">{t('Evidence')}</p>
        {evidence.length === 0 ? (
          <p className="text-[12.5px] text-ink-3">
            {t('No evidence assigned yet.')}
          </p>
        ) : (
          <ul className="space-y-2">
            {evidence.map((entry) => (
              <li
                key={entry.id}
                className="rounded-lg border border-border bg-surface px-3 py-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[12px] text-ink">
                      {entry.value}
                    </p>
                    <p className="text-[11px] text-ink-3">
                      {t(`type.${entry.primary_type}`)}
                      {entry.analysis_id ? ` · ${shortId(entry.analysis_id)}` : ''}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {entry.analysis_id && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/analysis/${entry.analysis_id}`)}
                      >
                        {t('Open')}
                      </Button>
                    )}
                    <button
                      type="button"
                      aria-label={t('Remove')}
                      className="p-1 text-ink-3 transition-colors hover:text-critical"
                      onClick={() => onRemoveEvidence(entry.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                <EvidenceNote
                  value={entry.note}
                  onSave={(note) => onUpdateNote(entry.id, note)}
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function EvidenceNote({
  value,
  onSave,
}: {
  value: string | null
  onSave: (note: string) => void
}) {
  const { t } = useI18n()
  const current = value ?? ''
  return (
    <input
      key={`note:${current}`}
      defaultValue={current}
      onBlur={(event) => {
        const next = event.currentTarget.value.trim()
        if (next !== current) onSave(next)
      }}
      placeholder={t('Evidence note…')}
      className="mt-1.5 h-7 w-full rounded-md border border-transparent bg-surface-2 px-2 text-[11.5px] text-ink-2 transition-colors placeholder:text-ink-3 focus:border-accent/50 focus:outline-none"
    />
  )
}

interface TimelineEvent {
  at: string
  value: string
  score: number | null
  level: ThreatLevel | null
  analysisId: string
}

function CampaignTimeline({ evidences }: { evidences: CampaignEvidence[] }) {
  const { t } = useI18n()
  const results = useQueries({
    queries: evidences.map((evidence) => ({
      queryKey: ['ioc', evidence.value],
      queryFn: () => fetchIOC(evidence.value),
      enabled: evidence.value.length > 0,
    })),
  })

  const events = useMemo<TimelineEvent[]>(() => {
    const list: TimelineEvent[] = []
    evidences.forEach((evidence, index) => {
      const data = results[index]?.data
      if (!data) return
      for (const snapshot of data.timeline) {
        list.push({
          at: snapshot.analyzed_at ?? '',
          value: evidence.value,
          score: snapshot.threat_score,
          level: LEVEL_ORDER.includes(snapshot.threat_level as ThreatLevel)
            ? (snapshot.threat_level as ThreatLevel)
            : null,
          analysisId: snapshot.analysis_id ?? '',
        })
      }
    })
    list.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0))
    return list
  }, [evidences, results])

  if (evidences.length === 0) {
    return (
      <p className="rounded-lg border border-border bg-surface px-3 py-4 text-[12.5px] text-ink-3">
        {t('No evidence assigned yet.')}
      </p>
    )
  }

  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-3">
      <p className="eyebrow mb-3">{t('Campaign timeline')}</p>
      {events.length === 0 ? (
        <p className="text-[12.5px] text-ink-3">
          {t('No telemetry snapshots yet for this evidence.')}
        </p>
      ) : (
        <div>
          {events.map((event, index) => (
            <div
              key={`${event.value}-${event.analysisId}-${event.at}`}
              className="relative flex gap-3 pb-4 last:pb-0"
            >
              {index < events.length - 1 && (
                <span className="absolute left-[5px] top-3 h-full w-px bg-border" />
              )}
              <span
                className={cn(
                  'relative z-10 mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full',
                  event.level ? levelDot(event.level) : 'bg-ink-3/50',
                )}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                  <p className="truncate font-mono text-[12px] text-ink">
                    {event.value}
                  </p>
                  <span className="font-mono text-[11px] text-ink-3">
                    {formatDate(event.at)}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[12px] text-ink">
                    {event.score == null ? '—' : event.score}
                    <span className="text-ink-3">/100</span>
                  </span>
                  <LevelBadge level={event.level} />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function levelDot(level: ThreatLevel): string {
  switch (level) {
    case 'clean':
      return 'bg-success'
    case 'suspicious':
      return 'bg-warn'
    case 'malicious':
      return 'bg-warning'
    case 'critical':
      return 'bg-danger'
  }
}

function CampaignMitre({ evidences }: { evidences: CampaignEvidence[] }) {
  const { t } = useI18n()
  const analysisIds = useMemo(() => {
    const ids = new Set<string>()
    for (const evidence of evidences) {
      if (evidence.analysis_id) ids.add(evidence.analysis_id)
    }
    return [...ids]
  }, [evidences])

  const results = useQueries({
    queries: analysisIds.map((id) => ({
      queryKey: ['mitre-analysis', id],
      queryFn: () => fetchMitreAnalysis(id),
    })),
  })

  const techniques = useMemo(() => {
    const counts = new Map<string, { count: number; name: string; tactic: string }>()
    results.forEach((result) => {
      const mapped = result.data?.mapped ?? []
      for (const technique of mapped) {
        const entry = counts.get(technique.id)
        if (entry) {
          entry.count += 1
        } else {
          counts.set(technique.id, {
            count: 1,
            name: technique.name ?? technique.id,
            tactic: technique.tactic,
          })
        }
      }
    })
    return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 6)
  }, [results])

  const hasLinked = useMemo(
    () => evidences.some((evidence) => evidence.analysis_id),
    [evidences],
  )

  if (!hasLinked) return null

  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-3">
      <p className="eyebrow mb-2">{t('ATT&CK coverage')}</p>
      {techniques.length === 0 ? (
        <p className="text-[12.5px] text-ink-3">{t('No MITRE mappings yet.')}</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {techniques.map((technique) => (
            <span
              key={`${technique.tactic}-${technique.name}`}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-3 px-2 py-1 font-mono text-[11px] text-ink-2"
            >
              <span className="rounded bg-accent/15 px-1 text-[10px] text-accent">
                {technique.count}
              </span>
              {technique.tactic.replace(/_/g, ' ')} · {technique.name}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}