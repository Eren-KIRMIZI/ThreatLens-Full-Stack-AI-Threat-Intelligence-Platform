import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  ArrowRight,
  Crosshair,
  Download,
  FileCode2,
  LayoutGrid,
  Network,
  Pin,
  RefreshCw,
  Sparkles,
  Tag,
} from 'lucide-react'
import { useNavigate, useParams } from 'react-router-dom'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { EmptyState } from '../components/ui/EmptyState'
import { Spinner } from '../components/ui/Spinner'
import { AnalysisResultView } from '../components/analysis/AnalysisResultView'
import { AiAnalysisView } from '../components/analysis/AiAnalysisView'
import { formatDate } from '../components/analysis/level'
import {
  analysisJsonUrl,
  enrichWithAi,
  reportPdfUrl,
  sigmaUrl,
  stixUrl,
  yaraUrl,
} from '../services/api'
import { useAnalysis } from '../hooks/useAnalyses'
import {
  useAddNote,
  useAddTag,
  useMitreAnalysis,
  useNotes,
  usePinned,
  useSetPinned,
  useTags,
} from '../hooks/useIntel'
import { useI18n } from '../i18n'

export function AnalysisDetail() {
  const { analysisId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { t } = useI18n()

  const analysis = useAnalysis(analysisId)
  const mitre = useMitreAnalysis(analysisId)
  const pinned = usePinned()
  const setPinned = useSetPinned(analysisId)
  const tags = useTags(analysisId)
  const addTag = useAddTag(analysisId)
  const notes = useNotes(analysisId)
  const addNote = useAddNote(analysisId)

  const [tagInput, setTagInput] = useState('')
  const [noteInput, setNoteInput] = useState('')

  const isPinned = (pinned.data ?? []).includes(analysisId)

  const enrich = useMutation({
    mutationFn: () => enrichWithAi(analysisId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['analysis', analysisId] })
    },
  })

  const error = analysis.error

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('Analysis Detail')}
        description={t('Full intelligence portfolio for a single investigation.')}
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              disabled={!analysisId}
              onClick={() => setPinned.mutate(!isPinned)}
            >
              <Pin
                className={`h-4 w-4 ${isPinned ? 'fill-current text-accent' : ''}`}
              />
              {isPinned ? t('Pinned') : t('Pin')}
            </Button>
            <Button
              variant="secondary"
              disabled={!analysis.data}
              onClick={() =>
                analysis.data &&
                navigate(`/analysis/${analysis.data.analysis_id}/graph`)
              }
            >
              <Network className="h-4 w-4" />
              {t('Graph')}
            </Button>
            <Button
              variant="secondary"
              disabled={!analysis.data}
              onClick={() =>
                analysis.data &&
                window.open(reportPdfUrl(analysis.data.analysis_id), '_blank')
              }
            >
              <Download className="h-4 w-4" />
              {t('PDF')}
            </Button>
            <Button variant="secondary" onClick={() => navigate(-1)}>
              <ArrowLeft className="h-4 w-4" />
              {t('Back')}
            </Button>
          </div>
        }
      />

      {analysis.isPending ? (
        <Panel>
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner className="h-5 w-5" />
            {t('Loading analysis…')}
          </div>
        </Panel>
      ) : error ? (
        <Panel>
          <EmptyState
            title={t('Analysis could not be loaded')}
            description={
              error instanceof Error ? error.message : t('Unknown error.')
            }
            action={
              <Button
                variant="secondary"
                onClick={() => navigate('/history')}
              >
                {t('Back to history')}
              </Button>
            }
          />
        </Panel>
      ) : (
        analysis.data && (
          <>
            <AnalysisResultView result={analysis.data} />

            <Panel
              eyebrow={t('ATT&CK mapping')}
              title={t('MITRE ATT&CK techniques')}
              action={
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => navigate(`/mitre?analysis=${analysisId}`)}
                >
                  <LayoutGrid className="h-3.5 w-3.5" />
                  {t('Open matrix')}
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              }
            >
              {mitre.isLoading ? (
                <div className="flex items-center gap-3 py-6 text-ink-2">
                  <Spinner />
                  {t('Mapping techniques…')}
                </div>
              ) : (mitre.data?.mapped ?? []).length === 0 ? (
                <div className="flex items-center gap-3 rounded-lg border border-dashed border-border-strong bg-surface px-4 py-6">
                  <Crosshair className="h-5 w-5 shrink-0 text-ink-3" />
                  <p className="text-[13px] leading-relaxed text-ink-2">
                    {t(
                      'No ATT&CK-correlating evidence in this analysis yet. The matrix view unlocks it the moment enrichment or AI mapping finds a technique.',
                    )}
                  </p>
                </div>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {(mitre.data?.mapped ?? []).map((item) => (
                    <span
                      key={`${item.source}-${item.id}`}
                      className="inline-flex items-center gap-1.5 rounded-md border border-border-strong bg-surface-3 px-2 py-1"
                      title={item.tactic}
                    >
                      <span
                        className={
                          item.source === 'ai'
                            ? 'font-mono text-[11px] text-violet-300'
                            : 'font-mono text-[11px] text-accent-strong'
                        }
                      >
                        {item.id}
                      </span>
                      <span className="max-w-[180px] truncate text-[11.5px] text-ink-2">
                        {item.name}
                      </span>
                      {item.source === 'ai' && (
                        <Sparkles className="h-3 w-3 text-violet-300" aria-label={t('AI')} />
                      )}
                    </span>
                  ))}
                </div>
              )}
            </Panel>

            <div className="grid gap-4 lg:grid-cols-2">
              <Panel eyebrow={t('Exports')} title={t('Take the intelligence with you')}>
                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant="secondary"
                    onClick={() =>
                      window.open(analysisJsonUrl(analysisId), '_blank')
                    }
                  >
                    <Download className="h-4 w-4" />
                    {t('JSON')}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => window.open(stixUrl(analysisId), '_blank')}
                  >
                    <FileCode2 className="h-4 w-4" />
                    {t('STIX 2.1')}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => window.open(yaraUrl(analysisId), '_blank')}
                  >
                    <FileCode2 className="h-4 w-4" />
                    {t('YARA')}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => window.open(sigmaUrl(analysisId), '_blank')}
                  >
                    <FileCode2 className="h-4 w-4" />
                    {t('Sigma')}
                  </Button>
                </div>
                <p className="mt-3 text-[12px] leading-relaxed text-ink-3">
                  {t(
                    'STIX bundles, YARA and Sigma rules are generated from the stored evidence — ready for your SIEM or detection pipeline.',
                  )}
                </p>
              </Panel>

              <Panel eyebrow={t('Analyst workspace')} title={t('Tags & notes')}>
                <div className="space-y-4">
                  <div>
                    <span className="eyebrow">{t('Tags')}</span>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {(tags.data ?? []).map((tag) => (
                        <span
                          key={tag}
                          className="rounded-md border border-border-strong bg-surface-3 px-2 py-0.5 text-[11.5px] font-medium text-ink-2"
                        >
                          {tag}
                        </span>
                      ))}
                      {(tags.data ?? []).length === 0 && (
                        <span className="text-[12px] text-ink-3">
                          {t('No tags yet.')}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 flex gap-2">
                      <input
                        value={tagInput}
                        onChange={(event) => setTagInput(event.target.value)}
                        placeholder={t('Add tag…')}
                        className="h-9 min-w-0 flex-1 rounded-lg border border-border bg-surface-3 px-3 text-[12.5px] text-ink focus:border-accent/60 focus:outline-none"
                      />
                      <Button
                        variant="secondary"
                        disabled={!tagInput.trim() || addTag.isPending}
                        onClick={() =>
                          addTag.mutate(tagInput.trim(), {
                            onSuccess: () => setTagInput(''),
                          })
                        }
                      >
                        <Tag className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <span className="eyebrow">{t('Notes')}</span>
                    <ul className="mt-2 space-y-2">
                      {(notes.data ?? []).map((note) => (
                        <li
                          key={note.id}
                          className="rounded-lg border border-border bg-surface px-3 py-2"
                        >
                          <p className="text-[12.5px] leading-relaxed text-ink-2">
                            {note.body}
                          </p>
                          <p className="mt-1 text-[11px] text-ink-3">
                            {note.author} · {formatDate(note.created_at)}
                          </p>
                        </li>
                      ))}
                      {(notes.data ?? []).length === 0 && (
                        <li className="text-[12px] text-ink-3">
                          {t('No analyst notes yet.')}
                        </li>
                      )}
                    </ul>
                    <textarea
                      value={noteInput}
                      onChange={(event) => setNoteInput(event.target.value)}
                      rows={2}
                      placeholder={t('Add a note for the team…')}
                      className="mt-2 w-full rounded-lg border border-border bg-surface-3 px-3 py-2 text-[12.5px] text-ink focus:border-accent/60 focus:outline-none"
                    />
                    <Button
                      variant="secondary"
                      className="mt-2"
                      disabled={!noteInput.trim() || addNote.isPending}
                      onClick={() =>
                        addNote.mutate(
                          { author: 'analyst', body: noteInput.trim() },
                          { onSuccess: () => setNoteInput('') },
                        )
                      }
                    >
                      {t('Add note')}
                    </Button>
                  </div>
                </div>
              </Panel>
            </div>

            {!analysis.data.ai && (
              <Panel
                eyebrow={t('AI interpretation')}
                title={t('Unlock the evidence-based narrative')}
                action={
                  <Button
                    onClick={() => enrich.mutate()}
                    disabled={enrich.isPending}
                  >
                    {enrich.isPending ? (
                      <>
                        <Spinner />
                        {t('Generating…')}
                      </>
                    ) : (
                      <>
                        <Sparkles className="h-4 w-4" />
                        {t('Generate AI analysis')}
                      </>
                    )}
                  </Button>
                }
              >
                <div className="flex items-center gap-3 rounded-lg border border-dashed border-border-strong bg-surface px-4 py-6">
                  <Sparkles className="h-5 w-5 shrink-0 text-accent" />
                  <p className="text-[13px] leading-relaxed text-ink-2">
                    {t(
                      'The AI interpretation explains tactics, capabilities, recommendations and correlations — strictly derived from the evidence already collected. Nothing is sent besides the normalized report.',
                    )}
                  </p>
                </div>
              </Panel>
            )}
          </>
        )
      )}

      {enrich.isError && (
        <Panel className="border-critical/40">
          <p className="text-[13px] text-ink-2">
            {t('AI generation failed:')}{' '}
            {enrich.error instanceof Error
              ? enrich.error.message
              : t('Unknown error.')}
          </p>
        </Panel>
      )}

      {enrich.isPending && (
        <div className="flex items-center gap-3 text-ink-2">
          <Spinner />
          <RefreshCw className="h-4 w-4 animate-spin text-ink-3" />
          <span className="text-[13px]">
            {t('Interpreting evidence with the configured model…')}
          </span>
        </div>
      )}

      {enrich.isSuccess && enrich.data && (
        <Panel
          eyebrow={t('AI interpretation')}
          title={t('Evidence-based analysis')}
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => enrich.mutate()}
              disabled={enrich.isPending}
            >
              <RefreshCw className="h-3.5 w-3.5" />
              {t('Regenerate')}
            </Button>
          }
        >
          <AiAnalysisView ai={enrich.data} />
        </Panel>
      )}
    </div>
  )
}