import { useQuery } from '@tanstack/react-query'
import { Download, FileText, ShieldOff } from 'lucide-react'
import { useState } from 'react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate, shortId } from '../components/analysis/level'
import { ReportPreview } from '../components/reports/ReportPreview'
import { fetchReport, reportPdfUrl } from '../services/api'
import { useHistoryPage } from '../hooks/useAnalyses'
import { useI18n } from '../i18n'
import { cn } from '../utils/cn'

export function Reports() {
  const { t } = useI18n()
  const history = useHistoryPage({ filter: 'all', limit: 20 })
  const items = history.data?.items ?? []

  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Fall back to the most recent analysis until the user picks one.
  const effectiveId = selectedId ?? items[0]?.analysis_id ?? null

  const report = useQuery({
    queryKey: ['report', effectiveId],
    queryFn: () => fetchReport(effectiveId!),
    enabled: Boolean(effectiveId),
  })

  const download = () => {
    if (effectiveId) window.open(reportPdfUrl(effectiveId), '_blank')
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('Security Reports')}
        description={t(
          'Export professional, evidence-based PDF reports for any stored analysis.',
        )}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          eyebrow={t('Report library')}
          title={t('Available analyses')}
          action={<FileText className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          {history.isLoading ? (
            <div className="flex items-center justify-center gap-3 py-12 text-ink-2">
              <Spinner />
              {t('Loading…')}
            </div>
          ) : items.length === 0 ? (
            <EmptyState
              icon={<ShieldOff className="h-5 w-5" />}
              title={t('Nothing to report yet')}
              description={t(
                'Run an analysis first; every stored investigation can be exported as a PDF.',
              )}
              className="py-10"
            />
          ) : (
            <ul className="space-y-1">
              {items.map((item) => {
                const active = item.analysis_id === effectiveId
                return (
                  <li key={item.analysis_id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(item.analysis_id)}
                      className={cn(
                        'w-full rounded-lg border px-3 py-2.5 text-left transition-colors',
                        active
                          ? 'border-accent/50 bg-accent/10'
                          : 'border-transparent hover:bg-surface-2',
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 text-[10px] font-semibold text-ink-2 uppercase">
                          {t(`type.${item.indicator_type}`)}
                        </span>
                        <LevelBadge level={item.threat_level} />
                      </div>
                      <p className="mt-1.5 truncate font-mono text-[12.5px] text-ink">
                        {item.indicator}
                      </p>
                      <p className="mt-0.5 truncate text-[11px] text-ink-3">
                        {item.meaningful_name ?? shortId(item.analysis_id)} ·{' '}
                        {formatDate(item.created_at)}
                      </p>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </Panel>

        <div className="lg:col-span-2">
          {report.isPending ? (
            <Panel>
              <div className="flex items-center justify-center gap-3 py-16 text-ink-2">
                <Spinner className="h-5 w-5" />
                {t('Compiling report…')}
              </div>
            </Panel>
          ) : report.isError ? (
            <Panel>
              <EmptyState
                title={t('Report could not be generated')}
                description={
                  report.error instanceof Error
                    ? report.error.message
                    : t('Unknown error.')
                }
              />
            </Panel>
          ) : report.data ? (
            <>
              <Panel
                eyebrow={t('Preview')}
                title={`${report.data.title}`}
                action={
                  <Button
                    size="sm"
                    onClick={download}
                    disabled={!effectiveId}
                  >
                    <Download className="h-4 w-4" />
                    {t('Download PDF')}
                  </Button>
                }
                className="mb-0"
              >
                <ReportPreview report={report.data} />
              </Panel>
            </>
          ) : (
            <Panel>
              <EmptyState
                title={t('Select an analysis')}
                description={t(
                  'Pick an investigation from the library to preview and export its report.',
                )}
              />
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}