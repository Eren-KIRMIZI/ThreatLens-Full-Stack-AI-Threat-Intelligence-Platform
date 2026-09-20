import { useQuery } from '@tanstack/react-query'
import {
  ChevronDown,
  Download,
  FileCode,
  FileJson,
  FileSpreadsheet,
  FileText,
  Shield,
  ShieldOff,
} from 'lucide-react'
import { useState } from 'react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { Spinner } from '../components/ui/Spinner'
import { EmptyState } from '../components/ui/EmptyState'
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate, shortId } from '../components/analysis/level'
import { ReportPreview } from '../components/reports/ReportPreview'
import {
  analysisJsonUrl,
  downloadExport,
  fetchReport,
  historyCsvUrl,
  reportPdfUrl,
  sigmaUrl,
  stixUrl,
  yaraUrl,
} from '../services/api'
import { useHistoryPage } from '../hooks/useAnalyses'
import { useI18n } from '../i18n'
import { cn } from '../utils/cn'

function ExportMenu({ analysisId }: { analysisId: string }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const items = [
    {
      label: t('Raw JSON'),
      icon: FileJson,
      path: analysisJsonUrl(analysisId),
      file: `threatlens-${analysisId.slice(0, 8)}.json`,
    },
    {
      label: t('STIX 2.1'),
      icon: Shield,
      path: stixUrl(analysisId),
      file: `threatlens-${analysisId.slice(0, 8)}-stix.json`,
    },
    {
      label: t('YARA rule'),
      icon: FileCode,
      path: yaraUrl(analysisId),
      file: `threatlens-${analysisId.slice(0, 8)}-rule.yar`,
    },
    {
      label: t('Sigma rule'),
      icon: FileCode,
      path: sigmaUrl(analysisId),
      file: `threatlens-${analysisId.slice(0, 8)}-rule.yml`,
    },
  ]

  const run = async (label: string, path: string, file: string) => {
    setBusy(label)
    setError(null)
    setOpen(false)
    try {
      await downloadExport(path, file)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Download failed.'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="relative">
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          setError(null)
          setOpen((value) => !value)
        }}
      >
        {t('Export')}
        <ChevronDown className="h-4 w-4" />
      </Button>

      {open && (
        <>
          <button
            type="button"
            aria-label={t('Close export menu')}
            className="fixed inset-0 z-30 cursor-default"
            onClick={() => setOpen(false)}
          />
          <div className="absolute right-0 top-full z-40 mt-2 w-56 rounded-lg border border-border-strong bg-surface-2 p-1 shadow-lg">
            <p className="px-2 pt-1 pb-1.5 text-[11px] font-semibold tracking-wide text-ink-3 uppercase">
              {shortId(analysisId)} · {t('Export')}
            </p>
            <ul className="space-y-0.5">
              {items.map((item) => {
                const Icon = item.icon
                return (
                  <li key={item.label}>
                    <button
                      type="button"
                      onClick={() => run(item.label, item.path, item.file)}
                      disabled={busy !== null}
                      className="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-[13px] text-ink transition-colors hover:bg-surface-3 disabled:opacity-50"
                    >
                      {busy === item.label ? (
                        <Spinner className="h-4 w-4" />
                      ) : (
                        <Icon className="h-4 w-4 text-ink-2" />
                      )}
                      {item.label}
                    </button>
                  </li>
                )
              })}
            </ul>
            {error && <p className="px-2 pt-1 pb-1.5 text-[11.5px] text-critical">{error}</p>}
          </div>
        </>
      )}
    </div>
  )
}

export function Reports() {
  const { t } = useI18n()
  const history = useHistoryPage({ filter: 'all', limit: 20 })
  const items = history.data?.items ?? []

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [csvBusy, setCsvBusy] = useState(false)
  // Fall back to the most recent analysis until the user picks one.
  const effectiveId = selectedId ?? items[0]?.analysis_id ?? null

  const report = useQuery({
    queryKey: ['report', effectiveId],
    queryFn: () => fetchReport(effectiveId!),
    enabled: Boolean(effectiveId),
  })

  const downloadPdf = () => {
    if (effectiveId) window.open(reportPdfUrl(effectiveId), '_blank')
  }

  const downloadHistory = async () => {
    if (items.length === 0) return
    setCsvBusy(true)
    try {
      await downloadExport(historyCsvUrl('all'), 'threatlens-history.csv')
    } catch (err) {
      if (err instanceof Error) window.alert(err.message)
    } finally {
      setCsvBusy(false)
    }
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
          action={
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="ghost"
                onClick={downloadHistory}
                disabled={items.length === 0 || csvBusy}
              >
                {csvBusy ? (
                  <Spinner className="h-4 w-4" />
                ) : (
                  <FileSpreadsheet className="h-4 w-4" />
                )}
                {t('CSV')}
              </Button>
              <FileText className="h-4 w-4 text-ink-3" aria-hidden />
            </div>
          }
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
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      onClick={downloadPdf}
                      disabled={!effectiveId}
                    >
                      <Download className="h-4 w-4" />
                      {t('Download PDF')}
                    </Button>
                    {effectiveId && <ExportMenu analysisId={effectiveId} />}
                  </div>
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