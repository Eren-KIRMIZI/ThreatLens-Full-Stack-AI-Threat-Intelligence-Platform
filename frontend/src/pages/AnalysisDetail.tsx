import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Download, Network, RefreshCw, Sparkles } from 'lucide-react'
import { useNavigate, useParams } from 'react-router-dom'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { EmptyState } from '../components/ui/EmptyState'
import { Spinner } from '../components/ui/Spinner'
import { AnalysisResultView } from '../components/analysis/AnalysisResultView'
import { AiAnalysisView } from '../components/analysis/AiAnalysisView'
import { enrichWithAi, reportPdfUrl } from '../services/api'
import { useAnalysis } from '../hooks/useAnalyses'

export function AnalysisDetail() {
  const { analysisId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const analysis = useAnalysis(analysisId)

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
        title="Analysis Detail"
        description="Full intelligence portfolio for a single investigation."
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              disabled={!analysis.data}
              onClick={() =>
                analysis.data &&
                navigate(`/analysis/${analysis.data.analysis_id}/graph`)
              }
            >
              <Network className="h-4 w-4" />
              Graph
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
              PDF
            </Button>
            <Button variant="secondary" onClick={() => navigate(-1)}>
              <ArrowLeft className="h-4 w-4" />
              Back
            </Button>
          </div>
        }
      />

      {analysis.isPending ? (
        <Panel>
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner className="h-5 w-5" />
            Loading analysis…
          </div>
        </Panel>
      ) : error ? (
        <Panel>
          <EmptyState
            title="Analysis could not be loaded"
            description={
              error instanceof Error ? error.message : 'Unknown error.'
            }
            action={
              <Button
                variant="secondary"
                onClick={() => navigate('/history')}
              >
                Back to history
              </Button>
            }
          />
        </Panel>
      ) : (
        analysis.data && (
          <>
            <AnalysisResultView result={analysis.data} />
            {!analysis.data.ai && (
              <Panel
                eyebrow="AI interpretation"
                title="Unlock the evidence-based narrative"
                action={
                  <Button
                    onClick={() => enrich.mutate()}
                    disabled={enrich.isPending}
                  >
                    {enrich.isPending ? (
                      <>
                        <Spinner />
                        Generating…
                      </>
                    ) : (
                      <>
                        <Sparkles className="h-4 w-4" />
                        Generate AI analysis
                      </>
                    )}
                  </Button>
                }
              >
                <div className="flex items-center gap-3 rounded-lg border border-dashed border-border-strong bg-surface px-4 py-6">
                  <Sparkles className="h-5 w-5 shrink-0 text-accent" />
                  <p className="text-[13px] leading-relaxed text-ink-2">
                    The AI interpretation explains tactics, capabilities,
                    recommendations and correlations — strictly derived from
                    the evidence already collected. Nothing is sent besides the
                    normalized report.
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
            AI generation failed:{' '}
            {enrich.error instanceof Error
              ? enrich.error.message
              : 'Unknown error.'}
          </p>
        </Panel>
      )}

      {enrich.isPending && (
        <div className="flex items-center gap-3 text-ink-2">
          <Spinner />
          <RefreshCw className="h-4 w-4 animate-spin text-ink-3" />
          <span className="text-[13px]">
            Interpreting evidence with the configured model…
          </span>
        </div>
      )}

      {enrich.isSuccess && enrich.data && (
        <Panel
          eyebrow="AI interpretation"
          title="Evidence-based analysis"
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => enrich.mutate()}
              disabled={enrich.isPending}
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Regenerate
            </Button>
          }
        >
          <AiAnalysisView ai={enrich.data} />
        </Panel>
      )}
    </div>
  )
}