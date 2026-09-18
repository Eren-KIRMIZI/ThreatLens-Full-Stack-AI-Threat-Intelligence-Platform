import { useMutation } from '@tanstack/react-query'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowUpRight, Radio, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { EmptyState } from '../components/ui/EmptyState'
import { Button } from '../components/ui/Button'
import {
  IndicatorForm,
  type AnalyzeMode,
  type AnalyzeSubmission,
} from '../components/analyze/IndicatorForm'
import { AnalysisResultView } from '../components/analysis/AnalysisResultView'
import { ApiRequestError, analyzeFile, analyzeIndicator } from '../services/api'
import { useI18n } from '../i18n'

const MODES: { value: AnalyzeMode; label: string }[] = [
  { value: 'FILE', label: 'File' },
  { value: 'HASH', label: 'Hash' },
  { value: 'URL', label: 'URL' },
  { value: 'DOMAIN', label: 'Domain' },
  { value: 'IP', label: 'IP' },
]

const MODE_HINTS: Record<AnalyzeMode, string> = {
  FILE: 'Upload a file to compute its hashes and submit it for analysis.',
  HASH: 'Enter a SHA256, SHA1 or MD5 hash to pull the existing report.',
  URL: 'Submit a URL for VirusTotal scan and detection.',
  DOMAIN: 'Retrieve domain reputation and related intelligence.',
  IP: 'Check IP reputation and associated indicators.',
}

export function Analyze() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { t } = useI18n()
  const [searchParams] = useSearchParams()

  const initialType = searchParams.get('type') as AnalyzeMode | null
  const initialInput = searchParams.get('input') ?? ''

  const [mode, setMode] = useState<AnalyzeMode>(
    initialType && MODES.some((m) => m.value === initialType)
      ? initialType
      : 'HASH',
  )
  const [input, setInput] = useState(initialType ? initialInput : '')

  const mutation = useMutation({
    mutationFn: ({ mode, value, file, ai }: AnalyzeSubmission) =>
      mode === 'FILE'
        ? analyzeFile(file!, ai)
        : analyzeIndicator(mode, value, ai),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['history'] })
    },
  })

  const error = mutation.error

  const handleSubmit = (submission: AnalyzeSubmission) => {
    setInput(submission.value)
    mutation.mutate(submission)
  }

  const result = mutation.data

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('Analyze an Indicator')}
        description={t(
          'Submit a file, hash, URL, domain or IP address for threat analysis.',
        )}
      />

      <Panel eyebrow={t('Input type')} title={t('Select indicator type')}>
        <SegmentedControl
          options={MODES.map((mode) => ({ ...mode, label: t(mode.label) }))}
          value={mode}
          onChange={(next) => {
            setMode(next)
            setInput('')
            mutation.reset()
          }}
          className="w-full sm:w-auto"
        />
        <p className="mt-3 text-[13px] text-ink-2">{t(MODE_HINTS[mode])}</p>

        <div className="mt-4 max-w-xl">
          <IndicatorForm
            key={mode}
            mode={mode}
            defaultInput={input}
            submitting={mutation.isPending}
            onSubmit={handleSubmit}
          />
        </div>
      </Panel>

      {error && (
        <Panel className="border-critical/40">
          <div className="flex items-start gap-3">
            <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-critical" />
            <div className="min-w-0">
              <p className="text-[14px] font-semibold text-ink">
                {t('Analysis failed')}
              </p>
              <p className="mt-0.5 text-[13px] text-ink-2">
                {error instanceof ApiRequestError
                  ? error.message
                  : t('An unexpected error occurred.')}
              </p>
              {error instanceof ApiRequestError && error.code && (
                <p className="mt-1 font-mono text-[11.5px] text-ink-3">
                  {error.code}
                </p>
              )}
            </div>
          </div>
        </Panel>
      )}

      {result ? (
        <>
          <div className="flex justify-end">
            <Button
              variant="secondary"
              onClick={() => navigate(`/analysis/${result.analysis_id}`)}
            >
              {t('Open full analysis page')}
              <ArrowUpRight className="h-4 w-4" />
            </Button>
          </div>
          <AnalysisResultView result={result} />
        </>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <Panel eyebrow={t('Coverage')}>
            <h3 className="mb-4 text-[14px] font-semibold text-ink">
              {t('What ThreatLens analyzes')}
            </h3>
            <ul className="space-y-3">
              {[
                {
                  label: 'Hash intelligence',
                  text: 'VirusTotal reports for SHA256, SHA1 and MD5.',
                },
                {
                  label: 'URL & Domain',
                  text: 'Reputation, detections and historical signals.',
                },
                {
                  label: 'IP reputation',
                  text: 'ASN, country and detection context.',
                },
                {
                  label: 'File submission',
                  text: 'Hashes computed and submitted on the server side.',
                },
                {
                  label: 'AI interpretation',
                  text: 'Evidence-based security narrative generated server-side.',
                },
              ].map((item) => (
                <li key={item.label} className="flex gap-3">
                  <Radio className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
                  <div>
                    <p className="text-[13.5px] font-medium text-ink">
                      {t(item.label)}
                    </p>
                    <p className="text-[12.5px] leading-relaxed text-ink-2">
                      {t(item.text)}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel eyebrow={t('Status')} title={t('Ready')}>
            <EmptyState
              icon={<Radio className="h-5 w-5" />}
              title={t('Analysis engine standby')}
              description={t(
                'Results render here as soon as the backend responds. Enable AI interpretation to include an evidence-based narrative.',
              )}
              className="py-10"
            />
          </Panel>
        </div>
      )}
    </div>
  )
}