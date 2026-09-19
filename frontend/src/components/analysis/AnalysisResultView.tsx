import {
  Copy,
  FileSearch,
  Fingerprint,
  Sparkles,
} from 'lucide-react'
import { useState } from 'react'

import { Panel } from '../ui/Panel'
import { DetectionBar } from './DetectionBar'
import { DetectionTable } from './DetectionTable'
import { AiAnalysisView } from './AiAnalysisView'
import { MetadataView } from './MetadataView'
import { ThreatGauge } from './ThreatGauge'
import { LevelBadge } from './LevelBadge'
import { formatDate, shortId, statsTotal } from './level'
import { useCountUp } from '../../hooks/useCountUp'
import { useI18n } from '../../i18n'
import { cn } from '../../utils/cn'
import type { AnalysisResult } from '../../types'

function HeaderLine({ result }: { result: AnalysisResult }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(result.indicator)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      // Clipboard unavailable (non-secure context).
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="rounded-md border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11.5px] font-semibold tracking-wide text-accent-strong uppercase">
          {t(`type.${result.indicator_type}`)}
        </span>
        <LevelBadge level={result.threat_level} />
        <span className="font-mono text-[11.5px] text-ink-3">
          id: {shortId(result.analysis_id)}
        </span>
      </div>

      <div className="min-w-0">
        <button
          type="button"
          onClick={copy}
          title={t('Copy indicator')}
          className="group flex max-w-full items-start gap-1.5"
        >
          <span className="break-all font-mono text-[15px] leading-snug text-ink group-hover:text-accent-strong">
            {result.indicator}
          </span>
          <Copy className="mt-1 h-3.5 w-3.5 shrink-0 text-ink-3 group-hover:text-accent" />
        </button>
        <p className="mt-0.5 text-[12.5px] text-ink-2">
          {result.metadata.kind === 'file' && result.metadata.meaningful_name
            ? result.metadata.meaningful_name
            : t(`type.${result.indicator_type}`).toLowerCase()}
          {' '}· {t('Source:')} <span className="font-mono">{result.source}</span> ·
          {t('Analyzed {date}', { date: formatDate(result.analyzed_at) })}{' '}
          {copied && <span className="text-ok">{t('— copied')}</span>}
        </p>
      </div>
    </div>
  )
}

interface AnalysisResultViewProps {
  result: AnalysisResult
}

export function AnalysisResultView({ result }: AnalysisResultViewProps) {
  const { t } = useI18n()
  const malicious = useCountUp(result.stats.malicious)
  const total = statsTotal(result.stats)
  const ratio = total > 0 ? (result.stats.malicious / total) * 100 : 0
  const flagged = result.stats.malicious > 0

  return (
    <div className="space-y-4">
      <Panel eyebrow={t('Result')} className="relative overflow-hidden">
        <HeaderLine result={result} />
        <div className="mt-5 grid gap-6 border-t border-border/60 pt-5 lg:grid-cols-[auto_1fr]">
          <ThreatGauge score={result.threat_score} level={result.threat_level} />
          <div className="min-w-0">
            <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
              <span
                className={cn(
                  'text-[34px] leading-none font-semibold tracking-tight tabular-nums',
                  flagged ? 'text-critical' : 'text-ink',
                )}
              >
                {malicious}
              </span>
              <span className="font-mono text-[13px] text-ink-3">
                / {total} {t('engines')}
              </span>
              {flagged && <LevelBadge level={result.threat_level} />}
            </div>
            <p className="eyebrow mt-1.5 mb-2.5">
              {t('{count} engines flag this {type}', {
                count: result.stats.malicious,
                type: t(`type.${result.indicator_type}`),
              })}
            </p>
            <DetectionBar stats={result.stats} />
            <p className="mt-2 text-[12px] leading-relaxed text-ink-3">
              {flagged
                ? t('{pct}% of engines returned a malicious verdict.', {
                    pct: Math.round(ratio),
                  })
                : t(
                    'No engine flagged this indicator — consensus leans harmless.',
                  )}
            </p>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel
          eyebrow={t('Detection engines')}
          title={t('{count} engines', { count: result.detections.length })}
          className="lg:col-span-3"
          action={
            <Fingerprint className="h-4 w-4 text-ink-3" aria-hidden />
          }
        >
          <DetectionTable
            detections={result.detections}
            threatLevel={result.threat_level}
          />
        </Panel>

        <Panel
          eyebrow={t('Indicator profile')}
          title={t('Metadata')}
          className="lg:col-span-2"
          action={<FileSearch className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          <MetadataView metadata={result.metadata} />
        </Panel>
      </div>

      {result.ai && (
        <Panel
          eyebrow={t('AI interpretation')}
          title={t('Evidence-based analysis')}
          className="lg:col-span-5"
          action={
            <span className="flex items-center gap-1.5 text-[12px] text-ink-3">
              <Sparkles className="h-3.5 w-3.5" aria-hidden />
              {t('model-generated')}
            </span>
          }
        >
          <AiAnalysisView ai={result.ai} />
        </Panel>
      )}
    </div>
  )
}