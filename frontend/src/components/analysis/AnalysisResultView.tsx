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
import { formatDate, shortId } from './level'
import type { AnalysisResult, IndicatorType } from '../../types'

const TYPE_LABEL: Record<IndicatorType, string> = {
  FILE: 'File',
  HASH: 'Hash',
  URL: 'URL',
  DOMAIN: 'Domain',
  IP: 'IP',
}

function HeaderLine({ result }: { result: AnalysisResult }) {
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
          {TYPE_LABEL[result.indicator_type]}
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
          title="Copy indicator"
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
            : result.indicator_type.toLowerCase()}
          {' '}· Source: <span className="font-mono">{result.source}</span> ·
          Analyzed {formatDate(result.analyzed_at)}{' '}
          {copied && <span className="text-ok">— copied</span>}
        </p>
      </div>
    </div>
  )
}

interface AnalysisResultViewProps {
  result: AnalysisResult
}

export function AnalysisResultView({ result }: AnalysisResultViewProps) {
  return (
    <div className="space-y-4">
      <Panel eyebrow="Result" className="relative overflow-hidden">
        <HeaderLine result={result} />
        <div className="mt-5 grid gap-6 border-t border-border/60 pt-5 lg:grid-cols-[auto_1fr]">
          <ThreatGauge score={result.threat_score} level={result.threat_level} />
          <div className="min-w-0">
            <p className="eyebrow mb-2.5">Detection distribution</p>
            <DetectionBar stats={result.stats} />
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel
          eyebrow="Detection engines"
          title={`${result.detections.length} engines`}
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
          eyebrow="Indicator profile"
          title="Metadata"
          className="lg:col-span-2"
          action={<FileSearch className="h-4 w-4 text-ink-3" aria-hidden />}
        >
          <MetadataView metadata={result.metadata} />
        </Panel>
      </div>

      {result.ai && (
        <Panel
          eyebrow="AI interpretation"
          title="Evidence-based analysis"
          className="lg:col-span-5"
          action={
            <span className="flex items-center gap-1.5 text-[12px] text-ink-3">
              <Sparkles className="h-3.5 w-3.5" aria-hidden />
              model-generated
            </span>
          }
        >
          <AiAnalysisView ai={result.ai} />
        </Panel>
      )}
    </div>
  )
}