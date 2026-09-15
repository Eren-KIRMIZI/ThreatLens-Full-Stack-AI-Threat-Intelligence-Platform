import type { DetectionEntry, ThreatLevel } from '../../types'
import { LEVEL_STYLE } from './level'

const CATEGORY_CLASS: Record<string, string> = {
  malicious: 'text-critical',
  suspicious: 'text-elevated',
  harmless: 'text-ok',
  undetected: 'text-ink-2',
  timeout: 'text-ink-3',
  'type-unsupported': 'text-ink-3',
}

interface DetectionTableProps {
  detections: DetectionEntry[]
  threatLevel?: ThreatLevel | null
}

export function DetectionTable({ detections, threatLevel }: DetectionTableProps) {
  if (detections.length === 0) {
    return (
      <p className="py-6 text-center text-[13px] text-ink-3">
        No per-engine detections were returned by VirusTotal.
      </p>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-border bg-surface">
            <th className="eyebrow px-4 py-2.5 font-normal">Engine</th>
            <th className="eyebrow px-4 py-2.5 font-normal">Verdict</th>
            <th className="eyebrow px-4 py-2.5 font-normal">Result</th>
            <th className="eyebrow px-4 py-2.5 font-normal">Method</th>
          </tr>
        </thead>
        <tbody>
          {detections.map((detection, index) => {
            const categoryClass =
              CATEGORY_CLASS[detection.category] ?? 'text-ink-2'
            return (
              <tr
                key={`${detection.engine}-${index}`}
                className="border-b border-border/60 transition-colors last:border-0 hover:bg-surface"
              >
                <td className="px-4 py-2.5 font-mono text-[12.5px] whitespace-nowrap text-ink">
                  {detection.engine}
                  {detection.category === 'malicious' && (
                    <span className="ml-2 rounded-sm border border-critical/30 bg-critical/10 px-1.5 py-0.5 text-[10px] font-semibold text-critical">
                      flag
                    </span>
                  )}
                </td>
                <td
                  className={`px-4 py-2.5 text-[12.5px] font-medium capitalize ${categoryClass}`}
                >
                  {detection.category}
                </td>
                <td className="px-4 py-2.5 font-mono text-[12px] text-ink-2">
                  {detection.result ?? '—'}
                </td>
                <td className="px-4 py-2.5 font-mono text-[11.5px] text-ink-3">
                  {detection.method ?? '—'}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {threatLevel && (
        <p className="px-4 pt-3 pb-1 text-[11px] text-ink-3">
          Verdict scale:{' '}
          <span className={LEVEL_STYLE[threatLevel]!.text}>
            {threatLevel.toUpperCase()}
          </span>{' '}
          from the evidence-based score rubric.
        </p>
      )}
    </div>
  )
}