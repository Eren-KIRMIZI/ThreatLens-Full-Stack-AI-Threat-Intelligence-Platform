import type { DetectionStats } from '../../types'

interface DetectionBarProps {
  stats: DetectionStats
}

const SEGMENTS: {
  key: keyof DetectionStats
  label: string
  className: string
}[] = [
  { key: 'malicious', label: 'Malicious', className: 'bg-critical' },
  { key: 'suspicious', label: 'Suspicious', className: 'bg-elevated' },
  { key: 'undetected', label: 'Undetected', className: 'bg-surface-4' },
  { key: 'harmless', label: 'Harmless', className: 'bg-ok' },
  { key: 'timeout', label: 'Timeout', className: 'bg-ink-3' },
]

export function DetectionBar({ stats }: DetectionBarProps) {
  const total = Math.max(
    1,
    stats.malicious +
      stats.suspicious +
      stats.undetected +
      stats.harmless +
      stats.timeout,
  )

  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-4">
        {SEGMENTS.map((segment) => {
          const width = (stats[segment.key] / total) * 100
          if (width <= 0) return null
          return (
            <div
              key={segment.key}
              className={segment.className}
              style={{ width: `${width}%` }}
              title={`${segment.label}: ${stats[segment.key]}`}
            />
          )
        })}
      </div>
      <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5">
        {SEGMENTS.map((segment) => (
          <div
            key={segment.key}
            className="flex items-center gap-1.5 text-[12px] text-ink-2"
          >
            <span className={`h-2 w-2 rounded-sm ${segment.className}`} />
            <span>{segment.label}</span>
            <span className="font-semibold text-ink tabular-nums">
              {stats[segment.key]}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}