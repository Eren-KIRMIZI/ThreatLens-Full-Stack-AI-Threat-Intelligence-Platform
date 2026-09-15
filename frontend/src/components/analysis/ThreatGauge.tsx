import { LEVEL_STYLE } from './level'
import { LevelBadge } from './LevelBadge'
import type { ThreatLevel } from '../../types'

interface ThreatGaugeProps {
  score: number | null
  level: ThreatLevel | null
}

const SIZE = 132
const RADIUS = 52
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

export function ThreatGauge({ score, level }: ThreatGaugeProps) {
  const safe = score ?? 0
  const ratio = Math.max(0, Math.min(100, safe)) / 100
  const color = level ? LEVEL_STYLE[level]?.ring ?? '#5c6675' : '#5c6675'
  const offset = CIRCUMFERENCE * (1 - ratio)

  return (
    <div className="flex items-center gap-5">
      <div className="relative shrink-0" style={{ width: SIZE, height: SIZE }}>
        <svg width={SIZE} height={SIZE} className="-rotate-90">
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke="var(--color-surface-4)"
            strokeWidth="10"
          />
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 700ms ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-semibold tracking-tight text-ink tabular-nums">
            {score ?? '—'}
          </span>
          <span className="eyebrow mt-0.5">/ 100</span>
        </div>
      </div>
      <div>
        <p className="eyebrow mb-1.5">Threat score</p>
        <LevelBadge level={level} />
        <p className="mt-2 max-w-[190px] text-[12.5px] leading-relaxed text-ink-2">
          Deterministic, evidence-based verdict from the detection ratios.
        </p>
      </div>
    </div>
  )
}