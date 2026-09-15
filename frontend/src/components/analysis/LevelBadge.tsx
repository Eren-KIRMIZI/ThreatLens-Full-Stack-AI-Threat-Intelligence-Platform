import { cn } from '../../utils/cn'
import { levelLabel, LEVEL_STYLE } from './level'
import type { ThreatLevel } from '../../types'

interface LevelBadgeProps {
  level: ThreatLevel | null | undefined
  className?: string
}

export function LevelBadge({ level, className }: LevelBadgeProps) {
  if (!level) {
    return (
      <span
        className={cn(
          'inline-flex items-center rounded-md border border-border bg-surface-3 px-2 py-0.5 text-[12px] font-semibold text-ink-2',
          className,
        )}
      >
        —
      </span>
    )
  }
  const style = LEVEL_STYLE[level]!
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[12px] font-semibold uppercase tracking-wide',
        style.text,
        style.bg,
        style.border,
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full bg-current')} />
      {levelLabel(level)}
    </span>
  )
}