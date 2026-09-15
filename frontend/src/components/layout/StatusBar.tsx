import { useHealth } from '../../hooks/useHealth'
import { cn } from '../../utils/cn'

interface StatusBarProps {
  className?: string
}

export function StatusBar({ className }: StatusBarProps) {
  const { data, isError, isPending } = useHealth()

  const state = isError
    ? { label: 'Unreachable', dotClass: 'bg-critical', pulse: false }
    : isPending
      ? { label: 'Checking…', dotClass: 'bg-ink-3', pulse: true }
      : data?.status === 'ok'
        ? { label: 'Operational', dotClass: 'bg-ok', pulse: false }
        : { label: 'Degraded', dotClass: 'bg-warn', pulse: false }

  return (
    <footer
      className={cn(
        'flex h-9 shrink-0 items-center justify-between border-t border-border bg-surface px-4 font-mono text-[11px] text-ink-3 md:px-6',
        className,
      )}
    >
      <span className="flex items-center gap-2">
        <span
          className={cn(
            'h-1.5 w-1.5 rounded-full',
            state.dotClass,
            state.pulse && 'animate-pulse',
          )}
        />
        API Status: {state.label}
      </span>
      {data && (
        <span className="hidden md:inline">
          ThreatLens v{data.version} · {data.environment}
        </span>
      )}
    </footer>
  )
}