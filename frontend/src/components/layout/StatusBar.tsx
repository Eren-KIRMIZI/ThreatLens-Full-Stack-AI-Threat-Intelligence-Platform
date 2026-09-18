import { useHealth } from '../../hooks/useHealth'
import { cn } from '../../utils/cn'
import { useI18n } from '../../i18n'

interface StatusBarProps {
  className?: string
}

export function StatusBar({ className }: StatusBarProps) {
  const { data, isError, isPending } = useHealth()
  const { t } = useI18n()

  const state = isError
    ? { label: t('Unreachable'), dotClass: 'bg-critical', pulse: false }
    : isPending
      ? { label: t('Checking…'), dotClass: 'bg-ink-3', pulse: true }
      : data?.status === 'ok'
        ? { label: t('Operational'), dotClass: 'bg-ok', pulse: false }
        : { label: t('Degraded'), dotClass: 'bg-warn', pulse: false }

  return (
    <footer
      className={cn(
        'flex h-9 shrink-0 items-center justify-between border-t border-border/80 bg-surface px-4 font-mono text-[11px] text-ink-3 md:px-6',
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
        <span className="text-ink-2">
          {t('API Status:')} {state.label}
        </span>
      </span>
      <span className="hidden items-center gap-1.5 md:inline-flex">
        <span className="h-1 w-1 rounded-full bg-ink-3" />
        <span>
          ThreatLens v{data?.version ?? '—'} · {data?.environment ?? '—'}
        </span>
      </span>
    </footer>
  )
}