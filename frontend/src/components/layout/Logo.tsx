import { cn } from '../../utils/cn'

interface LogoProps {
  className?: string
}

/** ThreatLens brand mark — a lens focused on a signal. */
export function LogoMark({ className }: LogoProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className={cn('h-7 w-7', className)}
    >
      <rect
        width="24"
        height="24"
        rx="7"
        className="fill-surface-4"
        stroke="currentColor"
        strokeOpacity="0.35"
        strokeWidth="1"
      />
      <circle
        cx="12"
        cy="12"
        r="6"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeOpacity="0.9"
      />
      <circle cx="12" cy="12" r="1.8" fill="currentColor" />
      <path
        d="M8.2 4.6a7.6 7.6 0 0 0-3.6 3.6M15.8 4.6a7.6 7.6 0 0 1 3.6 3.6"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeOpacity="0.5"
        strokeLinecap="round"
      />
    </svg>
  )
}

export function Logo({ className }: LogoProps) {
  return (
    <div className={cn('flex items-center gap-2.5', className)}>
      <span className="text-accent">
        <LogoMark />
      </span>
      <span className="text-[15.5px] font-semibold tracking-tight text-ink">
        ThreatLens
      </span>
      <span className="mt-0.5 hidden rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[9.5px] tracking-wider text-ink-3 uppercase sm:inline">
        Intel
      </span>
    </div>
  )
}