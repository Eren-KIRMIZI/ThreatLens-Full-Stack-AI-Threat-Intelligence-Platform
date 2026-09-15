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
      <rect width="24" height="24" rx="6" className="fill-surface-3" />
      <circle cx="12" cy="12" r="7.5" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="12" cy="12" r="2.2" fill="currentColor" />
      <path
        d="M3 12h4.5M16.5 12H21"
        stroke="currentColor"
        strokeWidth="1.6"
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
      <span className="text-[15px] font-semibold tracking-tight text-ink">
        ThreatLens
      </span>
    </div>
  )
}