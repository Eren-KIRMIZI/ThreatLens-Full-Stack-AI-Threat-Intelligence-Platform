import type { ReactNode } from 'react'

import { cn } from '../../utils/cn'

interface StatCardProps {
  label: string
  value: ReactNode
  hint?: string
  valueClass?: string
  className?: string
}

export function StatCard({
  label,
  value,
  hint,
  valueClass,
  className,
}: StatCardProps) {
  return (
    <div className={cn('panel px-4 py-4 md:px-5', className)}>
      <p className="eyebrow">{label}</p>
      <p
        className={cn(
          'mt-2.5 text-[28px] leading-none font-semibold tracking-tight text-ink tabular-nums',
          valueClass,
        )}
      >
        {value}
      </p>
      {hint && (
        <p className="mt-2 text-[12px] leading-relaxed text-ink-3">{hint}</p>
      )}
    </div>
  )
}