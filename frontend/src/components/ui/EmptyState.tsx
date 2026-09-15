import type { ReactNode } from 'react'

import { cn } from '../../utils/cn'

interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description?: string
  action?: ReactNode
  className?: string
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border-strong bg-surface px-6 py-12 text-center',
        className,
      )}
    >
      {icon && (
        <div className="grid h-11 w-11 place-items-center rounded-lg border border-border bg-surface-3 text-ink-3">
          {icon}
        </div>
      )}
      <div>
        <h3 className="text-[14px] font-semibold text-ink">{title}</h3>
        {description && (
          <p className="mx-auto mt-1 max-w-sm text-[13px] leading-relaxed text-ink-2">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  )
}