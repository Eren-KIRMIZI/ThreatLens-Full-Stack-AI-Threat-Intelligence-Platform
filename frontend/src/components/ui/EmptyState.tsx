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
        'flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border-strong/70 bg-surface/60 px-6 py-12 text-center',
        className,
      )}
    >
      {icon && (
        <div className="grid h-12 w-12 place-items-center rounded-full border border-border-strong/70 bg-surface-2 text-ink-3 shadow-[inset_0_1px_0_rgb(255_255_255/0.04)]">
          {icon}
        </div>
      )}
      <div>
        <h3 className="text-[14.5px] font-semibold tracking-tight text-ink">
          {title}
        </h3>
        {description && (
          <p className="mx-auto mt-1 max-w-sm text-pretty text-[13px] leading-relaxed text-ink-2">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  )
}