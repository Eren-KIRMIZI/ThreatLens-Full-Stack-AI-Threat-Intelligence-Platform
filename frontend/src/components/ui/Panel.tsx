import type { HTMLAttributes } from 'react'

import { cn } from '../../utils/cn'

interface PanelProps extends HTMLAttributes<HTMLDivElement> {
  title?: string
  eyebrow?: string
  action?: React.ReactNode
}

export function Panel({
  title,
  eyebrow,
  action,
  className,
  children,
  ...rest
}: PanelProps) {
  return (
    <section className={cn('panel', className)} {...rest}>
      {(title || eyebrow || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-border/70 px-4 py-3.5 md:px-5">
          <div className="min-w-0">
            {eyebrow && <div className="eyebrow mb-1">{eyebrow}</div>}
            {title && (
              <h3 className="truncate text-[14.5px] font-semibold tracking-tight text-ink">
                {title}
              </h3>
            )}
          </div>
          {action}
        </header>
      )}
      <div className="p-4 md:p-5">{children}</div>
    </section>
  )
}