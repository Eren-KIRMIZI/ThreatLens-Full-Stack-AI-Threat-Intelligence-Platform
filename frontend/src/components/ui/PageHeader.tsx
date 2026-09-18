import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  action?: ReactNode
}

export function PageHeader({ title, description, action }: PageHeaderProps) {
  return (
    <div className="mb-7 flex items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[24px] font-semibold tracking-tight text-ink md:text-[27px]">
          {title}
        </h1>
        {description && (
          <p className="mt-1.5 text-pretty text-[13.5px] leading-relaxed text-ink-2">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  )
}