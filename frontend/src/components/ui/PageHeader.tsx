import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  action?: ReactNode
}

export function PageHeader({ title, description, action }: PageHeaderProps) {
  return (
    <div className="mb-6 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-[22px] font-semibold tracking-tight text-ink md:text-2xl">
          {title}
        </h1>
        {description && (
          <p className="mt-1 text-[13.5px] text-ink-2">{description}</p>
        )}
      </div>
      {action}
    </div>
  )
}