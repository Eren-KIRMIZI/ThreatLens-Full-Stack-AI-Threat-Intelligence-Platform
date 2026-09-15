import { Menu, Settings, Search } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'

import { cn } from '../../utils/cn'

const quickSearchSchema = z.object({
  query: z.string().trim().min(1, 'Enter an indicator to search'),
})

type QuickSearchValues = z.infer<typeof quickSearchSchema>

interface TopBarProps {
  onMenuClick: () => void
  className?: string
}

export function TopBar({ onMenuClick, className }: TopBarProps) {
  const navigate = useNavigate()
  const { register, handleSubmit } = useForm<QuickSearchValues>({
    resolver: zodResolver(quickSearchSchema),
  })

  const onSubmit = (values: QuickSearchValues) => {
    navigate(`/analyze?input=${encodeURIComponent(values.query)}`)
  }

  return (
    <header
      className={cn(
        'glass sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border px-4 md:px-6',
        className,
      )}
    >
      <button
        type="button"
        onClick={onMenuClick}
        className="grid h-9 w-9 place-items-center rounded-lg border border-border bg-surface-2 text-ink-2 transition-colors hover:text-ink md:hidden"
        aria-label="Toggle navigation"
      >
        <Menu className="h-4 w-4" />
      </button>

      <form
        onSubmit={handleSubmit(onSubmit)}
        className="relative hidden max-w-md flex-1 sm:block"
      >
        <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-ink-3" />
        <input
          {...register('query')}
          type="search"
          placeholder="Search hash, URL, domain or IP…"
          className="h-9 w-full rounded-lg border border-border bg-surface-2 pr-3 pl-9 text-[13px] text-ink placeholder:text-ink-3 focus:border-accent/60 focus:ring-2 focus:ring-accent/20 focus:outline-none"
        />
      </form>

      <div className="ml-auto flex items-center gap-2">
        <span className="hidden font-mono text-[11px] tracking-wider text-ink-3 md:inline">
          API v1
        </span>
        <button
          type="button"
          onClick={() => navigate('/settings')}
          className="grid h-9 w-9 place-items-center rounded-lg border border-border bg-surface-2 text-ink-2 transition-colors hover:text-ink"
          aria-label="Settings"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}