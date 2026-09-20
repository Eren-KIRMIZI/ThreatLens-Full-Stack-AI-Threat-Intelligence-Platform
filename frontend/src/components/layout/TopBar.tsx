import { Menu, Settings, Search, Command } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'

import { cn } from '../../utils/cn'
import { useI18n } from '../../i18n'
import { LanguageToggle } from './LanguageToggle'
import { useCommandPalette } from '../command/commandContext'

type QuickSearchValues = { query: string }

interface TopBarProps {
  onMenuClick: () => void
  className?: string
}

export function TopBar({ onMenuClick, className }: TopBarProps) {
  const navigate = useNavigate()
  const { t } = useI18n()
  const { open } = useCommandPalette()

  const quickSearchSchema = z.object({
    query: z.string().trim().min(1, t('Enter an indicator to search')),
  })

  const { register, handleSubmit } = useForm<QuickSearchValues>({
    resolver: zodResolver(quickSearchSchema),
  })

  const onSubmit = (values: QuickSearchValues) => {
    navigate(`/analyze?input=${encodeURIComponent(values.query)}`)
  }

  return (
    <header
      className={cn(
        'glass sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border/80 px-4 md:px-6',
        className,
      )}
    >
      <button
        type="button"
        onClick={onMenuClick}
        className="focus-ring grid h-9 w-9 place-items-center rounded-lg border border-border bg-surface-2 text-ink-2 transition-colors hover:text-ink md:hidden"
        aria-label={t('Toggle navigation')}
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
          placeholder={t('Search hash, URL, domain or IP…')}
          className="focus-ring h-9 w-full rounded-lg border border-border bg-surface-2 pr-3 pl-9 text-[13px] text-ink shadow-[inset_0_1px_0_rgb(0_0_0/0.25)] placeholder:text-ink-3 focus:border-accent/50"
        />
      </form>

      <div className="ml-auto flex items-center gap-2.5">
        <button
          type="button"
          onClick={open}
          className="focus-ring flex h-9 items-center gap-2 rounded-lg border border-border bg-surface-2 px-2.5 text-ink-2 transition-colors hover:text-ink"
          aria-label={t('Command palette')}
        >
          <Command className="h-4 w-4" />
          <kbd className="hidden rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-ink-3 sm:inline">
            ⌘K
          </kbd>
        </button>
        <LanguageToggle />
        <span className="hidden font-mono text-[11px] tracking-wider text-ink-3 md:inline">
          API v1
        </span>
        <button
          type="button"
          onClick={() => navigate('/settings')}
          className="focus-ring grid h-9 w-9 place-items-center rounded-lg border border-border bg-surface-2 text-ink-2 transition-colors hover:text-ink"
          aria-label={t('Settings')}
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}