import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import {
  ArrowRight,
  BellRing,
  Boxes,
  CornerDownLeft,
  Crosshair,
  FileText,
  FolderOpen,
  History,
  LayoutDashboard,
  LayoutGrid,
  Radar,
  Search,
  Settings2,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import { useI18n } from '../../i18n'
import { cn } from '../../utils/cn'
import { CommandPaletteContext } from './commandContext'

interface CommandItem {
  id: string
  label: string
  alias?: string
  icon: LucideIcon
  group: string
  hint?: string
  run: () => void
}

interface CommandPaletteProviderProps {
  children: ReactNode
}

export function CommandPaletteProvider({
  children,
}: CommandPaletteProviderProps) {
  const navigate = useNavigate()
  const [isOpen, setIsOpen] = useState(false)

  const open = useCallback(() => setIsOpen(true), [])
  const close = useCallback(() => setIsOpen(false), [])

  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setIsOpen((prev) => !prev)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const value = useMemo(
    () => ({ isOpen, open, close }),
    [isOpen, open, close],
  )

  return (
    <CommandPaletteContext.Provider value={value}>
      {children}
      {isOpen && <CommandsPanel navigate={navigate} close={close} />}
    </CommandPaletteContext.Provider>
  )
}

function buildCommands(navigate: ReturnType<typeof useNavigate>): CommandItem[] {
  const nav: CommandItem[] = [
    { id: 'nav-dashboard', label: 'Dashboard', icon: LayoutDashboard, group: 'Navigate', run: () => navigate('/') },
    { id: 'nav-analyze', label: 'Analyze', icon: Radar, group: 'Navigate', run: () => navigate('/analyze') },
    { id: 'nav-hunt', label: 'Threat Hunting', icon: Crosshair, group: 'Navigate', run: () => navigate('/hunt') },
    { id: 'nav-iocs', label: 'IOC Inventory', icon: Boxes, group: 'Navigate', run: () => navigate('/iocs') },
    { id: 'nav-history', label: 'History', icon: History, group: 'Navigate', run: () => navigate('/history') },
    { id: 'nav-watchlist', label: 'Watchlist', icon: BellRing, group: 'Navigate', run: () => navigate('/watchlist') },
    { id: 'nav-investigations', label: 'Investigations', icon: FolderOpen, group: 'Navigate', run: () => navigate('/investigations') },
    { id: 'nav-mitre', label: 'MITRE ATT&CK', icon: LayoutGrid, group: 'Navigate', run: () => navigate('/mitre') },
    { id: 'nav-reports', label: 'Reports', icon: FileText, group: 'Navigate', run: () => navigate('/reports') },
    { id: 'nav-settings', label: 'Settings', icon: Settings2, group: 'Navigate', run: () => navigate('/settings') },
  ]
  const actions: CommandItem[] = [
    {
      id: 'act-analyze',
      label: 'Analyze an indicator',
      alias: 'hash url domain ip scan',
      icon: Radar,
      group: 'Actions',
      run: () => navigate('/analyze'),
    },
    {
      id: 'act-hunt',
      label: 'Hunt indicators',
      alias: 'search ioc query',
      icon: Crosshair,
      group: 'Actions',
      run: () => navigate('/hunt'),
    },
    {
      id: 'act-investigation',
      label: 'New investigation',
      alias: 'case open incident',
      icon: FolderOpen,
      group: 'Actions',
      run: () => navigate('/investigations'),
    },
    {
      id: 'act-watchlist',
      label: 'Manage watchlist',
      alias: 'alerts monitor',
      icon: BellRing,
      group: 'Actions',
      run: () => navigate('/watchlist'),
    },
    {
      id: 'act-report',
      label: 'Generate report',
      alias: 'pdf export sigma yara stix',
      icon: FileText,
      group: 'Actions',
      run: () => navigate('/reports'),
    },
  ]
  return [...nav, ...actions]
}

function CommandsPanel({
  navigate,
  close,
}: {
  navigate: ReturnType<typeof useNavigate>
  close: () => void
}) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const commands = useMemo(() => buildCommands(navigate), [navigate])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter((item) => {
      const hay = `${item.label} ${item.alias ?? ''} ${item.group}`.toLowerCase()
      return hay.includes(q)
    })
  }, [commands, query])

  const run = (command: CommandItem) => {
    close()
    command.run()
  }

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActive((prev) => (prev + 1) % Math.max(filtered.length, 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActive(
        (prev) =>
          (prev - 1 + Math.max(filtered.length, 1)) % Math.max(filtered.length, 1),
      )
    } else if (event.key === 'Enter' && filtered[active]) {
      event.preventDefault()
      run(filtered[active]!)
    } else if (event.key === 'Escape') {
      event.preventDefault()
      close()
    }
  }

  const groups = useMemo(() => {
    const order = new Set(filtered.map((item) => item.group))
    return [...order].map((group) => ({
      group,
      items: filtered.filter((item) => item.group === group),
    }))
  }, [filtered])

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh]"
      role="dialog"
      aria-modal="true"
      aria-label={t('Command palette')}
    >
      <button
        type="button"
        aria-label={t('Close')}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={close}
      />

      <div className="relative w-full max-w-xl overflow-hidden rounded-xl border border-border-strong bg-surface shadow-2xl shadow-black/50">
        <div className="flex items-center gap-3 border-b border-border px-4">
          <Search className="h-4 w-4 shrink-0 text-ink-3" />
          <input
            ref={inputRef}
            autoFocus
            value={query}
            onChange={(event) => {
              setQuery(event.target.value)
              setActive(0)
            }}
            onKeyDown={onKeyDown}
            placeholder={t('Type a command or search…')}
            className="h-13 w-full bg-transparent py-3.5 text-[14px] text-ink placeholder:text-ink-3 focus:outline-none"
          />
          <kbd className="rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-ink-3">
            ESC
          </kbd>
        </div>

        <div className="max-h-[52vh] overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <p className="px-4 py-8 text-center font-mono text-[12.5px] text-ink-3">
              {t('No command matches “{query}”.', { query })}
            </p>
          ) : (
            groups.map((group) => (
              <div key={group.group} className="mb-1 last:mb-0">
                <p className="eyebrow px-3 pt-2 pb-1.5">{t(group.group)}</p>
                {group.items.map((item) => {
                  const index = filtered.indexOf(item)
                  const isActive = index === active
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onMouseEnter={() => setActive(index)}
                      onClick={() => run(item)}
                      className={cn(
                        'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left',
                        isActive && 'bg-accent/10 ring-1 ring-accent/20',
                      )}
                    >
                      <item.icon
                        className={cn(
                          'h-4 w-4 shrink-0',
                          isActive ? 'text-accent' : 'text-ink-3',
                        )}
                      />
                      <span
                        className={cn(
                          'flex-1 truncate text-[13px]',
                          isActive ? 'text-ink' : 'text-ink-2',
                        )}
                      >
                        {t(item.label)}
                      </span>
                      <span className="flex items-center gap-1 text-ink-3">
                        <CornerDownLeft className="h-3 w-3" />
                        <ArrowRight className="h-3 w-3" />
                      </span>
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border bg-surface-2 px-4 py-2.5">
          <span className="font-mono text-[10.5px] tracking-wide text-ink-3">
            ↑↓ {t('navigate')} · ↵ {t('open')} · esc {t('close')}
          </span>
          <span className="ml-auto hidden font-mono text-[10.5px] tracking-wide text-ink-3 sm:inline">
            THREATLENS / COMMAND
          </span>
        </div>
      </div>
    </div>
  )
}