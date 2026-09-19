import {
  BellRing,
  Boxes,
  Crosshair,
  FileText,
  FolderOpen,
  History,
  LayoutDashboard,
  LayoutGrid,
  Radar,
  Settings2,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'

import { cn } from '../../utils/cn'
import { Logo } from './Logo'
import { useI18n } from '../../i18n'

const COMMAND_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/analyze', label: 'Analyze', icon: Radar },
  { to: '/hunt', label: 'Threat Hunting', icon: Crosshair },
  { to: '/history', label: 'History', icon: History },
  { to: '/iocs', label: 'IOC Inventory', icon: Boxes },
  { to: '/investigations', label: 'Investigations', icon: FolderOpen },
]

const SYSTEM_ITEMS = [
  { to: '/watchlist', label: 'Watchlist', icon: BellRing },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: LayoutGrid },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings2 },
]

interface SidebarProps {
  className?: string
}

export function Sidebar({ className }: SidebarProps) {
  const { t } = useI18n()
  return (
    <aside
      className={cn(
        'flex h-full w-64 flex-col border-r border-border bg-surface',
        className,
      )}
    >
      <div className="flex h-16 shrink-0 items-center border-b border-border/70 px-5">
        <Logo />
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">
        <p className="eyebrow px-3 pt-2 pb-1.5">{t('Command')}</p>
        {COMMAND_ITEMS.map((item) => (
          <SidebarLink key={item.to} item={item} p={t} />
        ))}
        <p className="eyebrow px-3 pt-4 pb-1.5">{t('System')}</p>
        {SYSTEM_ITEMS.map((item) => (
          <SidebarLink key={item.to} item={item} p={t} />
        ))}
      </nav>

      <div className="border-t border-border/70 p-3">
        <div className="flex items-center gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5 shadow-[inset_0_1px_0_rgb(255_255_255/0.04)]">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
          </span>
          <span className="font-mono text-[11px] tracking-wide text-ink-2">
            Platform v0.1
          </span>
        </div>
      </div>
    </aside>
  )
}

function SidebarLink({
  item,
  p,
}: {
  item: (typeof COMMAND_ITEMS)[number]
  p: (key: string) => string
}) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      className={({ isActive }) =>
        cn(
          'group flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] font-medium transition-all',
          isActive
            ? 'bg-accent/10 text-ink ring-1 ring-accent/20'
            : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
        )
      }
    >
      {({ isActive }) => (
        <>
          <item.icon
            className={cn(
              'h-[17px] w-[17px] transition-colors',
              isActive ? 'text-accent' : 'text-ink-3 group-hover:text-ink-2',
            )}
          />
          <span>{p(item.label)}</span>
        </>
      )}
    </NavLink>
  )
}