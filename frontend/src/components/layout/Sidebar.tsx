import {
  BellRing,
  Boxes,
  FileText,
  FolderOpen,
  History,
  LayoutDashboard,
  Radar,
  Settings2,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'

import { cn } from '../../utils/cn'
import { Logo } from './Logo'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/analyze', label: 'Analyze', icon: Radar },
  { to: '/history', label: 'History', icon: History },
  { to: '/iocs', label: 'IOC Inventory', icon: Boxes },
  { to: '/investigations', label: 'Investigations', icon: FolderOpen },
  { to: '/watchlist', label: 'Watchlist', icon: BellRing },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings2 },
]

interface SidebarProps {
  className?: string
}

export function Sidebar({ className }: SidebarProps) {
  return (
    <aside
      className={cn(
        'flex h-full w-60 flex-col border-r border-border bg-surface',
        className,
      )}
    >
      <div className="flex h-16 items-center border-b border-border px-5">
        <Logo />
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                'group flex items-center gap-3 rounded-lg px-3 py-2 text-[13.5px] font-medium transition-colors',
                isActive
                  ? 'bg-surface-3 text-ink'
                  : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
              )
            }
          >
            {({ isActive }) => (
              <>
                <item.icon
                  className={cn(
                    'h-4 w-4 transition-colors',
                    isActive
                      ? 'text-accent'
                      : 'text-ink-3 group-hover:text-ink-2',
                  )}
                />
                <span>{item.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border p-3">
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ok" />
          <span className="font-mono text-[11px] text-ink-2">
            Platform v0.1
          </span>
        </div>
      </div>
    </aside>
  )
}