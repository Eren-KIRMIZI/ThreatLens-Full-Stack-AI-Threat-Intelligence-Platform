import { useState } from 'react'
import {
  BellRing,
  Boxes,
  Command,
  Crosshair,
  FileText,
  FolderOpen,
  History,
  LayoutDashboard,
  LayoutGrid,
  Mail,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Settings2,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { NavLink } from 'react-router-dom'

import { cn } from '../../utils/cn'
import { Logo, LogoMark } from './Logo'
import { useI18n } from '../../i18n'
import { useCommandPalette } from '../command/commandContext'

const STORAGE_KEY = 'threatlens.sidebar.collapsed'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  end?: boolean
}

interface NavGroup {
  group: string
  items: NavItem[]
}

const NAV: NavGroup[] = [
  {
    group: 'Overview',
    items: [{ to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true }],
  },
  {
    group: 'Intelligence',
    items: [
      { to: '/analyze', label: 'Analyze', icon: Radar },
      { to: '/iocs', label: 'IOC Inventory', icon: Boxes },
      { to: '/hunt', label: 'Threat Hunting', icon: Crosshair },
      { to: '/history', label: 'History', icon: History },
    ],
  },
  {
    group: 'Operations',
    items: [
      { to: '/watchlist', label: 'Watchlist', icon: BellRing },
      { to: '/investigations', label: 'Investigations', icon: FolderOpen },
    ],
  },
  {
    group: 'Detection',
    items: [
      { to: '/forensics', label: 'Phishing Forensics', icon: Mail },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: LayoutGrid },
    ],
  },
  {
    group: 'Reporting',
    items: [{ to: '/reports', label: 'Reports', icon: FileText }],
  },
  {
    group: 'System',
    items: [{ to: '/settings', label: 'Settings', icon: Settings2 }],
  },
]

interface SidebarProps {
  className?: string
}

export function Sidebar({ className }: SidebarProps) {
  const { t } = useI18n()
  const { open } = useCommandPalette()
  const [collapsed, setCollapsed] = useState(
    () => window.localStorage.getItem(STORAGE_KEY) === '1',
  )

  const toggle = () => {
    setCollapsed((prev) => {
      window.localStorage.setItem(STORAGE_KEY, prev ? '0' : '1')
      return !prev
    })
  }

  return (
    <aside
      className={cn(
        'flex h-full flex-col border-r border-border bg-surface transition-[width] duration-200 ease-out',
        collapsed ? 'w-[58px]' : 'w-64',
        className,
      )}
    >
      <div
        className={cn(
          'flex h-16 shrink-0 items-center border-b border-border/70',
          collapsed ? 'justify-center px-0' : 'px-5',
        )}
      >
        {collapsed ? (
          <span className="text-accent">
            <LogoMark className="h-6 w-6" />
          </span>
        ) : (
          <Logo />
        )}
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-3">
        <button
          type="button"
          onClick={open}
          title={t('Search or run a command')}
          className={cn(
            'focus-ring mb-3 flex w-full items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2 text-left transition-colors hover:border-accent/40',
            collapsed && 'justify-center px-0',
          )}
        >
          <Command className="h-[17px] w-[17px] shrink-0 text-ink-3" />
          {!collapsed && (
            <>
              <span className="flex-1 truncate text-[12.5px] font-medium text-ink-2">
                {t('Search')}
              </span>
              <kbd className="rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-ink-3">
                ⌘K
              </kbd>
            </>
          )}
        </button>

        <div className="space-y-4">
          {NAV.map((group) => (
            <div key={group.group}>
              {!collapsed && (
                <p className="eyebrow px-3 pb-1.5">{t(group.group)}</p>
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <SidebarLink
                    key={item.to}
                    item={item}
                    p={t}
                    collapsed={collapsed}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </nav>

      <div className="border-t border-border/70 p-3">
        <button
          type="button"
          onClick={toggle}
          className="focus-ring flex w-full items-center justify-center gap-2 rounded-lg px-3 py-2 text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink-2"
          title={collapsed ? t('Expand navigation') : t('Collapse navigation')}
        >
          {collapsed ? (
            <PanelLeftOpen className="h-4 w-4" />
          ) : (
            <>
              <PanelLeftClose className="h-4 w-4" />
              <span className="text-[12.5px] font-medium">
                {t('Collapse')}
              </span>
            </>
          )}
        </button>
        <div
          className={cn(
            'mt-2.5 flex items-center gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5',
            collapsed && 'justify-center px-0',
          )}
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
          </span>
          {!collapsed && (
            <span className="font-mono text-[11px] tracking-wide text-ink-2">
              ThreatLens / operations
            </span>
          )}
        </div>
      </div>
    </aside>
  )
}

function SidebarLink({
  item,
  p,
  collapsed,
}: {
  item: NavItem
  p: (key: string) => string
  collapsed: boolean
}) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      title={p(item.label)}
      className={({ isActive }) =>
        cn(
          'group flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] font-medium transition-all',
          collapsed && 'justify-center px-0',
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
              'h-[17px] w-[17px] shrink-0 transition-colors',
              isActive ? 'text-accent' : 'text-ink-3 group-hover:text-ink-2',
            )}
          />
          {!collapsed && <span className="truncate">{p(item.label)}</span>}
        </>
      )}
    </NavLink>
  )
}