import { Suspense, useState } from 'react'
import { Outlet } from 'react-router-dom'

import { Sidebar } from './Sidebar'
import { Spinner } from '../ui/Spinner'
import { StatusBar } from './StatusBar'
import { TopBar } from './TopBar'
import { CommandPaletteProvider } from '../command/CommandPalette'
import { useI18n } from '../../i18n'

export function AppLayout() {
  const { t } = useI18n()
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  return (
    <CommandPaletteProvider>
      <div className="flex h-svh overflow-hidden">
        {/* Desktop sidebar */}
        <div className="hidden md:block">
          <Sidebar />
        </div>

        {/* Mobile sidebar drawer */}
        {mobileNavOpen && (
          <div className="fixed inset-0 z-40 flex md:hidden">
            <button
              type="button"
              aria-label={t('Close navigation')}
              className="absolute inset-0 bg-black/60"
              onClick={() => setMobileNavOpen(false)}
            />
            <div className="relative z-10 h-full">
              <Sidebar />
            </div>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar onMenuClick={() => setMobileNavOpen(true)} />
          <main className="min-h-0 flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-[1280px] px-4 py-6 md:px-8 md:py-8">
              <Suspense
                fallback={
                  <div className="flex min-h-[40vh] items-center justify-center">
                    <Spinner className="h-6 w-6" />
                  </div>
                }
              >
                <Outlet />
              </Suspense>
            </div>
          </main>
          <StatusBar />
        </div>
      </div>
    </CommandPaletteProvider>
  )
}