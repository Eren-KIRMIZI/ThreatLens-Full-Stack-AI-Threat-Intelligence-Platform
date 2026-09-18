import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { I18nContext } from './index'
import type { Locale } from './index'
import { tr } from './tr'

const STORAGE_KEY = 'threatlens.locale'

function detectLocale(): Locale {
  if (typeof window === 'undefined') return 'en'
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (stored === 'tr' || stored === 'en') return stored
  return navigator.language?.toLowerCase().startsWith('tr') ? 'tr' : 'en'
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectLocale)

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    window.localStorage.setItem(STORAGE_KEY, next)
  }, [])

  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => {
      let out = locale === 'tr' ? (tr[key] ?? key) : key
      if (vars) {
        for (const [name, value] of Object.entries(vars)) {
          out = out.replaceAll(`{${name}}`, String(value))
        }
      }
      return out
    },
    [locale],
  )

  const value = useMemo(
    () => ({ locale, setLocale, t }),
    [locale, setLocale, t],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}