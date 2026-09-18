import { useI18n } from '../../i18n'
import type { Locale } from '../../i18n'
import { cn } from '../../utils/cn'

const OPTIONS: Locale[] = ['en', 'tr']

export function LanguageToggle() {
  const { locale, setLocale } = useI18n()

  return (
    <div className="focus-ring flex items-center gap-0.5 rounded-lg border border-border bg-surface-2 p-0.5">
      {OPTIONS.map((code) => (
        <button
          key={code}
          type="button"
          onClick={() => setLocale(code)}
          aria-pressed={locale === code}
          aria-label={code === 'en' ? 'English' : 'Türkçe'}
          className={cn(
            'h-7 w-8 rounded-md text-[11px] font-semibold tracking-wider uppercase transition-colors',
            locale === code
              ? 'bg-accent/15 text-accent'
              : 'text-ink-3 hover:text-ink',
          )}
        >
          {code}
        </button>
      ))}
    </div>
  )
}