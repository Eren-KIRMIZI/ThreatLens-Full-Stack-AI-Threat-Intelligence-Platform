import { Loader2 } from 'lucide-react'

import { cn } from '../../utils/cn'
import { useI18n } from '../../i18n'

interface SpinnerProps {
  className?: string
}

export function Spinner({ className }: SpinnerProps) {
  const { t } = useI18n()
  return (
    <Loader2
      className={cn('h-4 w-4 animate-spin text-accent', className)}
      aria-label={t('Loading')}
    />
  )
}