import type { ButtonHTMLAttributes } from 'react'

import { cn } from '../../utils/cn'

type ButtonVariant = 'primary' | 'secondary' | 'ghost'
type ButtonSize = 'sm' | 'md'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
}

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-accent text-bg font-semibold hover:bg-accent-strong disabled:bg-surface-4 disabled:text-ink-3',
  secondary:
    'border border-border-strong bg-surface-3 text-ink hover:bg-surface-4 disabled:text-ink-3',
  ghost: 'text-ink-2 hover:bg-surface-2 hover:text-ink disabled:text-ink-3',
}

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-[12.5px] rounded-md gap-1.5',
  md: 'h-10 px-4 text-[13.5px] rounded-lg gap-2',
}

export function Button({
  variant = 'primary',
  size = 'md',
  className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center font-medium transition-colors focus:ring-2 focus:ring-accent/25 focus:outline-none disabled:cursor-not-allowed',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      disabled={disabled}
      {...rest}
    >
      {children}
    </button>
  )
}