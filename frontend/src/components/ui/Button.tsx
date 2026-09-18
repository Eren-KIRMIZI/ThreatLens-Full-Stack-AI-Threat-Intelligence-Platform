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
    'bg-accent text-bg font-semibold shadow-[0_0_0_1px_rgb(0_0_0/0.08),0_1px_2px_rgb(0_0_0/0.4)] hover:bg-accent-strong hover:shadow-[0_1px_2px_rgb(0_0_0/0.35)] active:scale-[0.985] disabled:bg-surface-4 disabled:text-ink-3 disabled:shadow-none',
  secondary:
    'border border-border-strong bg-surface-3 text-ink shadow-[inset_0_1px_0_rgb(255_255_255/0.04)] hover:bg-surface-4 hover:border-ink-3/70 active:scale-[0.985] disabled:text-ink-3 disabled:hover:bg-surface-3 disabled:hover:border-border-strong',
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
        'focus-ring inline-flex items-center justify-center font-medium transition-all disabled:cursor-not-allowed',
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