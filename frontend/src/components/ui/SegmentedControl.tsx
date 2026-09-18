import { cn } from '../../utils/cn'

interface SegmentedOption<T extends string> {
  value: T
  label: string
}

interface SegmentedControlProps<T extends string> {
  options: SegmentedOption<T>[]
  value: T
  onChange: (value: T) => void
  className?: string
}

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  className,
}: SegmentedControlProps<T>) {
  return (
    <div
      role="tablist"
      className={cn(
        'focus-ring inline-flex flex-wrap items-center gap-0.5 rounded-lg border border-border bg-surface p-1',
        className,
      )}
    >
      {options.map((option) => {
        const active = option.value === value
        return (
          <button
            key={option.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(option.value)}
            className={cn(
              'rounded-md px-3.5 py-1.5 text-[13px] font-medium transition-all',
              active
                ? 'bg-surface-4 text-ink shadow-[inset_0_1px_0_rgb(255_255_255/0.05)]'
                : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
            )}
          >
            {option.label}
          </button>
        )
      })}
    </div>
  )
}