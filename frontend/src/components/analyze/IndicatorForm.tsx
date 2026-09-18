import { zodResolver } from '@hookform/resolvers/zod'
import { FileUp, UploadCloud } from 'lucide-react'
import { useId, useState } from 'react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'

import { Button } from '../ui/Button'
import { Spinner } from '../ui/Spinner'
import { cn } from '../../utils/cn'
import { isDomain, isHash, isIp, isUrl } from '../../utils/validate'
import { useI18n } from '../../i18n'
import type { I18nContextValue } from '../../i18n'
import type { IndicatorType } from '../../types'

export type AnalyzeMode = Exclude<IndicatorType, 'FILE'> | 'FILE'

const textSchema = (
  mode: Exclude<AnalyzeMode, 'FILE'>,
  t: I18nContextValue['t'],
) =>
  z.object({
    value: z
      .string()
      .trim()
      .min(1, t('Enter an indicator to analyze'))
      .refine((v) => {
        if (mode === 'HASH') return isHash(v)
        if (mode === 'URL') return isUrl(v)
        if (mode === 'DOMAIN') return isDomain(v)
        return isIp(v)
      }, t('That does not look like a valid {mode} indicator.', { mode: mode.toLowerCase() })),
  })

const schema = (mode: AnalyzeMode, t: I18nContextValue['t']) =>
  z.object({
    value: mode === 'FILE' ? z.string() : textSchema(mode, t).shape.value,
    file:
      mode === 'FILE'
        ? z
            .instanceof(File)
            .refine((f) => f.size > 0, t('The selected file is empty.'))
        : z.instanceof(File).optional(),
  })

const PLACEHOLDERS = {
  FILE: '',
  HASH: 'SHA256, SHA1 or MD5…',
  URL: 'https://example.com/path…',
  DOMAIN: 'example.com…',
  IP: '8.8.8.8 or 2606:4700::6810:85e5…',
}

export interface AnalyzeSubmission {
  mode: AnalyzeMode
  value: string
  file?: File
  ai: boolean
}

interface IndicatorFormProps {
  mode: AnalyzeMode
  defaultInput?: string
  submitting?: boolean
  onSubmit: (submission: AnalyzeSubmission) => void
}

export function IndicatorForm({
  mode,
  defaultInput,
  submitting,
  onSubmit,
}: IndicatorFormProps) {
  const id = useId()
  const { t } = useI18n()
  const [ai, setAi] = useState(false)
  const isFile = mode === 'FILE'

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<{ value: string; file?: File }>({
    resolver: zodResolver(schema(mode, t)),
    defaultValues: { value: defaultInput ?? '' },
  })

  const submit = handleSubmit((values) => {
    onSubmit({
      mode,
      value: isFile ? values.file!.name : values.value,
      file: isFile ? values.file : undefined,
      ai,
    })
  })

  return (
    <form onSubmit={submit} className="space-y-4">
      {isFile ? (
        <FilePicker
          id={`${id}-file`}
          invalid={Boolean(errors.file)}
          onChange={(file) => setValue('file', file, { shouldValidate: true })}
        />
      ) : (
        <div>
          <input
            {...register('value')}
            type="text"
            placeholder={PLACEHOLDERS[mode]}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            className={cn(
              'h-11 w-full rounded-lg border bg-surface-3 px-3.5 font-mono text-[13px] text-ink placeholder:font-sans placeholder:text-ink-3 focus:ring-2 focus:outline-none',
              errors.value
                ? 'border-critical/60 focus:ring-critical/20'
                : 'border-border focus:border-accent/60 focus:ring-accent/20',
            )}
          />
          {errors.value && (
            <p className="mt-1.5 text-[12px] text-critical">
              {errors.value.message}
            </p>
          )}
        </div>
      )}

      <AiToggle checked={ai} onChange={setAi} />

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={submitting}>
          {submitting ? (
            <>
              <Spinner /> {t('Analyzing…')}
            </>
          ) : (
            t('Analyze')
          )}
        </Button>
        {errors.file && (
          <p className="text-[12px] text-critical">{errors.file.message}</p>
        )}
      </div>
    </form>
  )
}

interface FilePickerProps {
  id: string
  invalid?: boolean
  onChange: (file: File) => void
}

function FilePicker({ id, invalid, onChange }: FilePickerProps) {
  const { t } = useI18n()
  const [name, setName] = useState<string | null>(null)

  return (
    <label
      htmlFor={id}
      className={cn(
        'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed bg-surface-3 px-4 py-8 text-center transition-colors hover:bg-surface-4',
        invalid ? 'border-critical/60' : 'border-border-strong',
      )}
    >
      {name ? (
        <FileUp className="h-6 w-6 text-accent" />
      ) : (
        <UploadCloud className="h-6 w-6 text-ink-3" />
      )}
      <span className="text-[13px] font-medium text-ink">
        {name ?? t('Choose a file to analyze')}
      </span>
      <span className="text-[12px] text-ink-3">
        {t('Hashes are computed and submitted server-side. Max 32 MB.')}
      </span>
      <span className="mt-1 font-mono text-[11.5px] text-accent-strong">
        {name ?? t('or drop it here')}
      </span>
      <input
        id={id}
        type="file"
        className="sr-only"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) {
            setName(file.name)
            onChange(file)
          }
        }}
      />
    </label>
  )
}

function AiToggle({
  checked,
  onChange,
}: {
  checked: boolean
  onChange: (value: boolean) => void
}) {
  const { t } = useI18n()
  return (
    <label className="flex w-fit cursor-pointer items-center gap-2.5 select-none">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative h-5.5 w-10 shrink-0 rounded-full transition-colors',
          checked ? 'bg-accent/70' : 'bg-surface-4',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 left-0.5 h-4.5 w-4.5 rounded-full bg-ink transition-transform',
            checked && 'translate-x-[18px]',
          )}
        />
      </button>
      <span className="text-[13px] font-medium text-ink">
        {t('Include AI interpretation')}
      </span>
    </label>
  )
}