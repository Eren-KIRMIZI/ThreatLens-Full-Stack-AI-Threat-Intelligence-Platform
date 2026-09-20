import { useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { FileUp, FileText } from 'lucide-react'

import { EmailForensicReport } from '../components/forensics/EmailForensicReport'
import { Button } from '../components/ui/Button'
import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Spinner } from '../components/ui/Spinner'
import { ApiRequestError, forensicEmail, forensicEmailRaw } from '../services/api'
import { useI18n } from '../i18n'
import { cn } from '../utils/cn'
import type { EmailForensicOut } from '../types'

type InputMode = 'upload' | 'raw'

export function Forensics() {
  const { t } = useI18n()
  const [mode, setMode] = useState<InputMode>('upload')
  const [file, setFile] = useState<File | null>(null)
  const [raw, setRaw] = useState('')
  const [report, setReport] = useState<EmailForensicOut | null>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  const mutation = useMutation({
    mutationFn: async (): Promise<EmailForensicOut> => {
      if (mode === 'upload') {
        if (!file) throw new ApiRequestError(422, { code: 'no_file', message: 'No file selected' })
        return forensicEmail(file)
      }
      if (!raw.trim()) {
        throw new ApiRequestError(422, { code: 'no_body', message: 'No message body pasted' })
      }
      return forensicEmailRaw(raw)
    },
    onSuccess: (result) => setReport(result),
  })

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 md:px-8">
      <PageHeader
        title={t('Phishing Forensics')}
        description={t(
          'Parse a suspicious email offline and get a deterministic, evidence-locked verdict. Raw samples are never stored and never reach the AI layer.',
        )}
      />

      <Panel title={t('Submit message')} eyebrow={t('RFC-822 input')}>
        <div className="mb-5 flex items-center gap-2">
          <button
            type="button"
            onClick={() => setMode('upload')}
            className={cn(
              'focus-ring flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors',
              mode === 'upload'
                ? 'bg-accent/10 text-ink ring-1 ring-accent/20'
                : 'text-ink-2 hover:bg-surface-2',
            )}
          >
            <FileUp className="h-4 w-4" />
            {t('Upload .eml')}
          </button>
          <button
            type="button"
            onClick={() => setMode('raw')}
            className={cn(
              'focus-ring flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors',
              mode === 'raw'
                ? 'bg-accent/10 text-ink ring-1 ring-accent/20'
                : 'text-ink-2 hover:bg-surface-2',
            )}
          >
            <FileText className="h-4 w-4" />
            {t('Paste raw source')}
          </button>
        </div>

        {mode === 'upload' ? (
          <div>
            <input
              ref={fileRef}
              type="file"
              accept=".eml,.txt,message/rfc822"
              className="hidden"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className="focus-ring flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border-strong bg-surface-2 px-4 py-10 text-center transition-colors hover:border-accent/40"
            >
              <FileUp className="h-6 w-6 text-ink-3" />
              <span className="text-[13.5px] font-medium text-ink-2">
                {file ? file.name : t('Choose an .eml or RFC-822 file')}
              </span>
              <span className="text-[12px] text-ink-3">
                {t('Parsed in memory; bytes are never persisted')}
              </span>
            </button>
          </div>
        ) : (
          <textarea
            value={raw}
            onChange={(event) => setRaw(event.target.value)}
            rows={10}
            spellCheck={false}
            placeholder={
              'From: "Dropbox Security" <billing@dropbox-support.xyz>\r\nReceived-SPF: fail\r\nSubject: Your account is locked\r\n\r\nClick here to verify: http://dropbox-support.xyz/reset'
            }
            className="focus-ring w-full resize-y rounded-lg border border-border bg-surface-2 px-3 py-2.5 font-mono text-[12.5px] leading-relaxed text-ink placeholder:text-ink-3"
          />
        )}

        <div className="mt-4 flex items-center justify-end gap-3">
          {mutation.isError && (
            <p className="mr-auto text-[12.5px] text-critical">
              {mutation.error?.message ?? t('Analysis failed')}
            </p>
          )}
          <Button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || (mode === 'upload' && !file)}
          >
            {mutation.isPending ? (
              <>
                <Spinner className="h-4 w-4" />
                {t('Analyzing…')}
              </>
            ) : (
              t('Analyze message')
            )}
          </Button>
        </div>
      </Panel>

      {report && (
        <div className="mt-6">
          <EmailForensicReport report={report} />
        </div>
      )}
    </div>
  )
}