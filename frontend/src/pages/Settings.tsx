import type { ReactNode } from 'react'
import { KeyRound, ServerCrash, ShieldCheck } from 'lucide-react'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { useHealth } from '../hooks/useHealth'

export function Settings() {
  const { data: health, isError, isPending } = useHealth()

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Service configuration and platform information."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel eyebrow="Service" title="Backend status">
          <dl className="space-y-3">
            <Row label="Status" mono>
              <span className="flex items-center gap-2">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    isError ? 'bg-critical' : 'bg-ok'
                  }`}
                />
                {isError
                  ? 'Unreachable'
                  : isPending
                    ? 'Checking…'
                    : 'Operational'}
              </span>
            </Row>
            <Row label="Version" mono>
              {health?.version ?? '—'}
            </Row>
            <Row label="Environment" mono>
              {health?.environment ?? '—'}
            </Row>
            <Row label="Service" mono>
              {health?.service ?? '—'}
            </Row>
          </dl>
        </Panel>

        <Panel eyebrow="Security" title="API keys">
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-3 px-3.5 py-3">
              <KeyRound className="h-4 w-4 shrink-0 text-ink-3" />
              <p className="text-[13px] leading-relaxed text-ink-2">
                VirusTotal and OpenRouter keys are stored in the backend{' '}
                <code className="mono text-[12px] text-ink">.env</code> file and
                are never exposed to the browser.
              </p>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-3 px-3.5 py-3">
              <ServerCrash className="h-4 w-4 shrink-0 text-ink-3" />
              <p className="text-[13px] leading-relaxed text-ink-2">
                Rate limits are enforced server-side; upstream provider errors
                are surfaced as clean, user-friendly messages.
              </p>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-3 px-3.5 py-3">
              <ShieldCheck className="h-4 w-4 shrink-0 text-ink-3" />
              <p className="text-[13px] leading-relaxed text-ink-2">
                All uploaded samples are hashed and sent as metadata only. Raw
                binaries are not forwarded to the AI layer.
              </p>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}

function Row({
  label,
  children,
  mono,
}: {
  label: string
  children: ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="eyebrow">{label}</dt>
      <dd
        className={
          mono
            ? 'font-mono text-[13px] text-ink'
            : 'text-[13px] text-ink'
        }
      >
        {children}
      </dd>
    </div>
  )
}