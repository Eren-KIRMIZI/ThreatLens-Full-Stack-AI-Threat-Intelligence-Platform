import {
  AlertTriangle,
  Braces,
  Compass,
  Crosshair,
  ListChecks,
  Radar,
  Repeat,
  ShieldAlert,
  Sparkles,
  UserX,
} from 'lucide-react'

import type { AIAnalysis } from '../../types'
import { formatDate, levelLabel, LEVEL_STYLE } from './level'
import { LevelBadge } from './LevelBadge'

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-border/70 pb-4 last:border-0 last:pb-0">
      <h4 className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-ink">
        <span className="grid h-6 w-6 place-items-center rounded-md bg-surface-3 text-accent">
          {icon}
        </span>
        {title}
      </h4>
      {children}
    </section>
  )
}

function EmptyText() {
  return <p className="text-[12.5px] text-ink-3">Not assessed from the evidence.</p>
}

interface AiAnalysisViewProps {
  ai: AIAnalysis
}

export function AiAnalysisView({ ai }: AiAnalysisViewProps) {
  const levelStyle = ai.threat_level_assessment ? LEVEL_STYLE[ai.threat_level_assessment] : null

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-accent" />
          <span className="text-[13px] text-ink-2">
            Model: <span className="font-mono text-ink">{ai.model ?? '—'}</span>
          </span>
        </div>
        <div className="flex items-center gap-3 text-[12px] text-ink-3">
          {ai.created_at && <span>{formatDate(ai.created_at)}</span>}
          {ai.threat_level_assessment && (
            <LevelBadge level={ai.threat_level_assessment} />
          )}
        </div>
      </div>

      <Section icon={<Radar className="h-3.5 w-3.5" />} title="Summary">
        <p className="text-[13.5px] leading-relaxed text-ink">{ai.summary}</p>
      </Section>

      <Section icon={<Compass className="h-3.5 w-3.5" />} title="Tactics">
        {ai.tactics.length === 0 ? (
          <EmptyText />
        ) : (
          <ul className="space-y-2.5">
            {ai.tactics.map((tactic, index) => (
              <li
                key={`${tactic.phase}-${index}`}
                className="rounded-lg border border-border bg-surface px-3 py-2.5"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[13px] font-semibold text-ink">
                    {tactic.phase}
                  </span>
                  {tactic.technique_id && (
                    <span className="rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 font-mono text-[11px] text-accent-strong">
                      {tactic.technique_id}
                    </span>
                  )}
                  {tactic.technique_name && (
                    <span className="text-[12px] text-ink-2">
                      {tactic.technique_name}
                    </span>
                  )}
                </div>
                {tactic.notes && (
                  <p className="mt-1 text-[12.5px] text-ink-2">{tactic.notes}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section
        icon={<UserX className="h-3.5 w-3.5" />}
        title="Threat actor profile"
      >
        {!ai.threat_actor_profile ? (
          <EmptyText />
        ) : (
          <div className="rounded-lg border border-border bg-surface px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] font-semibold text-ink">
                {ai.threat_actor_profile.name ?? 'Unknown / unprofiled'}
              </span>
              {ai.threat_actor_profile.confidence && (
                <span className="rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 text-[11px] text-ink-2">
                  confidence: {ai.threat_actor_profile.confidence}
                </span>
              )}
            </div>
            {ai.threat_actor_profile.campaign && (
              <p className="mt-1 text-[12.5px] text-ink-2">
                Campaign: {ai.threat_actor_profile.campaign}
              </p>
            )}
            {ai.threat_actor_profile.description && (
              <p className="mt-1 text-[12.5px] leading-relaxed text-ink-2">
                {ai.threat_actor_profile.description}
              </p>
            )}
          </div>
        )}
      </Section>

      <Section icon={<ShieldAlert className="h-3.5 w-3.5" />} title="Capabilities & impact">
        {ai.capabilities.length === 0 ? (
          <EmptyText />
        ) : (
          <ul className="space-y-2">
            {ai.capabilities.map((cap, index) => (
              <li
                key={index}
                className="flex gap-2.5 rounded-lg border border-border bg-surface px-3 py-2"
              >
                <Crosshair className="mt-0.5 h-3.5 w-3.5 shrink-0 text-elevated" />
                <div>
                  <span className="text-[13px] font-medium text-ink">
                    {cap.capability}
                  </span>
                  <p className="text-[12.5px] leading-relaxed text-ink-2">
                    {cap.description}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section icon={<ListChecks className="h-3.5 w-3.5" />} title="Recommendations">
        {ai.recommendations.length === 0 ? (
          <EmptyText />
        ) : (
          <ul className="space-y-1.5">
            {ai.recommendations.map((item, index) => (
              <li key={index} className="flex gap-2 text-[12.5px] text-ink-2">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent" />
                {item}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section icon={<Repeat className="h-3.5 w-3.5" />} title="Intelligence lifecycle">
        {ai.lifecycle_stage ? (
          <p className="text-[12.5px] text-ink-2">
            Currently assessed at the{' '}
            <span className="font-medium text-ink">{ai.lifecycle_stage}</span>{' '}
            stage of the threat intelligence lifecycle.
          </p>
        ) : (
          <EmptyText />
        )}
      </Section>

      <Section icon={<Braces className="h-3.5 w-3.5" />} title="Correlations">
        {ai.correlations.length === 0 ? (
          <EmptyText />
        ) : (
          <ul className="space-y-1.5">
            {ai.correlations.map((item, index) => (
              <li key={index} className="flex gap-2 text-[12.5px] text-ink-2">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-elevated" />
                {item}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section
        icon={<AlertTriangle className="h-3.5 w-3.5" />}
        title="Evidence cited"
      >
        {ai.evidence_refs.length === 0 ? (
          <EmptyText />
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {ai.evidence_refs.map((engine) => (
              <span
                key={engine}
                className="rounded border border-border-strong bg-surface-3 px-2 py-0.5 font-mono text-[11.5px] text-ink-2"
              >
                {engine}
              </span>
            ))}
          </div>
        )}
        {levelStyle && (
          <p className="mt-3 text-[12px] text-ink-3">
            AI assessment: {levelLabel(ai.threat_level_assessment)} — reported
            separately from the deterministic score.
          </p>
        )}
      </Section>
    </div>
  )
}