import type { DetectionStats, ThreatLevel } from '../../types'

export const LEVEL_ORDER: ThreatLevel[] = [
  'clean',
  'suspicious',
  'malicious',
  'critical',
]

export const LEVEL_STYLE: Record<
  ThreatLevel,
  { text: string; bg: string; border: string; ring: string }
> = {
  clean: {
    text: 'text-clean',
    bg: 'bg-clean/12',
    border: 'border-clean/30',
    ring: '#34d399',
  },
  suspicious: {
    text: 'text-elevated',
    bg: 'bg-elevated/12',
    border: 'border-elevated/30',
    ring: '#fbbf24',
  },
  malicious: {
    text: 'text-high',
    bg: 'bg-high/12',
    border: 'border-high/30',
    ring: '#fb923c',
  },
  critical: {
    text: 'text-critical',
    bg: 'bg-critical/12',
    border: 'border-critical/30',
    ring: '#fb7185',
  },
}

export function levelLabel(level: ThreatLevel | null | undefined): string {
  if (!level) return '—'
  return level.charAt(0).toUpperCase() + level.slice(1)
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function shortId(value: string): string {
  if (value.length <= 24) return value
  return `${value.slice(0, 12)}…${value.slice(-8)}`
}

export function statsTotal(stats: DetectionStats): number {
  return (
    stats.malicious +
    stats.suspicious +
    stats.undetected +
    stats.harmless +
    stats.timeout
  )
}