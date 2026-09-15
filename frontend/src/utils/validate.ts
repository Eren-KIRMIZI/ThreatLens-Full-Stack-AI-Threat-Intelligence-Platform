import type { IndicatorType } from '../types'

const HEX = /^[a-fA-F0-9]+$/

export function isHash(value: string): boolean {
  if (!HEX.test(value)) return false
  return [32, 40, 64].includes(value.length)
}

export function isUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:'
  } catch {
    return false
  }
}

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/

export function isIp(value: string): boolean {
  if (IPV4.test(value)) {
    return value
      .split('.')
      .every((part) => Number(part) >= 0 && Number(part) <= 255)
  }
  // Loose IPv6 heuristic.
  return value.includes(':') && /^[0-9a-fA-F:.]+$/.test(value)
}

const DOMAIN =
  /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i

export function isDomain(value: string): boolean {
  return DOMAIN.test(value)
}

/** Best-effort type detection used by quick-analyze views. */
export function guessIndicatorType(
  value: string,
): Exclude<IndicatorType, 'FILE'> | null {
  const trimmed = value.trim()
  if (isHash(trimmed)) return 'HASH'
  if (isUrl(trimmed)) return 'URL'
  if (isIp(trimmed)) return 'IP'
  if (isDomain(trimmed)) return 'DOMAIN'
  return null
}