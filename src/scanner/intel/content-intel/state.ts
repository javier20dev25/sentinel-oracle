import type { IntelRisk } from '../types'

/**
 * Lifecycle of a content-intelligence cache entry, keyed by the sha512 of a
 * published artifact:
 *
 *   UNKNOWN ──scan_started──▶ SCANNING ──verdict_*──▶ KNOWN_SAFE | SUSPICIOUS | MALICIOUS
 *      │  ◀─────── rescan / revoke ◀───────────────────┘
 *      │                                                │
 *      └──── verdict_* (direct) ───────────────────────▶ KNOWN_SAFE | SUSPICIOUS | MALICIOUS
 *   any decisive state ──revoke──▶ REVOKED
 *   any state ──rescan──▶ SCANNING   (revalidation after scannerVersion bump)
 *
 * Transitions are deterministic; an invalid transition throws so a programmer
 * error fails fast instead of silently corrupting cache state.
 */
export type ContentIntelState =
  | 'UNKNOWN'
  | 'SCANNING'
  | 'KNOWN_SAFE'
  | 'SUSPICIOUS'
  | 'MALICIOUS'
  | 'REVOKED'

export type ContentIntelEvent =
  | 'scan_started'
  | 'verdict_safe'
  | 'verdict_suspicious'
  | 'verdict_malicious'
  | 'revoke'
  | 'rescan'

const TRANSITIONS: Record<ContentIntelState, Partial<Record<ContentIntelEvent, ContentIntelState>>> = {
  UNKNOWN: {
    scan_started: 'SCANNING',
    verdict_safe: 'KNOWN_SAFE',
    verdict_suspicious: 'SUSPICIOUS',
    verdict_malicious: 'MALICIOUS',
    rescan: 'SCANNING',
  },
  SCANNING: {
    verdict_safe: 'KNOWN_SAFE',
    verdict_suspicious: 'SUSPICIOUS',
    verdict_malicious: 'MALICIOUS',
  },
  KNOWN_SAFE: {
    verdict_safe: 'KNOWN_SAFE',
    verdict_suspicious: 'SUSPICIOUS',
    verdict_malicious: 'MALICIOUS',
    revoke: 'REVOKED',
    rescan: 'SCANNING',
  },
  SUSPICIOUS: {
    verdict_safe: 'KNOWN_SAFE',
    verdict_suspicious: 'SUSPICIOUS',
    verdict_malicious: 'MALICIOUS',
    revoke: 'REVOKED',
    rescan: 'SCANNING',
  },
  MALICIOUS: {
    verdict_safe: 'KNOWN_SAFE',
    verdict_suspicious: 'SUSPICIOUS',
    verdict_malicious: 'MALICIOUS',
    revoke: 'REVOKED',
    rescan: 'SCANNING',
  },
  REVOKED: {
    scan_started: 'SCANNING',
    verdict_safe: 'KNOWN_SAFE',
    verdict_suspicious: 'SUSPICIOUS',
    verdict_malicious: 'MALICIOUS',
    revoke: 'REVOKED',
    rescan: 'SCANNING',
  },
}

export class ContentIntelTransitionError extends Error {}

export function nextState(state: ContentIntelState, event: ContentIntelEvent): ContentIntelState {
  const target = TRANSITIONS[state]?.[event]
  if (!target) {
    throw new ContentIntelTransitionError(`Invalid content-intel transition: ${state} --${event}--> ?`)
  }
  return target
}

/** Event that produces a given decisive state (used when recording a verdict). */
export function verdictEventForState(state: ContentIntelState): ContentIntelEvent | null {
  switch (state) {
    case 'KNOWN_SAFE': return 'verdict_safe'
    case 'SUSPICIOUS': return 'verdict_suspicious'
    case 'MALICIOUS': return 'verdict_malicious'
    default: return null
  }
}

export function isDecisiveState(state: ContentIntelState): boolean {
  return state === 'KNOWN_SAFE' || state === 'SUSPICIOUS' || state === 'MALICIOUS' || state === 'REVOKED'
}

export function isPendingState(state: ContentIntelState): boolean {
  return state === 'UNKNOWN' || state === 'SCANNING'
}

/** Risk mapping for a decisive verdict (drives the pre-commit gate on hit). */
export function stateToRisk(state: ContentIntelState): IntelRisk | null {
  switch (state) {
    case 'KNOWN_SAFE': return 'low'
    case 'SUSPICIOUS': return 'medium'
    case 'MALICIOUS': return 'critical'
    case 'REVOKED': return 'critical'
    default: return null
  }
}

/** Verdict state for an Oracle risk level (critical→MALICIOUS, high/medium→SUSPICIOUS, low→KNOWN_SAFE). */
export function stateFromRisk(risk: IntelRisk): ContentIntelState {
  switch (risk) {
    case 'critical': return 'MALICIOUS'
    case 'high':
    case 'medium': return 'SUSPICIOUS'
    default: return 'KNOWN_SAFE'
  }
}
