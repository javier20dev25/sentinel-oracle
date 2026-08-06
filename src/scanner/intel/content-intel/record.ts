import { createHmac, timingSafeEqual } from 'node:crypto'
import type { Finding } from '../../rules'
import type { IntelRisk } from '../types'
import { isDecisiveState, nextState, verdictEventForState, type ContentIntelEvent, type ContentIntelState } from './state'

/**
 * Cached intelligence for one published artifact (identified by content hash).
 *
 * The record is SIGNED (HMAC-SHA256 over the canonical payload) so a tampered
 * or stale cache row is detected on read and treated as a miss — a corrupted
 * cache can never flip a verdict. `scannerVersion` is part of the payload: a
 * scanner/rules upgrade invalidates every row at once (revalidation re-scans).
 */
export interface ContentIntelEvidence {
  risk: IntelRisk
  filesChanged: number
  newDomains: string[]
  newNetworkCalls: number
  newCapabilities: string[]
  newScripts: string[]
  newBinaries: string[]
  lifecycleScripts: { script: string; command: string; dangerous: boolean }[]
  summary: string
  /** Final derived findings (lifecycle + delta + rules) — replayed verbatim on a cache hit. */
  findings: Finding[]
}

export interface ContentIntelRecord {
  contentId: string
  state: ContentIntelState
  stateSince: number
  firstSeen: number
  lastSeen: number
  seenInRepoCount: number
  seenRepoKeys: string[]
  scannerVersion: string
  /** true only when the downloaded bytes matched the registry SRI before the verdict was recorded. */
  verified: boolean
  evidence: ContentIntelEvidence
  signer: string
  signature: string
}

export const DEFAULT_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000
export const MAX_SEEN_REPO_KEYS = 64

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k])
    }
    return out
  }
  return value
}

/** Canonical, key-sorted JSON of everything except the signature. */
export function canonicalizeRecordPayload(rec: ContentIntelRecord | Omit<ContentIntelRecord, 'signature'>): string {
  const rest: Record<string, unknown> = { ...rec }
  delete rest.signature
  return JSON.stringify(sortKeys(rest))
}

export function signRecord(rec: Omit<ContentIntelRecord, 'signature'>, key: Buffer, signer: string): ContentIntelRecord {
  const base: Omit<ContentIntelRecord, 'signature'> = { ...rec, signer }
  const signature = createHmac('sha256', key).update(canonicalizeRecordPayload(base)).digest('hex')
  return { ...base, signature }
}

export function verifyRecord(rec: ContentIntelRecord, key: Buffer): boolean {
  if (!rec.signature || !key.length) return false
  const expected = createHmac('sha256', key).update(canonicalizeRecordPayload(rec)).digest('hex')
  const a = Buffer.from(expected, 'hex')
  const b = Buffer.from(rec.signature, 'hex')
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

export function touchRecord(rec: ContentIntelRecord, repoKey: string | undefined, now?: number): ContentIntelRecord {
  const t = now ?? Date.now()
  const updated: ContentIntelRecord = { ...rec, lastSeen: t }
  if (repoKey && !updated.seenRepoKeys.includes(repoKey)) {
    updated.seenRepoKeys = [...updated.seenRepoKeys, repoKey].slice(-MAX_SEEN_REPO_KEYS)
    updated.seenInRepoCount += 1
  }
  return updated
}

/**
 * Build the next record for a verdict, applying the state machine on top of any
 * existing record and preserving first-seen / seen-in-repos history. The result
 * is NOT signed (stores sign with their own key).
 */
export function applyVerdict(
  existing: ContentIntelRecord | null,
  opts: {
    contentId: string
    state: ContentIntelState
    scannerVersion: string
    verified: boolean
    evidence: ContentIntelEvidence
    now?: number
    repoKey?: string
  },
): ContentIntelRecord {
  const event = verdictEventForState(opts.state)
  if (!event) throw new ContentIntelTransitionGuard(opts.state)
  let target: ContentIntelState
  if (!existing) {
    target = nextState('UNKNOWN', event)
  } else if (isDecisiveState(existing.state)) {
    // Re-verdict: a decisive record may be re-affirmed (TTL refresh) or
    // corrected in place by a fresh analysis — the rescan ceremony is not
    // needed to re-confirm what the analysis already decided.
    target = opts.state
  } else {
    target = nextState(existing.state, event)
  }
  const now = opts.now ?? Date.now()
  const fresh: ContentIntelRecord = {
    contentId: opts.contentId,
    state: target,
    stateSince: now,
    firstSeen: now,
    lastSeen: now,
    seenInRepoCount: opts.repoKey ? 1 : 0,
    seenRepoKeys: opts.repoKey ? [opts.repoKey] : [],
    scannerVersion: opts.scannerVersion,
    verified: opts.verified,
    evidence: opts.evidence,
    signer: '',
    signature: '',
  }
  const base = existing
    ? { ...fresh, firstSeen: existing.firstSeen, seenInRepoCount: existing.seenInRepoCount, seenRepoKeys: existing.seenRepoKeys }
    : fresh
  return opts.repoKey ? touchRecord(base, opts.repoKey, now) : base
}

/** A decisive verdict that is usable without re-downloading. */
export function needsRevalidation(rec: ContentIntelRecord, currentScannerVersion: string, maxAgeMs?: number, now: number = Date.now()): boolean {
  if (!isDecisiveState(rec.state)) return true
  if (rec.scannerVersion !== currentScannerVersion) return true
  if (maxAgeMs && now - rec.stateSince > maxAgeMs) return true
  return false
}

/** A cached row counts as a hit only when its verdict was integrity-verified and is still valid. */
export function isCacheHit(
  rec: ContentIntelRecord | null,
  currentScannerVersion: string,
  maxAgeMs?: number,
  now?: number,
): boolean {
  if (!rec) return false
  if (!rec.verified) return false
  if (needsRevalidation(rec, currentScannerVersion, maxAgeMs, now)) return false
  return true
}

/** REVOKED marker for a future intelligence feed (e.g. package depublished after a SAFE verdict). */
export function revokedRecord(existing: ContentIntelRecord, scannerVersion: string, now?: number): ContentIntelRecord {
  const t = now ?? Date.now()
  return {
    ...existing,
    state: nextState(existing.state, 'revoke' as ContentIntelEvent),
    stateSince: t,
    lastSeen: t,
    scannerVersion,
  }
}

class ContentIntelTransitionGuard extends Error {
  constructor(state: ContentIntelState) {
    super(`ContentIntelRecord cannot transition to non-verdict state: ${state}`)
    this.name = 'ContentIntelTransitionGuard'
  }
}
