/**
 * N3.3D — Cloud Match client (Oracle → Cloud).
 *
 * After the tarball phase the Oracle asks the Cloud's `POST /api/intelligence/match`
 * for SHARED, de-identified intelligence about each freshly integrity-verified
 * dependency: the N3.3 ladder (NO_MATCH / OBSERVED / CORROBORATED / MALICIOUS),
 * decisive state, known vs new behavior signals, artifact mismatch
 * (`identityLevel.hasCurrentArtifact`) and shared aggregates. The outcome is
 * fused into the IntelReport as a READ-ONLY annotation — it never rewrites
 * findings, deltas, risk or the existing scoring/verdict pipeline
 * (`buildSecurityDelta` and `determineScanVerdict` do not read
 * `dependencyMatchIntel`).
 *
 * This is a DIFFERENT layer from `enrichContentIntel` (cloud-lookup.ts):
 *
 *   - enrich mutates the LOCAL content-intel cache and is fail-CLOSED (a Cloud
 *     verdict can strengthen a local record; a rejected credential never looks
 *     like "the Cloud knows nothing").
 *   - the match is pure enrichment of the CURRENT scan: it NEVER writes anything
 *     and is fail-OPEN — 401/403/429/503/network/malformed all collapse to
 *     `{ kind: 'error' }`, the annotation is omitted and the local result stands.
 *
 * Contract points (pinned to the N3.3 contract `docs/design/n33-intelligence-match.md`
 * and the Cloud module `content_intel_match.ts` / route `/api/intelligence/match`):
 *   - contentId = 'sha512:' + sha512 hex of the MANIFEST utf8 bytes (same content
 *     identity the contribution payload uses; NOT the tarball cache id).
 *   - identity.packageHash = sha512 hex of the TARBALL bytes (`scan.contentId`),
 *     the field the Cloud compares to compute `hasCurrentArtifact`.
 *   - signals = closed N3.2 enum (shared `normalizeSignals`).
 *   - The request NEVER carries paths, PR/repo references or any user data.
 *   - Response validation mirrors the CLI's `validateMatchResult` (strict).
 *
 * Callers run matches CONCURRENTLY (one promise per dependency) and merge with
 * `Promise.allSettled`; each request is bounded by its own AbortController
 * timeout, so the whole match phase adds at most one timeout to the scan, never
 * one per dependency. `matchCloud` never throws.
 */
import type { Finding } from '../rules'
import type { TarballScanResult } from './deep-dependency'
import {
  identityFromManifest,
  signalSetFromScan,
  normalizeSignals,
  type ContributeIdentity,
  type ContributeSignal,
} from './cloud-contribute'
import { resolveCloudSettings } from './cloud-lookup'
import { CONTENT_ID_PREFIX, sha512Hex } from './content-intel/identity'
import { getScannerVersion } from './content-intel/scanner-version'

export const MATCH_ENDPOINT = '/api/intelligence/match'
export const MATCH_TIMEOUT_MS = 3000
export const MAX_SCANNER_VERSION_CHARS = 64
export const MAX_REQUEST_BODY_BYTES = 262144

export type IntelMatchState = 'NO_MATCH' | 'OBSERVED' | 'CORROBORATED' | 'MALICIOUS'
export type IntelVerdict = 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type IntelMatchMissReason = 'invalid' | 'revoked' | 'not_decisive' | 'scanner_mismatch' | 'ttl_expired'
export type IntelRiskBand = 'low' | 'medium' | 'high' | 'critical'

const MATCH_STATES: ReadonlyArray<string> = ['NO_MATCH', 'OBSERVED', 'CORROBORATED', 'MALICIOUS']
const VERDICTS: ReadonlyArray<string> = ['KNOWN_SAFE', 'SUSPICIOUS', 'MALICIOUS']
const MISS_REASONS: ReadonlyArray<string> = ['invalid', 'revoked', 'not_decisive', 'scanner_mismatch', 'ttl_expired']
const RISK_BANDS: ReadonlyArray<string> = ['low', 'medium', 'high', 'critical']
const SIGNATURE_RE = /^[0-9a-f]{64}$/
const CONTENT_ID_RE = /^sha512:[0-9a-f]{128}$/

export interface IntelMatchContentIdLevel {
  found: boolean
  verified: boolean
  usable: boolean
  verdict: IntelVerdict | null
  confidence: number | null
  signature: string | null
  reason: IntelMatchMissReason | null
  historyLength: number | null
}

export interface IntelMatchIdentityLevel {
  packageIdentity: string
  identityKnown: boolean
  observations: number
  distinctContributors: number
  artifacts: number
  corroborated: boolean
  corroboratedState: IntelVerdict | null
  knownSignals: string[]
  maxRisk: IntelRiskBand | null
  firstSeen: number | null
  hasCurrentArtifact: boolean
}

export interface IntelMatchSharedEvidence {
  observations: number
  distinctContributors: number
  artifacts: number
  riskBand: IntelRiskBand | null
  corroborated: boolean
  decisiveState: IntelVerdict | null
  firstSeen: number | null
}

export interface IntelMatchResult {
  state: IntelMatchState
  decisiveState: IntelVerdict | null
  contentId: string
  revoked: boolean
  contentIdLevel: IntelMatchContentIdLevel
  identityLevel: IntelMatchIdentityLevel | null
  match: {
    knownSignals: string[]
    newBehaviorSignals: string[]
    sharedEvidence: IntelMatchSharedEvidence | null
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isString(v: unknown): v is string {
  return typeof v === 'string'
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString)
}

function isNullableString(v: unknown): v is string | null | undefined {
  return v === null || v === undefined || isString(v)
}

function isNullableFiniteNumber(v: unknown): v is number | null | undefined {
  return v === null || v === undefined || (typeof v === 'number' && Number.isFinite(v))
}

function isRecordOrNull(v: unknown): boolean {
  return v === null || v === undefined || isRecord(v)
}

/**
 * Strict structural validation of the N3.3 match response (mirrors the CLI's
 * `validateMatchResult`). Anything off-contract returns null — the caller treats
 * it as a fail-open `error`, never as a match.
 */
export function validateMatchResult(value: unknown): IntelMatchResult | null {
  if (!isRecord(value)) return null
  if (!isString(value.state) || !MATCH_STATES.includes(value.state)) return null
  if (value.decisiveState !== null && value.decisiveState !== undefined) {
    if (!isString(value.decisiveState) || !VERDICTS.includes(value.decisiveState)) return null
  }
  if (!isString(value.contentId) || !CONTENT_ID_RE.test(value.contentId)) return null
  if (typeof value.revoked !== 'boolean') return null

  const cl = value.contentIdLevel
  if (!isRecord(cl)) return null
  if (typeof cl.found !== 'boolean') return null
  if (typeof cl.verified !== 'boolean') return null
  if (typeof cl.usable !== 'boolean') return null
  if (cl.verdict !== null && cl.verdict !== undefined) {
    if (!isString(cl.verdict) || !VERDICTS.includes(cl.verdict)) return null
  }
  if (!isNullableFiniteNumber(cl.confidence)) return null
  if (cl.confidence !== null && cl.confidence !== undefined && (cl.confidence < 0 || cl.confidence > 1)) return null
  if (!isNullableString(cl.signature)) return null
  if (cl.signature !== null && cl.signature !== undefined && !SIGNATURE_RE.test(cl.signature)) return null
  if (cl.reason !== null && cl.reason !== undefined) {
    if (!isString(cl.reason) || !MISS_REASONS.includes(cl.reason)) return null
  }
  if (!isNullableFiniteNumber(cl.historyLength)) return null

  if (!isRecordOrNull(value.identityLevel)) return null
  if (value.identityLevel !== null && value.identityLevel !== undefined) {
    const il = value.identityLevel as Record<string, unknown>
    if (!isString(il.packageIdentity) || il.packageIdentity.length === 0) return null
    if (typeof il.identityKnown !== 'boolean') return null
    if (!isNullableFiniteNumber(il.observations)) return null
    if (!isNullableFiniteNumber(il.distinctContributors)) return null
    if (!isNullableFiniteNumber(il.artifacts)) return null
    if (typeof il.corroborated !== 'boolean') return null
    if (il.corroboratedState !== null && il.corroboratedState !== undefined) {
      if (!isString(il.corroboratedState) || !VERDICTS.includes(il.corroboratedState)) return null
    }
    if (!isStringArray(il.knownSignals)) return null
    if (il.maxRisk !== null && il.maxRisk !== undefined) {
      if (!isString(il.maxRisk) || !RISK_BANDS.includes(il.maxRisk)) return null
    }
    if (!isNullableFiniteNumber(il.firstSeen)) return null
    if (typeof il.hasCurrentArtifact !== 'boolean') return null
  }

  const m = value.match
  if (!isRecord(m)) return null
  if (!isStringArray(m.knownSignals)) return null
  if (!isStringArray(m.newBehaviorSignals)) return null
  if (!isRecordOrNull(m.sharedEvidence)) return null
  if (m.sharedEvidence !== null && m.sharedEvidence !== undefined) {
    const se = m.sharedEvidence as Record<string, unknown>
    if (!isNullableFiniteNumber(se.observations)) return null
    if (!isNullableFiniteNumber(se.distinctContributors)) return null
    if (!isNullableFiniteNumber(se.artifacts)) return null
    if (se.riskBand !== null && se.riskBand !== undefined) {
      if (!isString(se.riskBand) || !RISK_BANDS.includes(se.riskBand)) return null
    }
    if (typeof se.corroborated !== 'boolean') return null
    if (se.decisiveState !== null && se.decisiveState !== undefined) {
      if (!isString(se.decisiveState) || !VERDICTS.includes(se.decisiveState)) return null
    }
    if (!isNullableFiniteNumber(se.firstSeen)) return null
  }

  return value as unknown as IntelMatchResult
}

export interface IntelMatchRequest {
  contentId: string
  identity?: ContributeIdentity
  signals?: ContributeSignal[]
  scannerVersion: string
}

/**
 * Build the N3.3 match request from a finished tarball scan. Returns null when
 * the tarball carried no package.json manifest (there is nothing to match).
 * contentId = sha512 of the MANIFEST bytes; identity.packageHash = sha512 of
 * the TARBALL bytes; signals = the closed N3.2 enum of the scan. No paths, no
 * PR/repo references, no user data ever enter the request.
 */
export function buildMatchRequest(scan: TarballScanResult, findings: readonly Finding[]): IntelMatchRequest | null {
  // Real registry tarballs keep the `package/` prefix on every path, so resolve
  // the manifest robustly instead of requiring the bare `package.json` key.
  const manifest = scan.files.get('package.json') ?? scan.files.get('package/package.json')
  if (typeof manifest !== 'string' || manifest.length === 0) return null
  const request: IntelMatchRequest = {
    contentId: CONTENT_ID_PREFIX + sha512Hex(Buffer.from(manifest, 'utf8')),
    scannerVersion: getScannerVersion().trim().slice(0, MAX_SCANNER_VERSION_CHARS) || 'dev',
  }
  const signals = normalizeSignals(signalSetFromScan(scan.delta, scan.lifecycleScripts, findings))
  if (signals.length > 0) request.signals = signals
  const identity = identityFromManifest(manifest, scan.contentId)
  if (identity) request.identity = identity
  return request
}

export type MatchOutcome =
  | { kind: 'match'; result: IntelMatchResult }
  | { kind: 'skipped'; reason: string }
  | { kind: 'error'; message?: string }

export interface MatchCloudOptions {
  baseUrl?: string
  token?: string
  timeoutMs?: number
  scannerVersion?: string
}

/**
 * POST the N3.3 match request. FAIL-OPEN: never throws; every failure mode
 * (unconfigured, timeout, network, HTTP error, malformed body, invalid response)
 * collapses into `{ kind: 'error' }` so the scan continues with local analysis.
 * Unlike the contribution client (which surfaces 401/403 for operator messages),
 * the match is enrichment-only: 401/403 are ordinary errors, not "the Cloud
 * knows nothing" — the annotation is simply omitted.
 */
export async function matchCloud(
  scan: TarballScanResult,
  findings: readonly Finding[],
  opts?: MatchCloudOptions,
): Promise<MatchOutcome> {
  const { baseUrl, token } = resolveCloudSettings({ baseUrl: opts?.baseUrl, token: opts?.token })
  if (!baseUrl || !token) return { kind: 'error', message: 'cloud not configured' }
  const request = buildMatchRequest(scan, findings)
  if (!request) return { kind: 'skipped', reason: 'no_manifest' }
  const timeoutMs = opts?.timeoutMs ?? MATCH_TIMEOUT_MS
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(`${baseUrl}${MATCH_ENDPOINT}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    })
    if (res.status !== 200) {
      return { kind: 'error', message: `match failed with status ${res.status}` }
    }
    let data: unknown
    try {
      data = await res.json()
    } catch {
      return { kind: 'error', message: 'invalid JSON match response' }
    }
    const result = validateMatchResult(data)
    if (!result) return { kind: 'error', message: 'match response failed contract validation' }
    return { kind: 'match', result }
  } catch (err) {
    return { kind: 'error', message: err instanceof Error ? err.message : String(err) }
  } finally {
    clearTimeout(timer)
  }
}

export type MatchRecommendation = 'BLOCK' | 'VERIFY' | 'CONTEXT' | 'KNOWN_SAFE' | 'none'

export interface DependencyMatchAnnotation {
  name: string
  version: string
  state: IntelMatchState
  decisiveState: IntelVerdict | null
  revoked: boolean
  /** Read-only hint; NEVER consumed by scoring/verdict. See annotateFromMatch. */
  recommendation: MatchRecommendation
  contentIdLevel: {
    found: boolean
    verified: boolean
    usable: boolean
    verdict: IntelVerdict | null
    reason: IntelMatchMissReason | null
    historyLength: number | null
  }
  identityLevel: {
    packageIdentity: string
    observations: number
    distinctContributors: number
    artifacts: number
    corroborated: boolean
    corroboratedState: IntelVerdict | null
    knownSignals: string[]
    maxRisk: IntelRiskBand | null
    hasCurrentArtifact: boolean
  } | null
  knownSignals: string[]
  newBehaviorSignals: string[]
  sharedEvidence: IntelMatchSharedEvidence | null
}

/**
 * Map a validated match onto a READ-ONLY dependency annotation. The N3.3 §5
 * semantics, reproduced for the Oracle:
 *
 *   - BLOCK  (fast-path) ⇔ state MALICIOUS AND contentIdLevel.verified AND
 *            contentIdLevel.usable AND identityLevel.hasCurrentArtifact AND a
 *            valid signature — the artifact physically seen matches shared
 *            corroborated knowledge.
 *   - VERIFY ⇔ state MALICIOUS but NOT hasCurrentArtifact (identity known, bytes
 *            not seen before). Never a blind BLOCK on identity alone: the local
 *            scan must verify the current artifact.
 *   - CONTEXT ⇔ CORROBORATED (corroboration NEVER equals MALICIOUS; the decisive
 *            state carries the verdict) or OBSERVED (shared observation, no
 *            independent corroboration).
 *   - KNOWN_SAFE ⇔ decisive KNOWN_SAFE on a usable record (informational cache
 *            semantics — the Oracle still performs its own analysis).
 *   - none ⇔ NO_MATCH (never implies SAFE) or any revoked content (a revoked
 *            verdict is never served as MALICIOUS).
 *
 * This function is pure; it cannot mutate scoring because nothing downstream
 * reads `dependencyMatchIntel`.
 */
export function annotateFromMatch(result: IntelMatchResult, scan: TarballScanResult): DependencyMatchAnnotation {
  const name = scan.delta?.packageName ?? 'unknown'
  const version = scan.delta?.toVersion ?? scan.resolvedVersion ?? ''

  let recommendation: MatchRecommendation
  if (result.revoked) {
    recommendation = 'none'
  } else if (
    result.state === 'MALICIOUS' &&
    result.contentIdLevel.verified === true &&
    result.contentIdLevel.usable === true &&
    result.identityLevel?.hasCurrentArtifact === true &&
    result.contentIdLevel.signature !== null
  ) {
    recommendation = 'BLOCK'
  } else if (result.state === 'MALICIOUS') {
    recommendation = 'VERIFY'
  } else if (result.state === 'CORROBORATED' || result.state === 'OBSERVED') {
    recommendation = result.decisiveState === 'KNOWN_SAFE' && result.contentIdLevel.usable ? 'KNOWN_SAFE' : 'CONTEXT'
  } else {
    recommendation = 'none'
  }

  return {
    name,
    version,
    state: result.state,
    decisiveState: result.decisiveState,
    revoked: result.revoked,
    recommendation,
    contentIdLevel: {
      found: result.contentIdLevel.found,
      verified: result.contentIdLevel.verified,
      usable: result.contentIdLevel.usable,
      verdict: result.contentIdLevel.verdict,
      reason: result.contentIdLevel.reason,
      historyLength: result.contentIdLevel.historyLength,
    },
    identityLevel: result.identityLevel
      ? {
          packageIdentity: result.identityLevel.packageIdentity,
          observations: result.identityLevel.observations,
          distinctContributors: result.identityLevel.distinctContributors,
          artifacts: result.identityLevel.artifacts,
          corroborated: result.identityLevel.corroborated,
          corroboratedState: result.identityLevel.corroboratedState,
          knownSignals: result.identityLevel.knownSignals,
          maxRisk: result.identityLevel.maxRisk,
          hasCurrentArtifact: result.identityLevel.hasCurrentArtifact,
        }
      : null,
    knownSignals: result.match.knownSignals,
    newBehaviorSignals: result.match.newBehaviorSignals,
    sharedEvidence: result.match.sharedEvidence,
  }
}
