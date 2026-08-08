import type { ContentIntelStore } from './content-intel/store'
import type { ContentIntelEvidence } from './content-intel/record'
import { stateToRisk } from './content-intel/state'
import { getScannerVersion } from './content-intel/scanner-version'

/**
 * Outcome of a Cloud intelligence lookup. Fail-closed: anything that is not a
 * structurally valid verdict (found/usable/contentId present, signature well
 * formed) is never treated as a hit.
 */
export type CloudLookupOutcome =
  | { kind: 'hit'; verdict: 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS'; confidence?: number; signature?: string; usable: true }
  | { kind: 'unusable'; reason?: string }
  | { kind: 'miss' }
  | { kind: 'error'; message?: string }

export interface CloudLookupOptions {
  baseUrl?: string
  token?: string
  timeoutMs?: number
  scannerVersion?: string
}

export interface EnrichContentIntelOptions {
  repoKey?: string
  baseUrl?: string
  token?: string
  timeoutMs?: number
  scannerVersion?: string
}

const DEFAULT_TIMEOUT_MS = 3000
const SIGNATURE_RE = /^[0-9a-f]{64}$/
const VERDICTS = ['KNOWN_SAFE', 'SUSPICIOUS', 'MALICIOUS'] as const

let configuredSettings: { baseUrl?: string; token?: string } | null = null

/**
 * Point the cloud lookup client at a Cloud deployment from loaded config
 * (called wherever loadConfig() runs: scan and server startup/reload). Empty
 * values clear the config so the environment fallback takes over. This makes
 * config.json connection settings effective — without it only the
 * SENTINEL_CLOUD_URL / SENTINEL_CLOUD_API_TOKEN env vars work.
 */
export function configureCloudLookup(baseUrl?: string, token?: string): void {
  configuredSettings = baseUrl && token ? { baseUrl, token } : null
}

/** Resolved Cloud settings: explicit opts > configured (config.json) > env. */
function cloudSettings(opts?: { baseUrl?: string; token?: string }): { baseUrl: string; token: string } {
  const baseUrl = (opts?.baseUrl ?? configuredSettings?.baseUrl ?? process.env.SENTINEL_CLOUD_URL ?? '')
    .trim()
    .replace(/\/+$/, '')
  const token = (opts?.token ?? configuredSettings?.token ?? process.env.SENTINEL_CLOUD_API_TOKEN ?? '').trim()
  return { baseUrl, token }
}

/**
 * Resolved Cloud connection settings under the same precedence used by the
 * lookup client: explicit opts > configured (config.json via configureCloudLookup)
 * > SENTINEL_CLOUD_URL / SENTINEL_CLOUD_API_TOKEN env vars. Shared by the
 * contribution client so both directions of the N3 contract read one config.
 */
export function resolveCloudSettings(opts?: { baseUrl?: string; token?: string }): { baseUrl: string; token: string } {
  return cloudSettings(opts)
}

/** True when both a Cloud URL and an API token are configured. */
export function hasCloudConnection(opts?: { baseUrl?: string; token?: string }): boolean {
  const { baseUrl, token } = cloudSettings(opts)
  return baseUrl.length > 0 && token.length > 0
}

function isVerdict(v: unknown): v is (typeof VERDICTS)[number] {
  return typeof v === 'string' && (VERDICTS as readonly string[]).includes(v)
}

/**
 * Ask the Cloud for intelligence about one content id. Never throws: every
 * failure mode (unconfigured, timeout, network, HTTP error, malformed body,
 * broken signature) collapses into `{ kind: 'error' }`. 401/403 are errors,
 * not misses — a rejected credential must not look like "the Cloud knows
 * nothing about this artifact".
 */
export async function lookupCloud(contentId: string, opts?: CloudLookupOptions): Promise<CloudLookupOutcome> {
  const { baseUrl, token } = cloudSettings(opts)
  if (!baseUrl || !token) return { kind: 'error' }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  try {
    const body: Record<string, string> = { contentId }
    if (opts?.scannerVersion) body.scannerVersion = opts.scannerVersion
    const res = await fetch(`${baseUrl}/api/intelligence/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    if (res.status === 401 || res.status === 403) return { kind: 'error' }
    if (!res.ok) return { kind: 'error' }
    const data: unknown = await res.json()
    if (!data || typeof data !== 'object') return { kind: 'error' }
    const record = data as Record<string, unknown>
    if (typeof record.found !== 'boolean') return { kind: 'error' }
    if (record.found === false) return { kind: 'miss' }
    if (typeof record.contentId !== 'string' || record.contentId.length === 0) return { kind: 'error' }
    if (typeof record.usable !== 'boolean') return { kind: 'error' }
    if (record.usable === false) {
      return { kind: 'unusable', reason: typeof record.reason === 'string' ? record.reason : undefined }
    }
    if (!isVerdict(record.verdict)) return { kind: 'error' }
    let signature: string | undefined
    const rawSignature = record.signature
    if (rawSignature !== undefined && rawSignature !== null) {
      if (typeof rawSignature !== 'string' || !SIGNATURE_RE.test(rawSignature)) return { kind: 'error' }
      signature = rawSignature
    }
    const hit: CloudLookupOutcome = { kind: 'hit', verdict: record.verdict, usable: true }
    if (typeof record.confidence === 'number' && Number.isFinite(record.confidence)) {
      hit.confidence = record.confidence
    }
    if (signature) hit.signature = signature
    return hit
  } catch (err) {
    return { kind: 'error', message: err instanceof Error ? err.message : String(err) }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Enrichment of the LOCAL content-intel cache from the CLOUD. Fail-closed: the
 * Cloud can only strengthen a local verdict (KNOWN_SAFE/UNKNOWN/SCANNING ->
 * SUSPICIOUS/MALICIOUS); a Cloud KNOWN_SAFE verdict never touches the record
 * and an already-decisive MALICIOUS/SUSPICIOUS record is never downgraded.
 * Never throws. Returns a short outcome string for logging ('enriched' |
 * 'noop' | 'upgrade' | 'unavailable') or null when there is nothing to do.
 */
export async function enrichContentIntel(
  store: ContentIntelStore | null,
  contentId: string,
  opts?: EnrichContentIntelOptions,
): Promise<string | null> {
  if (!store || !contentId) return null
  try {
    const current = store.lookup(contentId)
    if (!current) return 'noop'
    if (!hasCloudConnection({ baseUrl: opts?.baseUrl, token: opts?.token })) return 'unavailable'
    const outcome = await lookupCloud(contentId, {
      baseUrl: opts?.baseUrl,
      token: opts?.token,
      timeoutMs: opts?.timeoutMs,
      scannerVersion: opts?.scannerVersion ?? getScannerVersion(),
    })
    if (outcome.kind !== 'hit') return outcome.kind === 'miss' ? 'noop' : 'unavailable'
    if (outcome.verdict === 'KNOWN_SAFE') return 'noop'
    if (current.state === 'MALICIOUS' || current.state === 'SUSPICIOUS') return 'noop'
    if (current.state !== 'KNOWN_SAFE' && current.state !== 'UNKNOWN' && current.state !== 'SCANNING') return 'noop'
    const evidence: ContentIntelEvidence = {
      risk: stateToRisk(outcome.verdict) ?? 'low',
      filesChanged: 0,
      newDomains: [],
      newNetworkCalls: 0,
      newCapabilities: [],
      newScripts: [],
      newBinaries: [],
      lifecycleScripts: [],
      summary: `Cloud intelligence: ${outcome.verdict}`,
      findings: [],
    }
    store.record(contentId, outcome.verdict, evidence, { verified: true, repoKey: opts?.repoKey })
    return current.state === 'KNOWN_SAFE' ? 'upgrade' : 'enriched'
  } catch {
    return 'unavailable'
  }
}
