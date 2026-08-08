/**
 * Cloud contribution client for the N3 contract (Oracle → Cloud).
 *
 * When a tarball scan completes with integrity-verified evidence, the Oracle
 * pushes a self-contained intelligence record to the Cloud's
 * `POST /api/intelligence/contribute` endpoint. The client wraps EXISTING scan
 * output (DependencyDelta, typed findings, the tarball package.json) — it never
 * invents a new scanner.
 *
 * Contract points (pinned to the deployed Cloud commit):
 *   - contentId = 'sha512:' + sha512 hex of the MANIFEST utf8 bytes (NOT the
 *     local content-intel cache id, which is sha512 of the tarball bytes).
 *   - evidence.manifestHash = sha256(JSON.stringify({alerts, deltas})) hex, first 24 chars.
 *   - Response 200 must carry `applied` (boolean) and `verified === false`.
 *
 * Fail-safe by design: like the lookup/enrichment client, nothing here ever
 * throws. Every failure mode (unconfigured, timeout, network, HTTP error,
 * malformed body, disabled endpoint) collapses into a non-throwing outcome, so
 * the merge/enforcement flow is never blocked. 429 honors Retry-After with a
 * bounded backoff before giving up.
 */
import { createHash } from 'node:crypto'
import type { Finding } from '../rules'
import type { DependencyDelta, IntelRisk } from './types'
import type { TarballScanResult } from './deep-dependency'
import { CONTENT_ID_PREFIX, sha512Hex } from './content-intel/identity'
import { stateFromRisk } from './content-intel/state'
import { getScannerVersion } from './content-intel/scanner-version'
import { resolveCloudSettings } from './cloud-lookup'

export const CONTRIBUTE_ENDPOINT = '/api/intelligence/contribute'
export const MAX_MANIFEST_BYTES = 262144
export const MAX_ITEMS_PER_LIST = 100
export const MAX_SCANNER_VERSION_CHARS = 64
export const MAX_429_RETRIES = 2
export const MAX_RETRY_DELAY_MS = 60_000
const DEFAULT_TIMEOUT_MS = 3000

/**
 * Closed enum of normalized dependency signals (N3.2). Each value is the
 * canonical name for an observable the Oracle's tarball scanner already emits
 * (capabilities, domains, install scripts, binaries, lifecycle hooks, typed
 * findings). `signals` is OPTIONAL on the evidence and only sent when non-empty.
 */
export const CONTRIBUTE_SIGNALS = [
  'install_script',
  'network',
  'credential_access',
  'child_process',
  'runtime_execution',
  'obfuscation',
  'encoded_payload',
  'filesystem',
  'binary',
  'download',
  'config_tampering',
  'suspicious_url',
] as const
export type ContributeSignal = (typeof CONTRIBUTE_SIGNALS)[number]
export const MAX_SIGNALS = 32
const SIGNAL_SET = new Set<string>(CONTRIBUTE_SIGNALS)

/**
 * Dependency identity for the top-level N3.2 `identity` field. `packageHash` is
 * the sha512 hex of the TARBALL bytes (the registry `dist.integrity` / local
 * content-intel cache id — `sha512:<hex>`), NOT the manifest contentId used in
 * the contribute payload. Only present when the registry exposed a stable SRI.
 */
export interface ContributeIdentity {
  ecosystem: 'npm'
  package: string
  version?: string
  packageHash?: string
}

export type ContributeState = 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type ContributeSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING' | 'INFO'

export interface ContributeItem {
  type: string
  severity: ContributeSeverity
  riskLevel: number
  message: string
  evidence?: string
  script?: string
  category?: string
}

export interface ContributePayload {
  manifest: string
  contentId: string
  state: ContributeState
  scannerVersion: string
  /** N3.2 dependency identity; only present when the package.json name is a non-empty string. */
  identity?: ContributeIdentity
  evidence: {
    risk: IntelRisk
    manifestHash: string
    alerts: ContributeItem[]
    deltas: ContributeItem[]
    /** N3.2 normalized signals; only present when non-empty. */
    signals?: ContributeSignal[]
  }
}

export interface BuildContributePayloadOptions {
  manifest: string
  state: ContributeState
  risk: IntelRisk
  alerts: ContributeItem[]
  deltas: ContributeItem[]
  scannerVersion?: string
  signals?: readonly string[]
  identity?: ContributeIdentity
}

/** Drop a UTF-8 string to a whole-character prefix that fits in maxBytes. */
export function truncateUtf8(text: string, maxBytes: number): string {
  const bytes = Buffer.byteLength(text, 'utf8')
  if (bytes <= maxBytes) return text
  let lo = 0
  let hi = text.length
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2)
    if (Buffer.byteLength(text.slice(0, mid), 'utf8') <= maxBytes) lo = mid
    else hi = mid - 1
  }
  return text.slice(0, lo)
}

function normalizeScannerVersion(v?: string): string {
  const raw = (v ?? getScannerVersion()).trim()
  if (!raw) return 'dev'
  return raw.slice(0, MAX_SCANNER_VERSION_CHARS)
}

/**
 * Canonical risk → state mapping (mirrors content-intel/state.stateFromRisk,
 * which maps decisive risks to exactly KNOWN_SAFE | SUSPICIOUS | MALICIOUS).
 */
function contractStateFromRisk(risk: IntelRisk): ContributeState {
  return stateFromRisk(risk) as ContributeState
}

/**
 * Build the exact N3 request body. The contract's derived values are computed
 * from the FINAL (capped) arrays and the capped manifest, so what the client
 * sends always matches what the Cloud can recompute server-side. `signals` and
 * `identity` are OPTIONAL additive N3.2 fields: neither participates in
 * manifestHash (which stays sha256(JSON.stringify({alerts, deltas}))[:24]).
 */
export function buildContributePayload(opts: BuildContributePayloadOptions): ContributePayload {
  const manifest = truncateUtf8(opts.manifest, MAX_MANIFEST_BYTES)
  const alerts = opts.alerts.slice(0, MAX_ITEMS_PER_LIST)
  const deltas = opts.deltas.slice(0, MAX_ITEMS_PER_LIST)
  const scannerVersion = normalizeScannerVersion(opts.scannerVersion)
  const contentId = CONTENT_ID_PREFIX + sha512Hex(Buffer.from(manifest, 'utf8'))
  const manifestHash = createHash('sha256')
    .update(JSON.stringify({ alerts, deltas }))
    .digest('hex')
    .slice(0, 24)
  const evidence: ContributePayload['evidence'] = { risk: opts.risk, manifestHash, alerts, deltas }
  const signals = opts.signals ? normalizeSignals(opts.signals) : []
  if (signals.length > 0) evidence.signals = signals
  const payload: ContributePayload = {
    manifest,
    contentId,
    state: opts.state,
    scannerVersion,
    evidence,
  }
  if (opts.identity) payload.identity = opts.identity
  return payload
}

const FINDING_SEVERITY_TO_CONTRACT: Record<Finding['severity'], ContributeSeverity> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'INFO',
}

export const SEVERITY_RISK_LEVEL: Record<ContributeSeverity, number> = {
  CRITICAL: 9,
  HIGH: 7,
  MEDIUM: 5,
  WARNING: 3,
  INFO: 1,
}

/** Oracle Finding → N3 contribute item (severity + bounded riskLevel). */
export function findingToContributeItem(f: Finding): ContributeItem {
  const severity = FINDING_SEVERITY_TO_CONTRACT[f.severity]
  const item: ContributeItem = {
    type: f.category,
    severity,
    riskLevel: SEVERITY_RISK_LEVEL[severity],
    message: f.title,
    category: f.category,
  }
  if (f.description) item.evidence = f.description
  if (f.code) item.evidence = item.evidence ? `${item.evidence}\n${f.code}` : f.code
  return item
}

const CAPABILITY_SEVERITY: Record<string, ContributeSeverity> = {
  Shell: 'CRITICAL',
  'Dynamic Code': 'HIGH',
  Network: 'HIGH',
  Filesystem: 'MEDIUM',
  Crypto: 'MEDIUM',
}

/**
 * Normalize an arbitrary signal list into the closed N3.2 enum: drop unknown
 * values, dedupe, emit in the enum's canonical (stable) order, cap at 32.
 */
export function normalizeSignals(signals: readonly string[]): ContributeSignal[] {
  const present = new Set<ContributeSignal>()
  for (const s of signals) {
    if (SIGNAL_SET.has(s)) present.add(s as ContributeSignal)
  }
  return CONTRIBUTE_SIGNALS.filter(s => present.has(s)).slice(0, MAX_SIGNALS)
}

const MAX_PACKAGE_CHARS = 128

/**
 * Extract the N3.2 dependency identity from the tarball's package.json.
 * Returns undefined when the manifest is missing, malformed, or carries no
 * non-empty `name` (the contract only admits an identity when the package name
 * is present and ≤128 chars; ecosystem is fixed lowercase 'npm'). `packageHash`
 * is the sha512 hex of the tarball bytes when a stable SRI exists (`scan.contentId`).
 */
export function identityFromManifest(manifest: string | null | undefined, packageHash?: string): ContributeIdentity | undefined {
  if (typeof manifest !== 'string' || manifest.length === 0) return undefined
  try {
    const pkg = JSON.parse(manifest) as { name?: unknown; version?: unknown }
    if (typeof pkg?.name !== 'string') return undefined
    const name = pkg.name.trim()
    if (!name || name.length > MAX_PACKAGE_CHARS) return undefined
    const identity: ContributeIdentity = { ecosystem: 'npm', package: name }
    if (typeof pkg.version === 'string' && pkg.version.trim()) identity.version = pkg.version.trim()
    if (packageHash) identity.packageHash = packageHash
    return identity
  } catch {
    return undefined
  }
}

/** Download primitives inside a lifecycle command (ChainDrop install vector). */
const DOWNLOAD_RE = /\b(curl|wget|iwr)\b|invoke-webrequest/i
/** Clear-cut execution primitives inside a lifecycle command (mirrors dangerousScript's execution half). */
const EXECUTION_RE = /\bbash\b|\bsh\s+-c\b|\bpowershell\b|\bcmd\s+\/?c\b|node\s+[\w./'-]+\.(mjs|js|cjs|ts)/i

/**
 * Map the Oracle tarball scanner's raw signals onto the closed N3.2 enum.
 * Conservative by design: only clear-cut signals are mapped, everything
 * ambiguous is deliberately omitted (e.g. the Crypto capability, which is not
 * obfuscation/encoding; and no `suspicious_url`/`config_tampering`, which the
 * tarball scanner cannot classify today). The result is deduplicated, ordered
 * by the enum's declaration order, and capped at MAX_SIGNALS.
 */
export function signalSetFromScan(
  delta: DependencyDelta | undefined,
  lifecycleScripts: readonly { script: string; command: string; dangerous: boolean }[],
  findings: readonly Finding[],
): ContributeSignal[] {
  const signals = new Set<ContributeSignal>()
  if (delta) {
    for (const cap of delta.newCapabilities) {
      switch (cap) {
        case 'Shell':
          signals.add('child_process')
          break
        case 'Dynamic Code':
          signals.add('runtime_execution')
          break
        case 'Network':
          signals.add('network')
          break
        case 'Filesystem':
          signals.add('filesystem')
          break
      }
    }
    if (delta.newDomains.length > 0) signals.add('network')
    if (delta.newScripts.length > 0) signals.add('install_script')
    if (delta.newBinaries.length > 0) signals.add('binary')
  }
  for (const hook of lifecycleScripts) {
    signals.add('install_script')
    if (!hook.dangerous) continue
    const command = hook.command.toLowerCase()
    if (DOWNLOAD_RE.test(command)) signals.add('download')
    if (EXECUTION_RE.test(command)) signals.add('runtime_execution')
  }
  for (const f of findings) {
    if (f.category === 'secret') signals.add('credential_access')
    const title = f.title.toLowerCase()
    if (title.includes('base64-decoded')) signals.add('encoded_payload')
    if (title.includes('obfuscat') || title.includes('hex-encoded')) signals.add('obfuscation')
    if (title.includes('outbound network request')) signals.add('network')
    if (title.includes('os command execution')) signals.add('child_process')
    if (title.includes('file system access')) signals.add('filesystem')
    if (
      title.includes('unsafe eval') ||
      title.includes('dynamic function') ||
      title.includes('settimeout with string') ||
      title.includes('dynamic require')
    ) {
      signals.add('runtime_execution')
    }
  }
  return normalizeSignals([...signals])
}

/**
 * Serialize a fresh tarball scan into the N3 contribution inputs. Returns null
 * when there is nothing to contribute (no delta, or the tarball carried no
 * package.json manifest). Alerts are the typed scan findings; deltas are the
 * version-delta signal set (new capabilities/domains/scripts/binaries) plus a
 * files-changed note when the delta is otherwise clean. N3.2 `signals` and
 * `identity` are attached only when present.
 */
export function serializeScanEvidence(
  scan: TarballScanResult,
  findings: Finding[],
): { manifest: string; state: ContributeState; risk: IntelRisk; alerts: ContributeItem[]; deltas: ContributeItem[]; signals?: ContributeSignal[]; identity?: ContributeIdentity } | null {
  if (!scan.delta) return null
  const manifest = scan.files.get('package.json')
  if (typeof manifest !== 'string' || manifest.length === 0) return null

  const deltas: ContributeItem[] = []
  for (const cap of scan.delta.newCapabilities) {
    const severity = CAPABILITY_SEVERITY[cap] ?? 'MEDIUM'
    deltas.push({
      type: 'capability',
      severity,
      riskLevel: SEVERITY_RISK_LEVEL[severity],
      message: `Capability introduced: ${cap}`,
      category: 'supply_chain',
    })
  }
  for (const domain of scan.delta.newDomains) {
    deltas.push({
      type: 'network',
      severity: 'MEDIUM',
      riskLevel: SEVERITY_RISK_LEVEL.MEDIUM,
      message: `New network endpoint: ${domain}`,
      evidence: domain,
      category: 'supply_chain',
    })
  }
  for (const script of scan.delta.newScripts) {
    deltas.push({
      type: 'install_script',
      severity: 'HIGH',
      riskLevel: SEVERITY_RISK_LEVEL.HIGH,
      message: `Install-time script: ${script}`,
      script,
      category: 'supply_chain',
    })
  }
  for (const binary of scan.delta.newBinaries) {
    deltas.push({
      type: 'binary',
      severity: 'HIGH',
      riskLevel: SEVERITY_RISK_LEVEL.HIGH,
      message: `Prebuilt binary: ${binary}`,
      evidence: binary,
      category: 'supply_chain',
    })
  }
  if (deltas.length === 0) {
    deltas.push({
      type: 'files_changed',
      severity: 'INFO',
      riskLevel: SEVERITY_RISK_LEVEL.INFO,
      message: `${scan.delta.filesChanged} files in package`,
      evidence: `${scan.delta.packageName}@${scan.delta.toVersion}`,
      category: 'supply_chain',
    })
  }

  const signals = signalSetFromScan(scan.delta, scan.lifecycleScripts, findings)
  const identity = identityFromManifest(manifest, scan.contentId)

  return {
    manifest,
    state: contractStateFromRisk(scan.delta.risk),
    risk: scan.delta.risk,
    alerts: findings.map(findingToContributeItem),
    deltas,
    ...(signals.length > 0 ? { signals } : {}),
    ...(identity ? { identity } : {}),
  }
}

export type ContributeOutcome =
  | {
      kind: 'accepted'
      applied: boolean
      contentId: string
      state: string
      previousState: string
      reason: string | null
      scannerVersion: string
      verified: false
    }
  | { kind: 'rejected'; status: number; message: string }
  | { kind: 'disabled' }
  | { kind: 'error'; message?: string }

export interface ContributeEvidenceOptions extends BuildContributePayloadOptions {
  baseUrl?: string
  token?: string
  timeoutMs?: number
  /** Max 429 retries (each honoring Retry-After) before giving up. */
  maxRetries?: number
}

interface HttpOutcome {
  ok: boolean
  status: number
  text: string
  retryAfterMs: number | null
  message?: string
}

async function postOnce(url: string, payload: ContributePayload, token: string, timeoutMs: number): Promise<HttpOutcome> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })
    const text = await res.text()
    return { ok: res.ok, status: res.status, text, retryAfterMs: parseRetryAfter(res.headers.get('retry-after')) }
  } catch (err) {
    return { ok: false, status: 0, text: '', retryAfterMs: null, message: err instanceof Error ? err.message : String(err) }
  } finally {
    clearTimeout(timer)
  }
}

/** Retry-After header → bounded millisecond delay (supports seconds or HTTP-date). */
export function parseRetryAfter(v: string | null | undefined): number | null {
  if (!v) return null
  const secs = Number(v)
  if (Number.isFinite(secs)) return Math.min(Math.max(0, Math.floor(secs)) * 1000, MAX_RETRY_DELAY_MS)
  const t = Date.parse(v)
  if (Number.isFinite(t)) return Math.min(Math.max(0, t - Date.now()), MAX_RETRY_DELAY_MS)
  return null
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function isDisabledBody(text: string): boolean {
  try {
    const d = JSON.parse(text) as Record<string, unknown>
    return typeof d?.error === 'string' && d.error.includes('disabled')
  } catch {
    return false
  }
}

function validateContributeResponse(data: unknown): ContributeOutcome {
  if (!data || typeof data !== 'object') return { kind: 'error', message: 'contribution response is not an object' }
  const rec = data as Record<string, unknown>
  if (typeof rec.applied !== 'boolean') return { kind: 'error', message: 'contribution response missing applied' }
  if (rec.verified !== false) return { kind: 'error', message: 'contribution response verified must be false (pinned contract)' }
  if (typeof rec.contentId !== 'string') return { kind: 'error', message: 'contribution response missing contentId' }
  if (typeof rec.state !== 'string') return { kind: 'error', message: 'contribution response missing state' }
  if (typeof rec.previousState !== 'string') return { kind: 'error', message: 'contribution response missing previousState' }
  if (rec.reason !== null && typeof rec.reason !== 'string') return { kind: 'error', message: 'contribution response reason malformed' }
  if (typeof rec.scannerVersion !== 'string') return { kind: 'error', message: 'contribution response missing scannerVersion' }
  return {
    kind: 'accepted',
    applied: rec.applied,
    contentId: rec.contentId,
    state: rec.state,
    previousState: rec.previousState,
    reason: rec.reason,
    scannerVersion: rec.scannerVersion,
    verified: false,
  }
}

function classifyResponse(http: HttpOutcome): ContributeOutcome {
  switch (http.status) {
    case 200: {
      try {
        return validateContributeResponse(JSON.parse(http.text))
      } catch {
        return { kind: 'error', message: 'invalid JSON contribution response' }
      }
    }
    case 401:
      return { kind: 'rejected', status: 401, message: 'Cloud rejected the contribution token (401) — check SENTINEL_CLOUD_API_TOKEN / cloudApiToken' }
    case 403:
      return { kind: 'rejected', status: 403, message: 'Cloud denied the contribute capability (403) — the PAT lacks the content-intel contribute grant' }
    case 400:
      return { kind: 'rejected', status: 400, message: 'Cloud rejected the contribution body (400)' }
    case 413:
      return { kind: 'rejected', status: 413, message: 'Contribution payload too large (413)' }
    case 429:
      return { kind: 'rejected', status: 429, message: 'Cloud contribution quota/rate limit (429) after retries' }
    case 503:
      if (isDisabledBody(http.text)) return { kind: 'disabled' }
      return { kind: 'error', message: 'Cloud contribute endpoint unavailable (503)' }
    default:
      return { kind: 'error', message: `Unexpected cloud response status ${http.status}` }
  }
}

/**
 * POST the N3 contribution payload. Never throws. 429 responses honor
 * Retry-After (bounded) and are retried up to maxRetries before giving up;
 * 401/403/400/413 and every other failure are surfaced without retry so an
 * operator-facing message (token / capability / body) is never masked.
 */
export async function contributeEvidence(opts: ContributeEvidenceOptions): Promise<ContributeOutcome> {
  const { baseUrl, token } = resolveCloudSettings({ baseUrl: opts.baseUrl, token: opts.token })
  if (!baseUrl || !token) return { kind: 'error', message: 'cloud not configured' }
  const payload = buildContributePayload(opts)
  const url = `${baseUrl}${CONTRIBUTE_ENDPOINT}`
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const maxRetries = opts.maxRetries ?? MAX_429_RETRIES
  let attempt = 0
  for (;;) {
    const http = await postOnce(url, payload, token, timeoutMs)
    if (!http.ok && http.status === 0) return { kind: 'error', message: http.message }
    if (http.status !== 429 || attempt >= maxRetries) return classifyResponse(http)
    attempt++
    const delay = http.retryAfterMs ?? 0
    if (delay > 0) await sleep(delay)
  }
}

/**
 * Fire-and-forget wrapper for a finished tarball scan: serializes the scan's
 * evidence and contributes it. Never throws and never blocks the merge flow.
 * Returns a short status string for debug logging ('submitted' | 'rejected' |
 * 'disabled' | 'unavailable') or null when there is nothing to contribute.
 */
export async function contributeScanEvidence(
  scan: TarballScanResult,
  findings: Finding[],
  opts?: { baseUrl?: string; token?: string; scannerVersion?: string; timeoutMs?: number; maxRetries?: number },
): Promise<string | null> {
  const serialized = serializeScanEvidence(scan, findings)
  if (!serialized) return null
  const outcome = await contributeEvidence({
    ...serialized,
    baseUrl: opts?.baseUrl,
    token: opts?.token,
    scannerVersion: opts?.scannerVersion,
    timeoutMs: opts?.timeoutMs,
    maxRetries: opts?.maxRetries,
  })
  switch (outcome.kind) {
    case 'accepted':
      return outcome.applied ? 'submitted' : `rejected:${outcome.reason ?? 'applied=false'}`
    case 'disabled':
      return 'disabled'
    case 'rejected':
      return `rejected:${outcome.status}`
    case 'error':
      return 'unavailable'
  }
}
