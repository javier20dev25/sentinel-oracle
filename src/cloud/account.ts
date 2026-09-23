import * as fs from 'fs'
import * as path from 'path'
import type { Config } from '../config'
import { encrypt, decrypt } from '../storage/encryption'
import { configureCloudLookup, setCloudMotorFull } from '../scanner/intel/cloud-lookup'

/**
 * Sentinel Cloud account for the Oracle: a consumer bearer token stored at
 * rest encrypted (AES-256-GCM with the Oracle's main encryption key) plus the
 * bare minimum of profile/usage data needed by the UI.
 *
 * Security model:
 *  - The bearer token NEVER leaves the Oracle. The UI only ever talks to the
 *    Oracle's own /api/cloud/* routes; the Oracle proxies to Sentinel Cloud
 *    server-side.
 *  - The token is never returned to the browser and never logged.
 *  - The account file is mode 0600 and the token inside is encrypted; the
 *    capabilities/usage payloads (account name, used/remaining pulses) are the
 *    only things surfaced to the UI.
 *  - Only https:// Cloud URLs are accepted (loopback allowed for local
 *    development); a bearer token must never travel in the clear.
 */

export interface CloudAccount {
  baseUrl: string
  token: string
  subjectId: string | null
  user: string | null
  plan: string | null
  planLabel: string | null
  linkedAt: string
}

export interface CloudUsage {
  subjectId: string
  plan: string | null
  period: string
  used: number
  limit: number
  remaining: number
  ratio: number
}

export interface CloudCapabilities {
  user: string | null
  subjectId: string
  plan: string
  planLabel: string
  expiresAt: string
  issuedAt: string
  capabilities: Record<string, boolean>
  limits: Record<string, number>
}

const DEFAULT_TIMEOUT_MS = 8000

function accountFilePath(config: Config): string {
  return path.join(config.dataDir, 'cloud-account.json')
}

export function hasStoredCloudAccount(config: Config): boolean {
  try {
    return fs.existsSync(accountFilePath(config))
  } catch {
    return false
  }
}

export function loadCloudAccount(config: Config): CloudAccount | null {
  try {
    const file = accountFilePath(config)
    if (!fs.existsSync(file)) return null
    const raw = fs.readFileSync(file, 'utf8')
    const data = JSON.parse(raw) as Record<string, unknown>
    if (typeof data.baseUrl !== 'string' || typeof data.tokenEnc !== 'string') return null
    let token: string
    try {
      token = decrypt(data.tokenEnc, config.encryptionKey)
    } catch {
      return null
    }
    if (!token) return null
    return {
      baseUrl: data.baseUrl,
      token,
      subjectId: typeof data.subjectId === 'string' ? data.subjectId : null,
      user: typeof data.user === 'string' ? data.user : null,
      plan: typeof data.plan === 'string' ? data.plan : null,
      planLabel: typeof data.planLabel === 'string' ? data.planLabel : null,
      linkedAt: typeof data.linkedAt === 'string' ? data.linkedAt : new Date().toISOString(),
    }
  } catch {
    return null
  }
}

export function saveCloudAccount(
  config: Config,
  baseUrl: string,
  token: string,
  account: Pick<CloudAccount, 'subjectId' | 'user' | 'plan' | 'planLabel'>,
): void {
  const tokenEnc = encrypt(token, config.encryptionKey)
  const file = accountFilePath(config)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        baseUrl,
        tokenEnc,
        subjectId: account.subjectId,
        user: account.user,
        plan: account.plan,
        planLabel: account.planLabel,
        linkedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
    { mode: 0o600 },
  )
}

export function clearCloudAccount(config: Config): void {
  try {
    const file = accountFilePath(config)
    if (fs.existsSync(file)) fs.unlinkSync(file)
  } catch {
    // best effort
  }
}

export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false
  const h = host.toLowerCase().replace(/^\[|\]$/g, '')
  return h === 'localhost' || h === '::1' || /^127(\.\d{1,3}){3}$/.test(h)
}

/**
 * Refuses Cloud base URLs that would send the bearer token in the clear unless
 * the server is loopback (local development). Blocks http/ws to non-loopback
 * hosts and invalid URLs before any authenticated request is attempted.
 */
export function assertSecureCloudUrl(rawUrl: string): string {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new Error(`Invalid Sentinel Cloud base URL: '${rawUrl}'.`)
  }
  if (parsed.protocol !== 'https:' && !isLoopbackHost(parsed.hostname)) {
    throw new Error(
      `Refusing insecure Sentinel Cloud base URL '${rawUrl}'. Only https:// (or loopback for local development) is allowed; bearer tokens must never travel in the clear.`,
    )
  }
  return rawUrl.replace(/\/+$/, '')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

function validateCapabilities(body: unknown): CloudCapabilities | null {
  if (!isRecord(body)) return null
  if (!isString(body.subjectId) || !isString(body.plan) || !isString(body.planLabel)) return null
  if (!isString(body.expiresAt) || !isString(body.issuedAt)) return null
  if (body.user !== null && body.user !== undefined && !isString(body.user)) return null
  if (!isRecord(body.capabilities) || !isRecord(body.limits)) return null
  return {
    user: typeof body.user === 'string' ? body.user : null,
    subjectId: body.subjectId,
    plan: body.plan,
    planLabel: body.planLabel,
    expiresAt: body.expiresAt,
    issuedAt: body.issuedAt,
    capabilities: body.capabilities as Record<string, boolean>,
    limits: body.limits as Record<string, number>,
  }
}

function validateUsage(body: unknown): CloudUsage | null {
  if (!isRecord(body)) return null
  if (!isString(body.subjectId)) return null
  if (!isFiniteNumber(body.used) || !isFiniteNumber(body.limit)) return null
  let remaining = 0
  let ratio = 1
  if (typeof body.remaining === 'number' && Number.isFinite(body.remaining)) remaining = body.remaining
  if (typeof body.ratio === 'number' && Number.isFinite(body.ratio)) ratio = body.ratio
  return {
    subjectId: body.subjectId,
    plan: isString(body.plan) ? body.plan : null,
    period: isString(body.period) ? body.period : '',
    used: body.used,
    limit: body.limit,
    remaining,
    ratio,
  }
}

export async function fetchCloudCapabilities(
  baseUrl: string,
  token: string,
  opts?: { timeoutMs?: number },
): Promise<{ ok: true; data: CloudCapabilities } | { ok: false; status?: number; error?: string }> {
  const url = assertSecureCloudUrl(baseUrl) + '/api/auth/capabilities'
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      signal: controller.signal,
    })
    if (res.status === 401 || res.status === 403) {
      return { ok: false, status: res.status, error: 'Invalid or expired Sentinel Cloud API token.' }
    }
    if (!res.ok) return { ok: false, status: res.status, error: `Cloud request failed (${res.status}).` }
    const body: unknown = await res.json()
    const data = validateCapabilities(body)
    if (!data) return { ok: false, status: res.status, error: 'Invalid capabilities response from Sentinel Cloud.' }
    return { ok: true, data }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error && err.message.includes('Refusing insecure') ? err.message : 'Cloud unreachable (network or timeout).',
    }
  } finally {
    clearTimeout(timer)
  }
}

export async function fetchCloudUsage(
  baseUrl: string,
  token: string,
  opts?: { timeoutMs?: number },
): Promise<{ ok: true; data: CloudUsage } | { ok: false; status?: number; error?: string }> {
  const url = assertSecureCloudUrl(baseUrl) + '/api/auth/usage'
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      signal: controller.signal,
    })
    if (res.status === 401 || res.status === 403) {
      return { ok: false, status: res.status, error: 'Invalid or expired Sentinel Cloud API token.' }
    }
    if (!res.ok) return { ok: false, status: res.status, error: `Cloud request failed (${res.status}).` }
    const body: unknown = await res.json()
    const data = validateUsage(body)
    if (!data) return { ok: false, status: res.status, error: 'Invalid usage response from Sentinel Cloud.' }
    return { ok: true, data }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error && err.message.includes('Refusing insecure') ? err.message : 'Cloud unreachable (network or timeout).',
    }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Resolve the Cloud connection the Oracle should use: the linked (stored,
 * encrypted) account wins; otherwise fall back to config.json/env values for
 * backward compatibility. Returns a masked description suitable for the UI.
 */
export function resolveOracleCloudConnection(
  config: Config,
): { baseUrl: string; token: string; linked: boolean; viaConfigOrEnv: boolean } {
  const stored = loadCloudAccount(config)
  if (stored && stored.token) {
    return { baseUrl: stored.baseUrl, token: stored.token, linked: true, viaConfigOrEnv: false }
  }
  const baseUrl = (config.cloudApiUrl || '').trim().replace(/\/+$/, '')
  const token = (config.cloudApiToken || '').trim()
  return { baseUrl, token, linked: false, viaConfigOrEnv: baseUrl.length > 0 && token.length > 0 }
}

/** Point the cloud intel clients (lookup/contribute/match) at the resolved connection. */
export function applyConfiguredCloud(config: Config): void {
  const conn = resolveOracleCloudConnection(config)
  configureCloudLookup(conn.baseUrl, conn.token)
  setCloudMotorFull(config.cloudMotorFull)
}