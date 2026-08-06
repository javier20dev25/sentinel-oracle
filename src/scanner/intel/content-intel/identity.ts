import { createHash } from 'node:crypto'

export const CONTENT_ID_PREFIX = 'sha512:'

/** sha512 hex digest of the raw tarball bytes. */
export function sha512Hex(data: Buffer): string {
  return createHash('sha512').update(data).digest('hex')
}

/** Canonical content identity: `sha512:<128 hex chars>`. */
export function deriveContentId(data: Buffer): string {
  return CONTENT_ID_PREFIX + sha512Hex(data)
}

const SRI_RE = /^([A-Za-z0-9_-]+)-([A-Za-z0-9+/=]+)$/

/**
 * Normalize an npm SRI string (`sha512-<base64>` — the `dist.integrity` field of
 * registry metadata) or an already-canonical `sha512:<hex>` into the canonical
 * content id. Returns null for empty/malformed values or non-sha512 algorithms.
 */
export function normalizeIntegrity(integrity: string | null | undefined): string | null {
  if (!integrity) return null
  const raw = String(integrity).trim()
  if (raw.startsWith(CONTENT_ID_PREFIX)) {
    const hex = raw.slice(CONTENT_ID_PREFIX.length)
    return /^[0-9a-fA-F]{128}$/.test(hex) ? CONTENT_ID_PREFIX + hex.toLowerCase() : null
  }
  const m = SRI_RE.exec(raw)
  if (!m) return null
  if (m[1].toLowerCase() !== 'sha512') return null
  try {
    const hex = Buffer.from(m[2], 'base64').toString('hex')
    return hex.length === 128 ? CONTENT_ID_PREFIX + hex : null
  } catch {
    return null
  }
}

/**
 * Verify downloaded tarball bytes against the registry's SRI (dist.integrity).
 * A mismatch means either the registry lied about the hash or the download was
 * tampered with — the content identity asserted by the registry must be
 * confirmed before a verdict is trusted into the cache.
 */
export function verifyBufferAgainstIntegrity(data: Buffer, integrity: string | null | undefined): boolean {
  const id = normalizeIntegrity(integrity)
  if (!id) return false
  return deriveContentId(data) === id
}
