import { createHmac, timingSafeEqual } from 'crypto'
import { getHmacKey } from './signing'
import type { ScanState } from '../scanner/verdict'

export const ATTESTATION_VERSION = 1

/**
 * Signed scan attestation.
 *
 * The attestation binds the HMAC signature ONLY to evidence fields (prNumber,
 * scanHash, riskScore, state, severity counts, scannedAt). It carries no
 * scanner-identity claim that is ever trusted: `producer` is informational
 * and MAY be forged — verification recomputes the signature over the evidence
 * and nothing else. A consumer must conclude "these bytes came from a server
 * holding the key", never "this is the genuine Sentinel Oracle".
 */
export interface ScanAttestation {
  version: typeof ATTESTATION_VERSION
  producer: string
  prNumber: number
  scanHash: string
  riskScore: number
  state: ScanState
  critical: number
  high: number
  medium: number
  low: number
  scannedAt: number
  signature: string
}

export type ScanAttestationInput = Omit<ScanAttestation, 'signature' | 'version' | 'producer'>

export function signScanAttestation(input: ScanAttestationInput, producer = 'sentinel-oracle'): ScanAttestation {
  const body = { version: ATTESTATION_VERSION, producer, ...input } as Omit<ScanAttestation, 'signature'>
  return { ...body, signature: computeSignature(body) }
}

export function verifyScanAttestation(
  att: unknown,
  opts?: { maxAgeMs?: number },
): { valid: boolean; reason?: string } {
  if (!att || typeof att !== 'object') return { valid: false, reason: 'malformed' }
  const a = att as ScanAttestation
  if (typeof a.signature !== 'string' || a.signature.length === 0) return { valid: false, reason: 'missing_signature' }
  const { signature, ...body } = a
  const expected = computeSignature(body)
  const sig = Buffer.from(signature, 'hex')
  const exp = Buffer.from(expected, 'hex')
  if (sig.length !== exp.length || !timingSafeEqual(sig, exp)) return { valid: false, reason: 'signature_mismatch' }
  if (opts?.maxAgeMs != null) {
    const age = Date.now() - a.scannedAt
    if (age > opts.maxAgeMs || age < 0) return { valid: false, reason: 'stale' }
  }
  return { valid: true }
}

function computeSignature(body: Omit<ScanAttestation, 'signature'>): string {
  return createHmac('sha256', getHmacKey()).update(canonicalize(body)).digest('hex')
}

function canonicalize(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {}
  for (const key of Object.keys(obj).sort()) sorted[key] = obj[key]
  return JSON.stringify(sorted)
}
