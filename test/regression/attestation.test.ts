import { describe, it, expect, beforeEach } from 'vitest'
import { signScanAttestation, verifyScanAttestation } from '../../src/crypto/attestation'
import { initHmacKey } from '../../src/crypto/signing'

beforeEach(() => {
  initHmacKey(Buffer.from('test-attestation-seed', 'utf8'))
})

describe('scan attestation', () => {
  it('signs and verifies a valid attestation', () => {
    const att = signScanAttestation({
      prNumber: 42,
      scanHash: 'abc123',
      riskScore: 39,
      state: 'REVIEW',
      critical: 0,
      high: 3,
      medium: 2,
      low: 1,
      scannedAt: Date.now(),
    })
    const result = verifyScanAttestation(att)
    expect(result.valid).toBe(true)
  })

  it('detects tampered evidence (riskScore altered)', () => {
    const att = signScanAttestation({
      prNumber: 42,
      scanHash: 'abc123',
      riskScore: 0,
      state: 'PASS',
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scannedAt: Date.now(),
    })
    const tampered = { ...att, riskScore: 99, state: 'PASS' }
    const result = verifyScanAttestation(tampered)
    expect(result.valid).toBe(false)
    expect(result.reason).toBe('signature_mismatch')
  })

  it('does not trust the producer identity field — only the signature', () => {
    // Any producer label verifies as long as the signature matches the key.
    const att = signScanAttestation({
      prNumber: 7,
      scanHash: 'h',
      riskScore: 0,
      state: 'PASS',
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scannedAt: Date.now(),
    }, 'some-impostor-scanner')
    // verify() never compares producer against a trusted name.
    const result = verifyScanAttestation(att)
    expect(result.valid).toBe(true)
  })

  it('rejects malformed payloads', () => {
    expect(verifyScanAttestation(null).valid).toBe(false)
    expect(verifyScanAttestation('nope').valid).toBe(false)
    expect(verifyScanAttestation({}).valid).toBe(false)
    expect(verifyScanAttestation({ signature: 'abc' }).valid).toBe(false)
  })

  it('rejects stale attestations past maxAgeMs', () => {
    const att = signScanAttestation({
      prNumber: 7,
      scanHash: 'h',
      riskScore: 0,
      state: 'PASS',
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scannedAt: Date.now() - 60_000,
    })
    const result = verifyScanAttestation(att, { maxAgeMs: 30_000 })
    expect(result.valid).toBe(false)
    expect(result.reason).toBe('stale')
  })

  it('is deterministic for the same input and key', () => {
    const a = signScanAttestation({ prNumber: 1, scanHash: 'x', riskScore: 5, state: 'REVIEW', critical: 0, high: 0, medium: 0, low: 0, scannedAt: 123 })
    const b = signScanAttestation({ prNumber: 1, scanHash: 'x', riskScore: 5, state: 'REVIEW', critical: 0, high: 0, medium: 0, low: 0, scannedAt: 123 })
    expect(a.signature).toBe(b.signature)
  })
})
