import { describe, it, expect } from 'vitest'
import { createChallengeToken, verifyChallengeToken, generateNonce } from '../../src/crypto/signing'

describe('createChallengeToken', () => {
  it('creates a signed challenge with correct fields', () => {
    const token = createChallengeToken('challenge-1', 42)
    expect(token.challengeId).toBe('challenge-1')
    expect(token.prNumber).toBe(42)
    expect(token.timestamp).toBeGreaterThan(0)
    expect(token.signature).toBeTruthy()
    expect(token.signature.length).toBe(64)
  })

  it('produces different signatures for different payloads', () => {
    const t1 = createChallengeToken('a', 1)
    const t2 = createChallengeToken('b', 2)
    expect(t1.signature).not.toBe(t2.signature)
  })
})

describe('verifyChallengeToken', () => {
  it('verifies a valid token within TTL', () => {
    const token = createChallengeToken('challenge-1', 42)
    expect(verifyChallengeToken(token, 60000)).toBe(true)
  })

  it('rejects a token with modified prNumber', () => {
    const token = createChallengeToken('challenge-1', 42)
    const tampered = { ...token, prNumber: 99 }
    expect(verifyChallengeToken(tampered, 60000)).toBe(false)
  })

  it('rejects a token with modified challengeId', () => {
    const token = createChallengeToken('challenge-1', 42)
    const tampered = { ...token, challengeId: 'different' }
    expect(verifyChallengeToken(tampered, 60000)).toBe(false)
  })

  it('rejects an expired token', () => {
    const token = createChallengeToken('challenge-1', 42)
    expect(verifyChallengeToken(token, -1)).toBe(false)
  })
})

describe('generateNonce', () => {
  it('generates a 64-character hex string', () => {
    const nonce = generateNonce()
    expect(nonce).toBeTruthy()
    expect(typeof nonce).toBe('string')
    expect(nonce.length).toBe(64)
  })

  it('generates unique values', () => {
    const a = generateNonce()
    const b = generateNonce()
    expect(a).not.toBe(b)
  })
})
