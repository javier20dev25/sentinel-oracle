import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as path from 'path'
import * as os from 'os'
import * as fs from 'fs'
import { DatabaseStore } from '../src/storage/database'
import { AuthorizationQueue } from '../src/queue/authorization'
import { createAuthChallenge } from '../src/auth/challenge'
import type { GitHubClient } from '../src/github/client'

vi.mock('../src/auth/webauthn', () => ({
  verifyAssertion: vi.fn(),
  generateAssertion: vi.fn(),
  generateRegistration: vi.fn(),
  verifyRegistration: vi.fn(),
  getRpId: vi.fn(() => 'localhost'),
}))

import { verifyAssertion } from '../src/auth/webauthn'

function createMockClient(): GitHubClient {
  return {
    owner: 'test-owner',
    repo: 'test-repo',
    statusContext: 'Sentinel Authorization',
    setCommitStatus: vi.fn().mockResolvedValue(undefined),
    mergePR: vi.fn().mockResolvedValue(true),
  } as unknown as GitHubClient
}

function tmpDir(): string {
  const dir = path.join(os.tmpdir(), `oracle-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

const mockCredential = { id: 'test-cred-id', response: { authenticatorData: 'abc', signature: 'sig' } }
const mockChallenge = 'test-webauthn-challenge'

function registerTestDevice(db: DatabaseStore) {
  db.registerDevice({
    name: 'Test Phone',
    credentialId: 'test-cred-id',
    publicKey: 'mock-public-key',
    counter: 1,
    transports: '[]',
  })
}

describe('QR URL flow', () => {
  let db: DatabaseStore
  let dir: string

  beforeEach(() => {
    dir = tmpDir()
    db = new DatabaseStore(dir)
  })

  afterEach(() => {
    db.close()
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('creates challenge with URL in QR payload', () => {
    const result = createAuthChallenge(42, db, 45000, 'https://localhost:3443')
    expect(result.challengeId).toBeTruthy()
    expect(result.prNumber).toBe(42)
    expect(result.qrUrl).toBe(`https://localhost:3443/authorize?cid=${result.challengeId}&pr=42`)

    const parsed = JSON.parse(result.qrPayload)
    expect(parsed.v).toBe(1)
    expect(parsed.cid).toBe(result.challengeId)
    expect(parsed.pr).toBe(42)
    expect(parsed.url).toBe(result.qrUrl)
    expect(parsed.sig).toBeTruthy()
    expect(parsed.exp).toBeGreaterThan(Date.now())
  })

  it('can consume a valid challenge', () => {
    const result = createAuthChallenge(42, db, 45000, 'https://localhost:3443')
    const consumed = db.consumeChallenge(result.challengeId)
    expect(consumed).not.toBeNull()
    expect(consumed!.prNumber).toBe(42)
    expect(consumed!.data).toBeTruthy()
  })

  it('rejects double consumption', () => {
    const result = createAuthChallenge(42, db, 45000, 'https://localhost:3443')
    db.consumeChallenge(result.challengeId)
    const second = db.consumeChallenge(result.challengeId)
    expect(second).toBeNull()
  })

  it('rejects expired challenge', () => {
    const result = createAuthChallenge(42, db, -1000, 'https://localhost:3443')
    const consumed = db.consumeChallenge(result.challengeId)
    expect(consumed).toBeNull()
  })

  it('rejects nonexistent challenge', () => {
    const consumed = db.consumeChallenge('no-such-id')
    expect(consumed).toBeNull()
  })
})

describe('AuthorizationQueue', () => {
  let db: DatabaseStore
  let dir: string
  let mockClient: GitHubClient
  let queue: AuthorizationQueue

  beforeEach(() => {
    dir = tmpDir()
    db = new DatabaseStore(dir)
    mockClient = createMockClient()
    queue = new AuthorizationQueue(db, mockClient, 45000, 'https://localhost:3443', 'localhost')

    db.upsertPR({
      prNumber: 142,
      owner: 'test-owner',
      repo: 'test-repo',
      title: 'Fix race condition',
      author: 'maria',
      sha: 'abc123def456',
      ciStatus: 'passed',
      sentinelStatus: 'missing',
      authStatus: 'pending',
      createdAt: Date.now(),
      authorizedAt: null,
      deviceName: null,
    })

    registerTestDevice(db)
  })

  afterEach(() => {
    db.close()
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('lists pending PRs', () => {
    const prs = queue.getPendingPRs()
    expect(prs).toHaveLength(1)
    expect(prs[0].prNumber).toBe(142)
  })

  it('initiates authorization and returns QR URL', () => {
    const challenge = queue.initiateAuthorization(142)
    expect(challenge).not.toBeNull()
    expect(challenge!.prNumber).toBe(142)
    expect(challenge!.qrUrl).toContain('/authorize?cid=')
    expect(challenge!.qrUrl).toContain('pr=142')
  })

  it('returns null for non-existent PR', () => {
    const challenge = queue.initiateAuthorization(999)
    expect(challenge).toBeNull()
  })

  it('returns null for already authorized PR', () => {
    db.setAuthStatus(142, 'authorized')
    const challenge = queue.initiateAuthorization(142)
    expect(challenge).toBeNull()
  })

  it('returns null for rejected PR', () => {
    db.setAuthStatus(142, 'rejected')
    const challenge = queue.initiateAuthorization(142)
    expect(challenge).toBeNull()
  })

  it('confirms authorization with valid challengeId', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: true, credentialId: 'test-cred-id' })

    const challenge = queue.initiateAuthorization(142)
    const result = await queue.confirmAuthorization(142, challenge!.challengeId, mockCredential, mockChallenge)
    expect(result.success).toBe(true)

    const pr = db.getPRByNumber(142)
    expect(pr!.authStatus).toBe('authorized')

    expect(mockClient.setCommitStatus).toHaveBeenCalledWith(
      'abc123def456',
      'success',
      'Authorized via physical authentication'
    )
  })

  it('rejects confirm with wrong PR number', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: true, credentialId: 'test-cred-id' })

    const challenge = queue.initiateAuthorization(142)
    const result = await queue.confirmAuthorization(999, challenge!.challengeId, mockCredential, mockChallenge)
    expect(result.success).toBe(false)
    expect(db.getPRByNumber(142)!.authStatus).toBe('pending')
  })

  it('rejects confirm with invalid challengeId', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: true, credentialId: 'test-cred-id' })

    const result = await queue.confirmAuthorization(142, 'fake-challenge-id', mockCredential, mockChallenge)
    expect(result.success).toBe(false)
  })

  it('rejects duplicate confirmation', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: true, credentialId: 'test-cred-id' })

    const challenge = queue.initiateAuthorization(142)
    await queue.confirmAuthorization(142, challenge!.challengeId, mockCredential, mockChallenge)
    const second = await queue.confirmAuthorization(142, challenge!.challengeId, mockCredential, mockChallenge)
    expect(second.success).toBe(false)
  })

  it('rejects authorization and sets GitHub status', async () => {
    await queue.rejectAuthorization(142)
    const pr = db.getPRByNumber(142)
    expect(pr!.authStatus).toBe('rejected')
    expect(mockClient.setCommitStatus).toHaveBeenCalledWith(
      'abc123def456',
      'failure',
      'Authorization rejected'
    )
  })

  it('expires old pending PRs', () => {
    db.upsertPR({
      prNumber: 99,
      owner: 'test-owner',
      repo: 'test-repo',
      title: 'Old PR',
      author: 'juan',
      sha: 'oldsha',
      ciStatus: 'passed',
      sentinelStatus: 'missing',
      authStatus: 'pending',
      createdAt: Date.now() - 7200000,
      authorizedAt: null,
      deviceName: null,
    })

    const expired = queue.expireStaleChallenges()
    expect(expired).toBe(1)
    expect(db.getPRByNumber(99)!.authStatus).toBe('expired')
  })

  it('does not expire recent PRs', () => {
    const expired = queue.expireStaleChallenges()
    expect(expired).toBe(0)
    expect(db.getPRByNumber(142)!.authStatus).toBe('pending')
  })

  it('written audit log entries are readable', () => {
    queue.initiateAuthorization(142)
    const log = db.getAuditLog(10)
    expect(log.length).toBeGreaterThanOrEqual(1)
    expect(log[0].action).toBe('challenge_created')
    expect(log[0].prNumber).toBe(142)
  })

  it('logs authorization grant', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: true, credentialId: 'test-cred-id' })

    const challenge = queue.initiateAuthorization(142)
    await queue.confirmAuthorization(142, challenge!.challengeId, mockCredential, mockChallenge)
    const log = db.getAuditLog(10)
    expect(log.some(e => e.action === 'authorization_granted')).toBe(true)
  })

  it('logs authorization rejection', async () => {
    await queue.rejectAuthorization(142)
    const log = db.getAuditLog(10)
    expect(log.some(e => e.action === 'authorization_rejected')).toBe(true)
  })

  it('rejects confirm when WebAuthn fails', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: false })

    const challenge = queue.initiateAuthorization(142)
    const result = await queue.confirmAuthorization(142, challenge!.challengeId, mockCredential, mockChallenge)
    expect(result.success).toBe(false)
    expect(result.error).toBe('Biometric authentication failed')
    expect(db.getPRByNumber(142)!.authStatus).toBe('pending')
  })

  it('rejects confirm when system is locked', async () => {
    await queue.lockdown()
    const challenge = queue.initiateAuthorization(142)
    expect(challenge).toBeNull()

    const result = await queue.confirmAuthorization(142, 'any', mockCredential, mockChallenge)
    expect(result.success).toBe(false)
    expect(result.error).toBe('System is locked down')
  })

  it('revokes a device', () => {
    const ok = queue.revokeDevice('test-cred-id')
    expect(ok).toBe(true)
    expect(db.getDeviceByCredentialId('test-cred-id')).toBeUndefined()
  })

  it('returns false for unknown device revoke', () => {
    const ok = queue.revokeDevice('no-such-device')
    expect(ok).toBe(false)
  })

  it('rejects confirm with wrong PR in challenge', async () => {
    vi.mocked(verifyAssertion).mockResolvedValue({ verified: true, credentialId: 'test-cred-id' })

    const challenge = queue.initiateAuthorization(142)
    const result = await queue.confirmAuthorization(142, challenge!.challengeId, mockCredential, mockChallenge)

    expect(result.success).toBe(true)
    const pr = db.getPRByNumber(142)
    expect(pr!.authStatus).toBe('authorized')
  })
})
