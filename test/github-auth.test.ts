import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { generateKeyPairSync } from 'crypto'
import { GitHubAppAuth, type GitHubAppConfig } from '../src/github/auth'

function tmpDir(): string {
  const dir = path.join(os.tmpdir(), `oracle-github-app-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function generateTestKeyPair(): { privateKey: string } {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  })
  return { privateKey }
}

describe('GitHubAppAuth', () => {
  let testDir: string
  let keyPair: { privateKey: string }
  let keyPath: string
  let config: GitHubAppConfig

  beforeEach(() => {
    testDir = tmpDir()
    keyPair = generateTestKeyPair()
    keyPath = path.join(testDir, 'private-key.pem')
    fs.writeFileSync(keyPath, keyPair.privateKey, 'utf8')
    config = {
      appId: '123456',
      installationId: '654321',
      privateKeyPath: keyPath,
    }
  })

  afterEach(() => {
    try { fs.rmSync(testDir, { recursive: true, force: true }) } catch {}
  })

  describe('constructor', () => {
    it('creates instance with valid config', () => {
      const auth = new GitHubAppAuth(config)
      expect(auth).toBeInstanceOf(GitHubAppAuth)
    })

    it('throws if appId is empty', () => {
      expect(() => new GitHubAppAuth({ ...config, appId: '' })).toThrow('GitHub App requires')
    })

    it('throws if installationId is empty', () => {
      expect(() => new GitHubAppAuth({ ...config, installationId: '' })).toThrow('GitHub App requires')
    })

    it('throws if privateKeyPath is empty', () => {
      expect(() => new GitHubAppAuth({ ...config, privateKeyPath: '' })).toThrow('GitHub App requires')
    })

    it('throws if private key file does not exist', () => {
      expect(() => new GitHubAppAuth({ ...config, privateKeyPath: path.join(testDir, 'nonexistent.pem') }))
        .toThrow()
    })

    it('throws if private key file is not a valid PEM', () => {
      const badPath = path.join(testDir, 'bad-key.pem')
      fs.writeFileSync(badPath, 'not a real key', 'utf8')
      expect(() => new GitHubAppAuth({ ...config, privateKeyPath: badPath }))
        .toThrow('valid PEM')
    })

    it('requires private key to contain BEGIN marker', () => {
      const badPath = path.join(testDir, 'no-begin.pem')
      fs.writeFileSync(badPath, 'some random data', 'utf8')
      expect(() => new GitHubAppAuth({ ...config, privateKeyPath: badPath }))
        .toThrow('valid PEM')
    })
  })

  describe('generateJWT', () => {
    it('generates a valid JWT with three parts', () => {
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()

      const parts = jwt.split('.')
      expect(parts).toHaveLength(3)
      expect(parts[0]).toBeTruthy()
      expect(parts[1]).toBeTruthy()
      expect(parts[2]).toBeTruthy()
    })

    it('decodes to correct header (RS256)', () => {
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()

      const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString())
      expect(header.alg).toBe('RS256')
      expect(header.typ).toBe('JWT')
    })

    it('decodes to correct payload with appId', () => {
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()

      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString())
      expect(payload.iss).toBe('123456')
    })

    it('has correct expiration (600s from iat)', () => {
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()

      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString())
      expect(payload.exp - payload.iat).toBe(600)
    })

    it('produces JWTs with valid structure on each call', () => {
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()
      const parts = jwt.split('.')
      expect(parts).toHaveLength(3)
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
      expect(payload.iat).toBeGreaterThan(0)
      expect(payload.exp).toBe(payload.iat + 600)
    })

    it('signature verifies with the public key', () => {
      const { createPublicKey, verify } = require('crypto')
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()

      const parts = jwt.split('.')
      const message = `${parts[0]}.${parts[1]}`
      const sig = Buffer.from(parts[2], 'base64url')

      const publicKey = createPublicKey(keyPair.privateKey)
      const valid = verify(
        'RSA-SHA256',
        Buffer.from(message),
        publicKey,
        sig
      )
      expect(valid).toBe(true)
    })

    it('rejects tampered JWT signature', () => {
      const { createPublicKey, verify } = require('crypto')
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()

      const parts = jwt.split('.')
      const tamperedMessage = `${parts[0]}.eyJ0YW1wZXJlZCI6dHJ1ZX0`
      const sig = Buffer.from(parts[2], 'base64url')

      const publicKey = createPublicKey(keyPair.privateKey)
      const valid = verify(
        'RSA-SHA256',
        Buffer.from(tamperedMessage),
        publicKey,
        sig
      )
      expect(valid).toBe(false)
    })
  })

  describe('token caching', () => {
    it('starts with no cached token', () => {
      const auth = new GitHubAppAuth(config)
      expect(auth.getCachedTokenData()).toBeNull()
    })

    it('clearCache resets cached token', () => {
      const auth = new GitHubAppAuth(config)
      const jwt = auth.generateJWT()
      expect(auth.getCachedTokenData()).toBeNull()
      auth.clearCache()
      expect(auth.getCachedTokenData()).toBeNull()
    })
  })

  describe('edge cases', () => {
    it('handles very long key paths', () => {
      const longPath = path.join(testDir, 'a'.repeat(200) + '.pem')
      fs.writeFileSync(longPath, keyPair.privateKey, 'utf8')
      const auth = new GitHubAppAuth({ ...config, privateKeyPath: longPath })
      const jwt = auth.generateJWT()
      const parts = jwt.split('.')
      expect(parts).toHaveLength(3)
    })

    it('handles multiple JWT generations without state corruption', () => {
      const auth = new GitHubAppAuth(config)
      for (let i = 0; i < 10; i++) {
        const jwt = auth.generateJWT()
        const parts = jwt.split('.')
        expect(parts).toHaveLength(3)
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
        expect(payload.iss).toBe('123456')
        expect(payload.exp - payload.iat).toBe(600)
      }
    })
  })
})

describe('GitHubClient mode detection', () => {
  it('passes PAT string mode correctly', async () => {
    const { GitHubClient } = await import('../src/github/client')
    const client = new GitHubClient('ghp_test_token', 'owner', 'repo', 'Sentinel Authorization')
    expect(client.authMode).toBe('pat')
  })

  it('passes GitHub App config mode correctly', async () => {
    const { GitHubClient } = await import('../src/github/client')

    const testDir = tmpDir()
    const keyPair = generateTestKeyPair()
    const keyPath = path.join(testDir, 'key.pem')
    fs.writeFileSync(keyPath, keyPair.privateKey, 'utf8')

    try {
      const client = new GitHubClient(
        { appId: '123', installationId: '456', privateKeyPath: keyPath },
        'owner',
        'repo',
        'Sentinel Authorization'
      )
      expect(client.authMode).toBe('github_app')
      expect(client.appAuthInstance).not.toBeNull()
    } finally {
      try { fs.rmSync(testDir, { recursive: true, force: true }) } catch {}
    }
  })
})
