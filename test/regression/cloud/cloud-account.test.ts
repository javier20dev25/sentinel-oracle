import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from 'vitest'
import * as path from 'path'
import * as fs from 'fs'

const tmpDir = path.join(__dirname, 'tmp-cloud-account-test')
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true })
}

// Mock the 'os' module to redirect CONFIG_PATH + dataDir in config.ts to our temp directory
// (isolated from cloud-config.test.ts, which uses its own directory).
vi.mock('os', async (importOriginal) => {
  const original = await importOriginal<typeof import('os')>()
  return {
    ...original,
    homedir: () => require('path').join(__dirname, 'tmp-cloud-account-test'),
  }
})

import { loadConfig } from '../../../src/config'
import {
  assertSecureCloudUrl,
  clearCloudAccount,
  hasStoredCloudAccount,
  isLoopbackHost,
  loadCloudAccount,
  resolveOracleCloudConnection,
  saveCloudAccount,
} from '../../../src/cloud/account'

const accountFile = path.join(tmpDir, '.sentinel-oracle', 'cloud-account.json')

describe('cloud/account: secure base URL', () => {
  it('rejects plain http to non-loopback hosts', () => {
    expect(() => assertSecureCloudUrl('http://cloud.example.com')).toThrow(/insecure/i)
  })

  it('rejects non-URL strings', () => {
    expect(() => assertSecureCloudUrl('not a url')).toThrow(/invalid/i)
  })

  it('accepts https URLs and strips trailing slashes', () => {
    expect(assertSecureCloudUrl('https://cloud.example.com/')).toBe('https://cloud.example.com')
  })

  it('accepts loopback http for local development', () => {
    expect(assertSecureCloudUrl('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080')
    expect(assertSecureCloudUrl('http://localhost:8080')).toBe('http://localhost:8080')
  })

  it('loopback detection handles localhost, 127.x and ::1', () => {
    expect(isLoopbackHost('localhost')).toBe(true)
    expect(isLoopbackHost('127.0.0.1')).toBe(true)
    expect(isLoopbackHost('::1')).toBe(true)
    expect(isLoopbackHost('cloud.example.com')).toBe(false)
  })
})

describe('cloud/account: encrypted at-rest account store', () => {
  let config: ReturnType<typeof loadConfig>

  beforeAll(() => {
    fs.mkdirSync(path.dirname(accountFile), { recursive: true })
    config = loadConfig()
  })

  afterEach(() => {
    clearCloudAccount(config)
  })

  afterAll(() => {
    try {
      fs.rmSync(path.dirname(accountFile), { recursive: true, force: true })
    } catch {}
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    } catch {}
  })

  it('has no stored account initially', () => {
    expect(hasStoredCloudAccount(config)).toBe(false)
    expect(loadCloudAccount(config)).toBeNull()
  })

  it('persists the account with the token encrypted (never in plaintext)', () => {
    saveCloudAccount(config, 'https://cloud.example.com', 'super-secret-token', {
      subjectId: 'sub-123',
      user: 'dev@example.com',
      plan: 'pro',
      planLabel: 'Pro',
    })
    expect(hasStoredCloudAccount(config)).toBe(true)
    const raw = fs.readFileSync(accountFile, 'utf8')
    expect(raw).not.toContain('super-secret-token')
    const account = loadCloudAccount(config)
    expect(account).not.toBeNull()
    expect(account!.token).toBe('super-secret-token')
    expect(account!.baseUrl).toBe('https://cloud.example.com')
    expect(account!.subjectId).toBe('sub-123')
    expect(account!.planLabel).toBe('Pro')
  })

  it('loads null for corrupt account files', () => {
    fs.writeFileSync(accountFile, '{not json', 'utf8')
    expect(loadCloudAccount(config)).toBeNull()
    expect(hasStoredCloudAccount(config)).toBe(true)
    clearCloudAccount(config)
    expect(hasStoredCloudAccount(config)).toBe(false)
  })

  it('clears the account and falls back to config/env', () => {
    clearCloudAccount(config)
    expect(hasStoredCloudAccount(config)).toBe(false)
    const conn = resolveOracleCloudConnection(config)
    expect(conn.linked).toBe(false)
    expect(conn.baseUrl).toBe('')
    expect(conn.token).toBe('')
  })

  it('resolves stored account over config/env values', () => {
    saveCloudAccount(config, 'https://stored.example.com', 'stored-token', {
      subjectId: 'sub-abc', user: null, plan: 'free', planLabel: 'Free',
    })
    config.cloudApiUrl = 'https://cfg.example.com'
    config.cloudApiToken = 'cfg-token'
    const conn = resolveOracleCloudConnection(config)
    expect(conn.linked).toBe(true)
    expect(conn.baseUrl).toBe('https://stored.example.com')
    expect(conn.token).toBe('stored-token')
    clearCloudAccount(config)
  })
})