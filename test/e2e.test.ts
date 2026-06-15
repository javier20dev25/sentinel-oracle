import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import * as path from 'path'
import * as os from 'os'
import * as fs from 'fs'
import * as http from 'http'
import { DatabaseStore } from '../src/storage/database'
import { createApp } from '../src/server'
import type { GitHubClient } from '../src/github/client'
import type { Config } from '../src/config'
import { initHmacKey } from '../src/crypto/signing'

function tmpDir(): string {
  const dir = path.join(os.tmpdir(), `oracle-e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function createMockClient(): GitHubClient {
  return {
    owner: 'test-owner',
    repo: 'test-repo',
    statusContext: 'Sentinel Authorization',
    authMode: 'pat',
    listOpenPRs: async () => [],
    updateCheckRun: async () => {},
    mergePR: async () => true,
  } as unknown as GitHubClient
}

function createTestConfig(dataDir: string): Config {
  return {
    port: 0,
    host: 'localhost',
    bindAddress: '127.0.0.1',
    dataDir,
    githubToken: '',
    githubAppId: '',
    githubInstallationId: '',
    githubPrivateKeyPath: '',
    githubOwner: 'test-owner',
    githubRepo: 'test-repo',
    githubStatusContext: 'Sentinel Authorization',
    serverOrigin: 'http://localhost:0',
    rpId: 'localhost',
    challengeTtlMs: 45000,
    rateLimitAuth: 100,
    rateLimitWindowMs: 60000,
    encryptionKey: Buffer.alloc(0),
    approveReasonRequired: false,
    locked: false,
    passwordHash: '',
    enrollmentTokenTtlMs: 300000,
    githubWebhookSecret: '',
    scanEnabled: false,
  }
}

function fetch(method: string, url: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const opts: http.RequestOptions = {
      hostname: u.hostname,
      port: parseInt(u.port, 10),
      path: u.pathname + u.search,
      method,
      headers,
    }
    const req = http.request(opts, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        resolve({ status: res.statusCode || 0, headers: res.headers, body: data })
      })
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

describe('E2E: full HTTP API flow', () => {
  let dir: string
  let db: DatabaseStore
  let server: http.Server
  let baseUrl: string
  let csrfToken: string
  let sessionCookie: string

  beforeAll(async () => {
    dir = tmpDir()
    db = new DatabaseStore(dir)
    initHmacKey(Buffer.from('test-hmac-key-for-e2e', 'utf8'))

    // Register a test device so session auth works
    db.registerDevice({
      name: 'E2E Test Device',
      credentialId: 'test-credential-e2e',
      publicKey: Buffer.from('mock-public-key').toString('base64'),
      counter: 1,
      transports: '[]',
    })

    // Manually create a session (simulates login)
    const sid = db.createSession('test-credential-e2e', 'E2E Test Device', 86400000, undefined, 'test-agent')
    csrfToken = db.getSessionCSRFToken(sid) || ''

    const mockClient = createMockClient()
    const config = createTestConfig(dir)
    const { app } = createApp(config, db, mockClient)

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address()
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`
        }
        resolve()
      })
    })

    // Create the session cookie
    sessionCookie = `sentinel_session=${sid}`
  })

  afterAll(async () => {
    if (server) await new Promise((resolve) => server.close(resolve))
    if (db) db.close()
    if (dir) fs.rmSync(dir, { recursive: true, force: true })
  })

  it('sends security headers on all responses', async () => {
    const res = await fetch('GET', `${baseUrl}/api/status`)
    expect(res.status).toBe(200)
    expect(res.headers['x-content-type-options']).toBe('nosniff')
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN')
    expect(res.headers['strict-transport-security']).toBeDefined()
  })

  it('returns setup status without auth', async () => {
    const res = await fetch('GET', `${baseUrl}/api/status`)
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(data).toHaveProperty('uptime')
    expect(data).toHaveProperty('locked')
    expect(data).toHaveProperty('setupRequired')
    expect(data).toHaveProperty('authMode')
  })

  it('rejects unauthenticated requests to protected endpoints', async () => {
    const res = await fetch('GET', `${baseUrl}/api/prs`)
    expect(res.status).toBe(401)
  })

  it('accepts requests with valid session cookie', async () => {
    const res = await fetch('GET', `${baseUrl}/api/prs`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(Array.isArray(data)).toBe(true)
  })

  it('returns CSRF token for authenticated session', async () => {
    const res = await fetch('GET', `${baseUrl}/api/session/csrf-token`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(data.csrfToken).toBeTruthy()
  })

  it('rejects POST to lockdown without CSRF token', async () => {
    const res = await fetch('POST', `${baseUrl}/api/lockdown`, {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
    }, JSON.stringify({ reAssertToken: 'test-token' }))
    expect(res.status).toBe(403)
    const data = JSON.parse(res.body)
    expect(data.error).toBe('Invalid CSRF token')
  })

  it('rejects POST to lockdown without re-assertion token', async () => {
    const res = await fetch('POST', `${baseUrl}/api/lockdown`, {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    }, JSON.stringify({}))
    expect(res.status).toBe(403)
    const data = JSON.parse(res.body)
    expect(data.error).toBe('Re-assertion token required')
  })

  it('serves the authorize page', async () => {
    const res = await fetch('GET', `${baseUrl}/authorize?cid=test&pr=1`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toContain('text/html')
  })

  it('returns empty audit log for fresh install', async () => {
    const res = await fetch('GET', `${baseUrl}/api/audit`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(Array.isArray(data)).toBe(true)
  })

  it('returns metrics endpoint data', async () => {
    const res = await fetch('GET', `${baseUrl}/api/metrics`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(data).toHaveProperty('totalPRs')
  })

  it('prints backfill status (not running)', async () => {
    const res = await fetch('GET', `${baseUrl}/api/admin/backfill-status`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(data.done).toBe(false)
  })
})
