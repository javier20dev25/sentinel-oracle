import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import * as path from 'path'
import * as os from 'os'
import * as fs from 'fs'
import { DatabaseStore } from '../../src/storage/database'
import { createApp } from '../../src/server'
import type { GitHubClient } from '../../src/github/client'
import type { Config } from '../../src/config'
import { initHmacKey } from '../../src/crypto/signing'

function tmpDir(): string {
  const dir = path.join(os.tmpdir(), `oracle-scans-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
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
    cookieSecret: 'test-cookie-secret-scans',
    hmacSeed: Buffer.from('test-hmac-key-for-scans', 'utf8'),
    approveReasonRequired: false,
    locked: false,
    passwordHash: '',
    enrollmentTokenTtlMs: 300000,
    githubWebhookSecret: '',
    scanEnabled: true,
    autoScan: false,
    aiEnabled: false,
    autoAnalyze: false,
    securityInbox: true,
    analystQueue: true,
    aiModel: '',
  }
}

function fetch(method: string, url: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const opts = require('http').RequestOptions = {
      hostname: u.hostname,
      port: parseInt(u.port, 10),
      path: u.pathname + u.search,
      method,
      headers,
    }
    const req = require('http').request(opts, (res: any) => {
      let data = ''
      res.on('data', (chunk: any) => { data += chunk })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }))
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

function setupServer(dataDir: string): Promise<{ server: any; baseUrl: string; sessionCookie: string; db: DatabaseStore }> {
  return new Promise((resolve) => {
    const db = new DatabaseStore(dataDir)
    initHmacKey(Buffer.from('test-hmac', 'utf8'))
    const config = createTestConfig(dataDir)
    const mockClient = createMockClient()
    const { app } = createApp(config, db, mockClient)
    const sid = db.createSession('test-credential', 'test-device', 86400000, undefined, 'test-agent')
    const cookieVal = JSON.stringify({ id: sid })
    const signature = require('crypto')
      .createHmac('sha256', 'test-cookie-secret-scans')
      .update(cookieVal)
      .digest('base64')
      .replace(/=+$/, '')
    const signedCookie = 's:' + cookieVal + '.' + signature
    const sessionCookie = `sentinel_session=${encodeURIComponent(signedCookie)}`
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      const baseUrl = addr && typeof addr === 'object' ? `http://127.0.0.1:${addr.port}` : ''
      resolve({ server, baseUrl, sessionCookie, db })
    })
  })
}

describe('GET /api/scans with data', () => {
  let dataDir: string
  let db: DatabaseStore
  let server: any
  let baseUrl: string
  let sessionCookie: string

  beforeAll(async () => {
    dataDir = tmpDir()
    const setup = await setupServer(dataDir)
    server = setup.server
    baseUrl = setup.baseUrl
    sessionCookie = setup.sessionCookie
    db = setup.db

    db.saveScanResult(101, 'hash101', {
      riskScore: 15,
      critical: 2,
      high: 3,
      medium: 5,
      low: 8,
      findings: [
        { severity: 'critical', title: 'Hardcoded secret', file: 'config.ts' },
        { severity: 'high', title: 'SQL injection', file: 'db.ts' },
      ],
    })

    db.saveScanResult(102, 'hash102', {
      riskScore: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      findings: [],
    })

    db.upsertPR({ prNumber: 101, owner: 'test-owner', repo: 'test-repo', title: 'Test PR 101', author: 'author1', sha: 'sha101', ciStatus: 'success', sentinelStatus: 'pending', authStatus: 'pending', createdAt: Date.now() - 86400000, authorizedAt: null, deviceName: null, checkRunId: null })
    db.setAuthStatus(101, 'authorized', 'device-name-1')
    db.upsertPR({ prNumber: 102, owner: 'test-owner', repo: 'test-repo', title: 'Test PR 102', author: 'author2', sha: 'sha102', ciStatus: 'success', sentinelStatus: 'pending', authStatus: 'pending', createdAt: Date.now() - 86400000, authorizedAt: null, deviceName: null, checkRunId: null })
    db.setAuthStatus(102, 'authorized', 'device-name-1')
  })

  afterAll(async () => {
    if (server) await new Promise((resolve) => server.close(resolve))
    if (db) db.close()
    await new Promise(r => setTimeout(r, 100))
    if (dataDir) try { fs.rmSync(dataDir, { recursive: true, force: true }) } catch {}
  })

  it('returns 401 without session cookie', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`)
    expect(res.status).toBe(401)
  })

  it('returns scans as JSON array', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(Array.isArray(data)).toBe(true)
    expect(data.length).toBeGreaterThanOrEqual(2)
  })

  it('enriches scans with PR titles from completed PRs', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`, { Cookie: sessionCookie })
    const data = JSON.parse(res.body)
    const scan101 = data.find((s: any) => s.prNumber === 101)
    expect(scan101).toBeTruthy()
    expect(scan101.title).toBe('Test PR 101')
    expect(scan101.author).toBe('author1')
    expect(scan101.authStatus).toBe('authorized')
  })

  it('includes riskScore and finding counts', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`, { Cookie: sessionCookie })
    const data = JSON.parse(res.body)
    const scan101 = data.find((s: any) => s.prNumber === 101)
    expect(scan101.riskScore).toBe(15)
    expect(scan101.critical).toBe(2)
    expect(scan101.high).toBe(3)
    expect(scan101.medium).toBe(5)
    expect(scan101.low).toBe(8)
    expect(scan101.findingsCount).toBe(2)
  })

  it('includes scannedAt as a number timestamp', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(Array.isArray(data)).toBe(true)
    for (const scan of data) {
      expect(typeof scan.scannedAt).toBe('number')
      expect(scan.scannedAt).toBeGreaterThan(0)
    }
  })
})

describe('GET /api/scans empty DB', () => {
  let dataDir: string
  let db: DatabaseStore
  let server: any
  let baseUrl: string
  let sessionCookie: string

  beforeAll(async () => {
    dataDir = tmpDir()
    const setup = await setupServer(dataDir)
    server = setup.server
    baseUrl = setup.baseUrl
    sessionCookie = setup.sessionCookie
    db = setup.db
  })

  afterAll(async () => {
    if (server) await new Promise((resolve) => server.close(resolve))
    if (db) db.close()
    await new Promise(r => setTimeout(r, 100))
    if (dataDir) try { fs.rmSync(dataDir, { recursive: true, force: true }) } catch {}
  })

  it('returns empty array when no scans exist', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    expect(JSON.parse(res.body)).toEqual([])
  })
})

describe('GET /api/scans corrupted data', () => {
  let dataDir: string
  let db: DatabaseStore
  let server: any
  let baseUrl: string
  let sessionCookie: string

  beforeAll(async () => {
    dataDir = tmpDir()
    db = new DatabaseStore(dataDir)
    // Insert corrupted data via raw SQL before creating app
    const stmt = db.db.prepare('INSERT INTO scan_results (pr_number, scan_hash, risk_score, critical, high, medium, low, findings_json, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    stmt.run(999, 'hash999', 10, 1, 1, 1, 1, 'not-json{{{', Date.now())
    const setup = await setupServer(dataDir)
    server = setup.server
    baseUrl = setup.baseUrl
    sessionCookie = setup.sessionCookie
  })

  afterAll(async () => {
    if (server) await new Promise((resolve) => server.close(resolve))
    if (db) db.close()
    await new Promise(r => setTimeout(r, 100))
    if (dataDir) try { fs.rmSync(dataDir, { recursive: true, force: true }) } catch {}
  })

  it('handles malformed findingsJson gracefully', async () => {
    const res = await fetch('GET', `${baseUrl}/api/scans`, { Cookie: sessionCookie })
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(Array.isArray(data)).toBe(true)
    const scan999 = data.find((s: any) => s.prNumber === 999)
    expect(scan999).toBeTruthy()
    expect(scan999.findingsCount).toBe(0)
  })
})
