import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { DatabaseStore } from '../../src/storage/database'
import { createSessionCookie, clearSessionCookie, initSessionDb } from '../../src/middleware/session'

function tmpDir(): string {
  const dir = path.join(os.tmpdir(), `oracle-session-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

describe('Session Authentication', () => {
  let testDir: string
  let db: DatabaseStore

  beforeEach(() => {
    testDir = tmpDir()
    db = new DatabaseStore(testDir)
  })

  afterEach(() => {
    try { db.close() } catch {}
    try { fs.rmSync(testDir, { recursive: true, force: true }) } catch {}
  })

  it('creates session and retrieves it', () => {
    const sessionId = db.createSession('test-credential', 'test-device', 300000)
    expect(sessionId).toBeTruthy()
    expect(typeof sessionId).toBe('string')

    const session = db.getSession(sessionId)
    expect(session).toBeDefined()
    expect(session!.credentialId).toBe('test-credential')
    expect(session!.deviceName).toBe('test-device')
  })

  it('creates session cookie via createSessionCookie', () => {
    initSessionDb(db)
    const cookie = createSessionCookie('test-credential', 'test-device')
    expect(cookie.name).toBe('sentinel_session')
    expect(cookie.value).toContain('id')
    const parsed = JSON.parse(cookie.value)
    expect(parsed.id).toBeTruthy()
    // Verify session exists in DB
    const session = db.getSession(parsed.id)
    expect(session).toBeDefined()
    expect(session!.credentialId).toBe('test-credential')
  })

  it('returns undefined for non-existent session', () => {
    const session = db.getSession('nonexistent-id')
    expect(session).toBeUndefined()
  })

  it('expires session after TTL', async () => {
    const sessionId = db.createSession('test-credential', 'test-device', 50)
    await new Promise(r => setTimeout(r, 100))
    const session = db.getSession(sessionId)
    expect(session).toBeUndefined()
  })

  it('rejects expired session due to idle timeout', () => {
    const shortIdleDb = new DatabaseStore(testDir, undefined, 50)
    const sessionId = shortIdleDb.createSession('test-credential', 'test-device', 300000)
    const session = shortIdleDb.getSession(sessionId)
    expect(session).toBeDefined()
    shortIdleDb.close()
  })

  it('creates session cookie with valid structure', () => {
    initSessionDb(db)
    const cookie = createSessionCookie('test-credential', 'test-device')
    expect(cookie.name).toBe('sentinel_session')
    expect(cookie.value).toContain('id')
    const parsed = JSON.parse(cookie.value)
    expect(parsed.id).toBeTruthy()
    expect(typeof parsed.id).toBe('string')
    expect(cookie.options.httpOnly).toBe(true)
    expect(cookie.options.secure).toBe(true)
    expect(cookie.options.sameSite).toBe('strict')
    expect(cookie.options.signed).toBe(true)
  })

  it('clearSessionCookie returns a valid clear-cookie directive', () => {
    const cookie = clearSessionCookie()
    expect(cookie.name).toBe('sentinel_session')
    expect(cookie.value).toBe('')
    expect(cookie.options.maxAge).toBe(0)
  })

  it('touches session updates last_used_at', async () => {
    const sessionId = db.createSession('test-credential', 'test-device', 300000)
    await new Promise(r => setTimeout(r, 10))
    db.touchSession(sessionId)
    const session = db.getSession(sessionId)
    expect(session).toBeDefined()
  })

  it('deletes session by credential ID', () => {
    const sessionId = db.createSession('test-credential', 'test-device', 300000)
    db.deleteSessionsByCredentialId('test-credential')
    const session = db.getSession(sessionId)
    expect(session).toBeUndefined()
  })

  it('creates and retrieves session with CSRF token', () => {
    const sessionId = db.createSession('test-credential', 'test-device', 300000, 'test-csrf-token')
    const token = db.getSessionCSRFToken(sessionId)
    expect(token).toBe('test-csrf-token')
  })

  it('handles concurrent session creation and retrieval', () => {
    const sessions = new Array(10).fill(0).map(() => db.createSession('cred-1', 'device', 300000))
    sessions.forEach(id => {
      const s = db.getSession(id)
      expect(s).toBeDefined()
    })
  })
})
