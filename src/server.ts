import crypto from 'crypto'
import * as fs from 'fs'
import express from 'express'
import cookieParser from 'cookie-parser'
import * as path from 'path'
import type { Config } from './config'
import type { DatabaseStore } from './storage/database'
import { GitHubApiError, type GitHubClient } from './github/client'
import { AuthorizationQueue } from './queue/authorization'
import { PollPRsError, pollPRs } from './github/monitor'
import { securityHeaders, corsBlock, auditLogger, csrfProtection } from './middleware/security'
import { requireAuth, createSessionCookie, clearSessionCookie, getSessionTTL, requireCSRF, initSessionDb, setNoAuthMode, isNoAuthMode } from './middleware/session'
import { authRateLimiter, apiRateLimiter } from './middleware/rateLimit'
import {
  generateRegistration,
  verifyRegistration,
  generateAssertion,
  verifyAssertion,
  getRpId,
} from './auth/webauthn'
import { hashPassword, verifyPassword } from './crypto/password'
import { saveConfig } from './config'
import { scanPRFiles } from './scanner/index'
import { analyzeWorkflowIntelligence } from './scanner/intel/index'
import { analyzePR as aiAnalyzePR, analyzeScanResults, explainPR, explainScanFindings } from './ai/analyzer'
import { detectAIBackend, detectAllModels, checkModelHealth } from './ai/detector'
import { buildCapabilitySnapshot, buildDNAReport } from './scanner/intel/security-dna'
import { TokenInventoryScanner } from './inventory/tokens'

function generateEnrollmentToken(): string {
  return crypto.randomBytes(16).toString('hex')
}

let _enrollmentToken: string | null = null
let _enrollmentUsed = false

export function getEnrollmentToken(): string {
  return _enrollmentToken || ''
}

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

export function initEnrollment(config: Config, db: DatabaseStore): void {
  const existing = db.getConfig('enrollment_completed')
  if (existing === 'true') {
    _enrollmentToken = null
    _enrollmentUsed = true
    console.log('[setup] First device already enrolled — enrollment token disabled')
    return
  }
  _enrollmentToken = generateEnrollmentToken()
  _enrollmentUsed = false
  console.log(`  ===== FIRST-TIME SETUP =====`)
  console.log(`  Enrollment token configured (length: ${_enrollmentToken.length})`)
  console.log(`  Token refreshes every ${config.enrollmentTokenTtlMs / 1000}s — check terminal for updates`)
  console.log(`  POST /api/setup/begin with enrollment token to enroll`)
  console.log(`  =============================\n`)
  db.log('enrollment_token_created', null, 'Enrollment token generated (one-time)')

  const interval = setInterval(() => {
    if (_enrollmentUsed || db.getConfig('enrollment_completed') === 'true') {
      clearInterval(interval)
      return
    }
    _enrollmentToken = generateEnrollmentToken()
    console.log(`\n  ===== ENROLLMENT TOKEN REFRESHED =====`)
    console.log(`  New token configured (length: ${_enrollmentToken.length})`)
    console.log(`  POST /api/setup/begin with enrollment token to enroll`)
    console.log(`  =====================================\n`)
    db.log('enrollment_token_refreshed', null, 'Enrollment token refreshed')
  }, config.enrollmentTokenTtlMs)

  try {
    require('fs').writeFileSync(require('os').homedir() + '\\.sentinel-oracle\\.enrollment_token', _enrollmentToken, 'utf8')
  } catch {}
}

export function createApp(config: Config, db: DatabaseStore, client: GitHubClient, noAuth?: boolean) {
  setNoAuthMode(!!noAuth)
  const app = express()
  const rpId = getRpId(config)
  const queue = new AuthorizationQueue(db, client, config.challengeTtlMs, config.serverOrigin, rpId)
  initSessionDb(db)

  app.disable('x-powered-by')
  app.set('trust proxy', 1)

  app.use(securityHeaders())
  app.use(corsBlock)
  app.use(auditLogger(db))
  app.use(express.json({
    limit: '1mb',
    verify: (req: any, _res: any, buf: Buffer) => {
      const cl = parseInt(req.headers['content-length'], 10)
      if (cl && buf.length !== cl) {
        const err = new Error('Content-Length mismatch')
        ;(err as any).status = 400
        ;(err as any).body = buf
        throw err
      }
    },
  }))
  app.use(cookieParser(config.cookieSecret))
  app.use(csrfProtection(config.serverOrigin, db))
  app.use(express.static(path.join(__dirname, '..', 'public')))
  app.get('/authorize', (_req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'authorize.html'))
  })

  // ----- WebAuthn Registration (authenticated) -----
  app.post('/api/webauthn/register/begin', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { deviceName } = req.body
      if (!deviceName || typeof deviceName !== 'string') {
        return res.status(400).json({ error: 'deviceName required' })
      }
      const result = await generateRegistration(deviceName, db, config.serverOrigin, rpId)
      res.json(result)
    } catch (err) {
      db.log('error', null, `WebAuthn register begin: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Registration initialization failed' })
    }
  })

  app.post('/api/webauthn/register/complete', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { credential, challenge, deviceName } = req.body
      const result = await verifyRegistration(credential, challenge, db, config.serverOrigin, rpId)
      if (!result.verified) {
        return res.status(400).json({ error: 'Registration verification failed' })
      }
      db.registerDevice({
        name: deviceName || 'Authenticator',
        credentialId: result.credentialId,
        publicKey: result.publicKey,
        counter: result.counter,
        transports: JSON.stringify(result.transports),
      })
      db.log('device_registered', null, `Device "${deviceName}" registered (credential: ${result.credentialId.slice(0, 16)}...)`)
      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `WebAuthn register complete: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Registration completion failed' })
    }
  })

  // ----- WebAuthn Assertion -----
  app.post('/api/webauthn/assert/begin', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = req.body?.prNumber ? parseInt(req.body.prNumber, 10) : undefined
      const result = await generateAssertion(db, config.serverOrigin, rpId, prNumber)
      console.log('[webauthn] assert/begin: challenge=%s', result.challenge)
      res.json(result)
    } catch (err) {
      db.log('error', null, `WebAuthn assert begin: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Assertion initialization failed' })
    }
  })

  app.post('/api/webauthn/assert/complete', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { credential, challenge } = req.body
      console.log('[webauthn] assert/complete: receivedChallenge=%s credentialId=%s', challenge, credential?.id?.slice(0, 20))
      const result = await verifyAssertion(credential, challenge, db, config.serverOrigin, rpId)
      if (!result.verified) {
        console.log('[webauthn] assert/complete: FAILED reason=%s', result.error)
        return res.status(401).json({ error: result.error || 'Authentication failed' })
      }
      console.log('[webauthn] assert/complete: OK credentialId=%s', result.credentialId)
      const device = db.getDeviceByCredentialId(result.credentialId)

      if (result.credentialId) {
        const cookie = createSessionCookie(result.credentialId, device?.name || 'unknown', req.headers['user-agent'] || '')
        console.log('[webauthn] assert/complete: Created session cookie:', { name: cookie.name, options: cookie.options })
        res.cookie(cookie.name, cookie.value, cookie.options)
        db.log('session_created', null, `Session for device "${device?.name || 'unknown'}"`)
      }

      db.log('authenticated', null, `Device "${device?.name || 'unknown'}" authenticated`)
      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `WebAuthn assert complete: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Assertion completion failed' })
    }
  })

  // ----- Session -----
  app.get('/api/session/check', (req, res) => {
    if (isNoAuthMode()) {
      return res.json({ authenticated: true, noAuth: true, deviceName: '--noauth mode' })
    }
    const raw = req.signedCookies?.sentinel_session
    console.log(`[session] check: hasCookie=${!!raw} type=${typeof raw} allSigned=${Object.keys(req.signedCookies || {}).join(',')} path=${req.path}`)
    if (!raw || typeof raw !== 'string') {
      if (raw === false) console.warn('[session] check: cookie signature INVALID')
      return res.json({ authenticated: false })
    }
    try {
      const cookieData = JSON.parse(raw)
      console.log(`[session] check: parsed sessionId=${cookieData.id?.slice(0, 16)}`)
      if (!cookieData.id) {
        const cookie = clearSessionCookie()
        res.cookie(cookie.name, cookie.value, cookie.options)
        return res.json({ authenticated: false })
      }
      const dbSession = db.getSession(cookieData.id)
      if (!dbSession) {
        const cookie = clearSessionCookie()
        res.cookie(cookie.name, cookie.value, cookie.options)
        return res.json({ authenticated: false, reason: 'session_not_found' })
      }
      db.touchSession(cookieData.id)
      res.json({ authenticated: true, deviceName: dbSession.deviceName })
    } catch {
      const cookie = clearSessionCookie()
      res.cookie(cookie.name, cookie.value, cookie.options)
      res.json({ authenticated: false })
    }
  })

  app.post('/api/session/logout', (req, res) => {
    const cookie = clearSessionCookie()
    res.cookie(cookie.name, cookie.value, cookie.options)
    db.log('session_logout', null, 'Session explicitly terminated')
    res.json({ loggedOut: true })
  })

  app.get('/api/session/csrf-token', requireAuth(), (req, res) => {
    res.json({ csrfToken: (req as any).session.csrfToken })
  })

  // ----- Re-assertion (for sensitive actions) -----
  app.post('/api/auth/re-assert', requireAuth(), async (req, res) => {
    const session = (req as any).session
    try {
      const assertion = await generateAssertion(db, config.serverOrigin, config.rpId)
      const actionHint = (req.body?.action as string) || ''
      db.setConfig(`reassert_action_${assertion.challenge}`, JSON.stringify({
        action: actionHint,
        sessionId: session.id,
        createdAt: Date.now(),
      }))
      res.json({ ...assertion, action: actionHint })
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to generate re-assertion challenge' })
    }
  })

  app.post('/api/auth/re-assert/complete', requireAuth(), async (req, res) => {
    const session = (req as any).session
    try {
      const { credential, challenge } = req.body
      const storedRaw = db.getConfig(`reassert_action_${challenge}`)
      if (!storedRaw) return res.status(400).json({ error: 'Invalid or expired challenge' })
      const stored = JSON.parse(storedRaw)
      if (stored.sessionId !== session.id) {
        return res.status(403).json({ error: 'Challenge belongs to different session' })
      }
      db.setConfig(`reassert_action_${challenge}`, '')
      const result = await verifyAssertion(credential, challenge, db, config.serverOrigin, config.rpId)
      if (!result.verified) return res.status(401).json({ error: 'Re-assertion failed' })
      const reAssertToken = require('crypto').randomBytes(32).toString('hex')
      db.setConfig(`reassert_token_${reAssertToken}`, JSON.stringify({
        sessionId: session.id,
        credentialId: result.credentialId,
        createdAt: Date.now(),
        ttl: 60000,
      }))
      res.json({ verified: true, reAssertToken })
    } catch (err: any) {
      res.status(500).json({ error: 'Re-assertion verification failed' })
    }
  })

  // ----- Enrollment -----
  function validatePasswordStrength(password: string): string | null {
    if (!password || password.length < 8) return 'Password must be at least 8 characters'
    if (!/[A-Z]/.test(password)) return 'Password must contain an uppercase letter'
    if (!/[a-z]/.test(password)) return 'Password must contain a lowercase letter'
    if (!/[0-9]/.test(password)) return 'Password must contain a digit'
    if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain a symbol'
    return null
  }

  app.post('/api/config/password', requireAuth(), authRateLimiter(5, 60000), (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body
      const strengthErr = validatePasswordStrength(newPassword)
      if (strengthErr) return res.status(400).json({ error: strengthErr })
      if (config.passwordHash && !verifyPassword(currentPassword, config.passwordHash)) {
        return res.status(403).json({ error: 'Current password is incorrect' })
      }
      config.passwordHash = hashPassword(newPassword)
      saveConfig({ passwordHash: config.passwordHash })
      db.log('password_set', null, 'Enrollment password was set or changed')
      res.json({ success: true })
    } catch (err) {
      db.log('error', null, `Password change: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to set password' })
    }
  })

  app.post('/api/config/password/reset', requireAuth(), authRateLimiter(5, 60000), (req, res) => {
    try {
      const { newPassword, reAssertToken } = req.body
      if (!reAssertToken) return res.status(403).json({ error: 'Re-assertion token required' })
      const tokenRaw = db.getConfig(`reassert_token_${reAssertToken}`)
      if (!tokenRaw) return res.status(403).json({ error: 'Invalid or expired re-assertion token' })
      const tokenData = JSON.parse(tokenRaw)
      if (Date.now() - tokenData.createdAt > tokenData.ttl) {
        db.setConfig(`reassert_token_${reAssertToken}`, '')
        return res.status(403).json({ error: 'Re-assertion token expired' })
      }
      const strengthErr = validatePasswordStrength(newPassword)
      if (strengthErr) return res.status(400).json({ error: strengthErr })
      db.setConfig(`reassert_token_${reAssertToken}`, '')
      config.passwordHash = hashPassword(newPassword)
      saveConfig({ passwordHash: config.passwordHash })
      db.log('password_reset', null, 'Password reset via WebAuthn re-assertion')
      res.json({ success: true })
    } catch (err) {
      db.log('error', null, `Password reset: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to reset password' })
    }
  })

  // ----- Setup / First Device Enrollment -----
  app.post('/api/setup/begin', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { enrollmentToken, deviceName } = req.body
      console.log('[setup/begin] enrollment attempt — token provided:', !!enrollmentToken, 'used:', _enrollmentUsed)
      if (_enrollmentUsed || !_enrollmentToken) {
        return res.status(403).json({ error: 'Enrollment not available — already completed or disabled' })
      }
      if (!enrollmentToken || !safeCompare(enrollmentToken, _enrollmentToken)) {
        return res.status(403).json({ error: 'Invalid enrollment token' })
      }
      if (!deviceName || typeof deviceName !== 'string') {
        return res.status(400).json({ error: 'deviceName required' })
      }

      const result = await generateRegistration('admin-' + deviceName, db, config.serverOrigin, rpId)
      res.json(result)
    } catch (err) {
      db.log('error', null, `Setup begin: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Setup initialization failed' })
    }
  })

  app.post('/api/setup/complete', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { credential, challenge, deviceName, enrollmentToken } = req.body
      console.log('[setup/complete] enrollment completion — token provided:', !!enrollmentToken, 'used:', _enrollmentUsed)
      if (_enrollmentUsed || !_enrollmentToken) {
        return res.status(403).json({ error: 'Enrollment not available' })
      }
      if (!enrollmentToken || !safeCompare(enrollmentToken, _enrollmentToken)) {
        return res.status(403).json({ error: 'Invalid enrollment token' })
      }
      if (!credential || !challenge) {
        return res.status(400).json({ error: 'credential and challenge required' })
      }

      const result = await verifyRegistration(credential, challenge, db, config.serverOrigin, rpId)
      if (!result.verified) {
        return res.status(400).json({ error: 'Registration verification failed' })
      }

      db.registerDevice({
        name: deviceName || 'Admin Device',
        credentialId: result.credentialId,
        publicKey: result.publicKey,
        counter: result.counter,
        transports: JSON.stringify(result.transports),
      })

      _enrollmentUsed = true
      db.setConfig('enrollment_completed', 'true')
      db.log('device_enrolled', null, `First device "${deviceName}" enrolled and registered`)

      const cookie = createSessionCookie(result.credentialId, deviceName || 'Admin Device', req.headers['user-agent'] || '')
      res.cookie(cookie.name, cookie.value, cookie.options)

      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `Setup complete: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Setup completion failed' })
    }
  })

  // ----- Authorization (authenticated) -----
  app.get('/api/prs', requireAuth(), apiRateLimiter(30, 60000), async (_req, res) => {
    try {
      await pollPRs(client, db)
      const prs = queue.getPendingPRs()
      res.json(prs)
    } catch (err) {
      db.log('error', null, `List PRs: ${err instanceof Error ? err.message : err}`)
      if (err instanceof PollPRsError) {
        return res.status(err.httpStatus).json({
          error: err.message,
          code: err.code,
          repo: `${err.owner}/${err.repo}`,
          githubStatus: err.githubStatus || null,
        })
      }
      res.status(500).json({ error: 'Failed to list PRs' })
    }
  })

  app.get('/api/prs/history', requireAuth(), apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const prs = db.getCompletedPRs()
      res.json(prs)
    } catch (err) {
      db.log('error', null, `List history: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to list history' })
    }
  })

  app.get('/api/scans', requireAuth(), apiRateLimiter(20, 60000), (_req, res) => {
    try {
      const scans = db.getAllScanResults()
      const history = db.getCompletedPRs()
      const lookup = new Map(history.map(p => [p.prNumber, p]))
      const enriched = scans.map(s => ({
        prNumber: s.prNumber,
        riskScore: s.riskScore,
        critical: s.critical,
        high: s.high,
        medium: s.medium,
        low: s.low,
        scannedAt: s.scannedAt,
        findingsCount: (() => {
          try { return JSON.parse(s.findingsJson || '[]').length } catch { return 0 }
        })(),
        title: lookup.get(s.prNumber)?.title || '',
        author: lookup.get(s.prNumber)?.author || '',
        authStatus: lookup.get(s.prNumber)?.authStatus || 'unknown',
      }))
      res.json(enriched)
    } catch (err) {
      db.log('error', null, `List scans: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to list scans' })
    }
  })

  app.post('/api/prs/:number/authorize', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const challenge = await queue.initiateAuthorization(prNumber)
      if (!challenge) {
        const locked = queue.isLocked()
        return res.status(locked ? 423 : 404).json({
          error: locked ? 'System is locked down' : 'PR not found or not awaiting authorization',
        })
      }
      res.json({ ...challenge, passwordRequired: !!config.passwordHash })
    } catch (err) {
      db.log('error', null, `Initiate authorization: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to initiate authorization' })
    }
  })

  app.post('/api/prs/:number/confirm', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const { challengeId, credential, challenge: webauthnChallenge, reason, password } = req.body

      if (!challengeId) return res.status(400).json({ error: 'challengeId required' })
      if (!credential) return res.status(400).json({ error: 'credential (WebAuthn assertion) required' })
      if (!webauthnChallenge) return res.status(400).json({ error: 'challenge (WebAuthn challenge) required' })

      if (config.passwordHash) {
        if (!password) return res.status(400).json({ error: 'password required' })
        if (!verifyPassword(password, config.passwordHash)) {
          return res.status(403).json({ error: 'Invalid authorization password' })
        }
      }

      const result = await queue.confirmAuthorization(prNumber, challengeId, credential, webauthnChallenge, reason)

      if (!result.success) {
        const statusCode = result.error === 'System is locked down' ? 423 : 400
        return res.status(statusCode).json({ error: result.error })
      }

      res.json({ authorized: true, prNumber, merged: result.merged === true })
    } catch (err) {
      db.log('error', null, `Confirm authorization: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to confirm authorization' })
    }
  })

  app.post('/api/prs/:number/reject', requireAuth(), requireCSRF(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const token = (req.body?.reAssertToken as string) || ''
      if (!token) return res.status(403).json({ error: 'Re-assertion token required' })
      const tokenRaw = db.getConfig(`reassert_token_${token}`)
      if (!tokenRaw) return res.status(403).json({ error: 'Invalid or expired re-assertion token' })
      const tokenData = JSON.parse(tokenRaw)
      if (Date.now() - tokenData.createdAt > tokenData.ttl) {
        db.setConfig(`reassert_token_${token}`, '')
        return res.status(403).json({ error: 'Re-assertion token expired' })
      }
      db.setConfig(`reassert_token_${token}`, '')
      const prNumber = parseInt(req.params.number as string, 10)
      const { reason } = req.body
      await queue.rejectAuthorization(prNumber, reason)
      res.json({ rejected: true, prNumber })
    } catch (err) {
      db.log('error', null, `Reject authorization: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to reject authorization' })
    }
  })

  // ----- PR Scan (independent verification — optional) -----
  function computeScanHash(files: { filename: string; status: string; additions: number; deletions: number; patch?: string }[], sha: string): string {
    const h = crypto.createHash('sha256')
    h.update(sha)
    for (const f of files) {
      h.update(f.filename)
      h.update(f.status)
      h.update(String(f.additions))
      h.update(String(f.deletions))
      if (f.patch) h.update(crypto.createHash('sha256').update(f.patch).digest('hex'))
    }
    return h.digest('hex')
  }

  app.get('/api/prs/:number/scan-result', requireAuth(), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      let row = db.getLatestScanResult(prNumber)
      if (!row) {
        return res.status(404).json({ error: 'No scan result found for this PR. Run a scan first.' })
      }
      const pr = db.getPRByNumber(prNumber)
      const prFiles = db.getPRFiles(prNumber)
      let findings: unknown[]
      try { findings = JSON.parse(row.findingsJson) } catch { findings = [] }
      let intel: unknown
      try { intel = row.intelJson ? JSON.parse(row.intelJson) : undefined } catch {}
      let buildIntel: unknown
      try { buildIntel = row.buildIntelJson ? JSON.parse(row.buildIntelJson) : undefined } catch {}
      res.json({
        riskScore: row.riskScore,
        scanHash: row.scanHash,
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low,
        findings,
        intel: intel || undefined,
        buildIntel: buildIntel || undefined,
        scannedAt: row.scannedAt,
        files: prFiles,
        prNumber,
        prTitle: pr?.title || '',
        prAuthor: pr?.author || '',
        prCreatedAt: pr?.createdAt || row.scannedAt,
        prAuthorizedAt: pr?.authorizedAt || null,
        prAuthStatus: pr?.authStatus || 'pending',
        scanDuration: 0,
        cached: true,
      })
    } catch (err) {
      res.status(500).json({ error: 'Failed to get scan result' })
    }
  })

  app.post('/api/prs/:number/scan', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    if (!config.scanEnabled) {
      return res.status(404).json({ error: 'PR scanning is not enabled. Set scanEnabled: true in config.json' })
    }
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const files = await client.getPRFiles(prNumber)
      if (files.length === 0) {
        return res.status(404).json({ error: 'No files found for this PR' })
      }
      db.storePRFiles(prNumber, files)
      const pr = db.getPRByNumber(prNumber)
      const sha = pr ? pr.sha : ''
      const scanHash = computeScanHash(files, sha)
      // Return cached result if nothing changed
      if (db.hasScanHash(prNumber, scanHash)) {
        const row = db.getLatestScanResult(prNumber)
        if (row) {
          const prFiles = db.getPRFiles(prNumber)
          let findings: unknown[]
          try { findings = JSON.parse(row.findingsJson) } catch { findings = [] }
          let intel: unknown
          try { intel = row.intelJson ? JSON.parse(row.intelJson) : undefined } catch {}
          let buildIntel: unknown
          try { buildIntel = row.buildIntelJson ? JSON.parse(row.buildIntelJson) : undefined } catch {}
          db.log('pr_scanned', prNumber, `Scan cache HIT — returning cached result (risk ${row.riskScore})`)
          return res.json({
            riskScore: row.riskScore,
            scanHash,
            critical: row.critical,
            high: row.high,
            medium: row.medium,
            low: row.low,
            findings,
            intel: intel || undefined,
            buildIntel: buildIntel || undefined,
            scannedAt: row.scannedAt,
            files: prFiles,
            prNumber,
            prTitle: pr?.title || '',
            prAuthor: pr?.author || '',
            prCreatedAt: pr?.createdAt || row.scannedAt,
            prAuthorizedAt: pr?.authorizedAt || null,
            prAuthStatus: pr?.authStatus || 'pending',
            scanDuration: 0,
            cached: true,
          })
        }
      }
      const t0 = Date.now()
      const result = await scanPRFiles(files, prNumber, config.githubOwner, config.githubRepo, sha)
      const scanDuration = Date.now() - t0
      // Persist scan result
      db.saveScanResult(prNumber, scanHash, result)
      db.log('pr_scanned', prNumber, `Scan: risk ${result.riskScore} (${result.critical}C ${result.high}H ${result.medium}M ${result.low}L) in ${scanDuration}ms`)
      // Auto-analyze with AI if enabled
      if (config.autoAnalyze && config.aiEnabled) {
        aiAnalyzePR(prNumber, pr?.title || '', pr?.author || '', pr?.title || '', '', sha, files, sha, db, config.aiModel || 'auto').then(analysis => {
          db.saveAnalysisResult(prNumber, scanHash, {
            analysisJson: JSON.stringify(analysis),
            reviewPriority: analysis.priority.reviewPriority,
            impactLevel: analysis.priority.impactLevel,
            complexity: analysis.priority.estimatedComplexity,
            injectionDetected: analysis.instructionManipulation.length > 0,
            injectionAttemptsJson: JSON.stringify(analysis.instructionManipulation),
          })
          db.log('ai_analyzed', prNumber, `Auto-analyze: priority=${analysis.priority.reviewPriority}, injection=${analysis.instructionManipulation.length > 0}`)
        }).catch(() => {})
      }
      // Persist capability snapshot for Security DNA
      if (result.intel && config.githubOwner && config.githubRepo) {
        const snapshot = buildCapabilitySnapshot(result.intel)
        db.storeCapabilitySnapshot(config.githubOwner, config.githubRepo, prNumber, snapshot)
      }
      const prFiles = db.getPRFiles(prNumber)
      res.json({
        ...result,
        scanHash,
        files: prFiles,
        prNumber,
        prTitle: pr?.title || '',
        prAuthor: pr?.author || '',
        prCreatedAt: pr?.createdAt || result.scannedAt,
        prAuthorizedAt: pr?.authorizedAt || null,
        prAuthStatus: pr?.authStatus || 'pending',
        scanDuration,
        cached: false,
      })
    } catch (err) {
      db.log('error', null, `PR scan: ${err instanceof Error ? err.message : err}`)
      if (err instanceof GitHubApiError) {
        return res.status(err.status === 401 ? 401 : err.status === 403 ? 403 : 424).json({
          error: err.message,
          code: 'GITHUB_API_ERROR',
          githubStatus: err.status,
        })
      }
      res.status(500).json({ error: 'Failed to scan PR' })
    }
  })

  // ----- AI Analysis -----
  app.post('/api/prs/:number/ai-analyze', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    if (!config.aiEnabled) {
      return res.status(404).json({ error: 'AI analysis is not enabled. Enable it in settings.' })
    }
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const files = await client.getPRFiles(prNumber)
      if (files.length === 0) return res.status(404).json({ error: 'No files found for this PR' })
      const scanHash = computeScanHash(files, pr.sha)
      if (db.hasAnalysisHash(prNumber, scanHash)) {
        const row = db.getLatestAnalysisResult(prNumber)
        if (row) {
          db.log('ai_analyzed', prNumber, 'AI analysis cache HIT')
          return res.json({ cached: true, ...JSON.parse(row.analysisJson) })
        }
      }
      const prBody = pr.title
      const analysis = await aiAnalyzePR(prNumber, pr.title, pr.author, prBody, '', pr.sha, files, pr.sha, db, config.aiModel || 'auto')
      db.saveAnalysisResult(prNumber, scanHash, {
        analysisJson: JSON.stringify(analysis),
        reviewPriority: analysis.priority.reviewPriority,
        impactLevel: analysis.priority.impactLevel,
        complexity: analysis.priority.estimatedComplexity,
        injectionDetected: analysis.instructionManipulation.length > 0,
        injectionAttemptsJson: JSON.stringify(analysis.instructionManipulation),
      })
      db.log('ai_analyzed', prNumber, `AI analysis: priority=${analysis.priority.reviewPriority}, injection=${analysis.instructionManipulation.length > 0}`)
      res.json({ cached: false, ...analysis })
    } catch (err) {
      db.log('error', null, `AI analysis: ${err instanceof Error ? err.message : err}`)
      if (err instanceof GitHubApiError) {
        return res.status(err.status === 401 ? 401 : err.status === 403 ? 403 : 424).json({
          error: err.message,
          code: 'GITHUB_API_ERROR',
          githubStatus: err.status,
        })
      }
      res.status(500).json({ error: 'Failed to analyze PR' })
    }
  })

  // ----- AI Scan Analysis -----
  app.post('/api/prs/:number/ai-scan-analyze', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    if (!config.aiEnabled) {
      return res.status(404).json({ error: 'AI analysis is not enabled. Enable it in settings.' })
    }
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const scanResult = db.getLatestScanResult(prNumber)
      if (!scanResult) return res.status(404).json({ error: 'No scan results found for this PR. Run a scan first.' })
      let findings: any[] = []
      try { findings = JSON.parse((scanResult as any).findingsJson || '[]') } catch { findings = [] }
      const analysis = await analyzeScanResults(prNumber, pr.title, findings, config.aiModel || 'auto')
      db.log('ai_scan_analyzed', prNumber, 'Scan AI analysis complete')
      res.json({ ...analysis, prNumber, analyzedAt: Date.now(), modelName: config.aiModel || 'auto' })
    } catch (err) {
      db.log('error', null, `AI scan analysis: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to analyze scan results' })
    }
  })

  // ----- AI Explanation (text-based, for PR code) -----
  app.post('/api/prs/:number/ai-explain', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    if (!config.aiEnabled) {
      return res.status(404).json({ error: 'AI analysis is not enabled. Enable it in settings.' })
    }
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const files = await client.getPRFiles(prNumber)
      if (files.length === 0) return res.status(404).json({ error: 'No files found for this PR' })
      const scanHash = computeScanHash(files, pr.sha)
      const result = await explainPR(prNumber, pr.title, pr.author, files, config.aiModel || 'auto')
      res.json({ ...result, prNumber, scanHash, modelName: config.aiModel || 'auto' })
    } catch (err) {
      db.log('error', null, `AI explain: ${err instanceof Error ? err.message : err}`)
      if (err instanceof GitHubApiError) {
        return res.status(err.status === 401 ? 401 : err.status === 403 ? 403 : 424).json({
          error: err.message,
          code: 'GITHUB_API_ERROR',
          githubStatus: err.status,
        })
      }
      res.status(500).json({ error: 'Failed to explain PR' })
    }
  })

  // ----- AI Explanation (text-based, for scan findings) -----
  app.post('/api/prs/:number/ai-scan-explain', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    if (!config.aiEnabled) {
      return res.status(404).json({ error: 'AI analysis is not enabled. Enable it in settings.' })
    }
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const scanResult = db.getLatestScanResult(prNumber)
      if (!scanResult) return res.status(404).json({ error: 'No scan results found for this PR. Run a scan first.' })
      let findings: any[] = []
      try { findings = JSON.parse((scanResult as any).findingsJson || '[]') } catch { findings = [] }
      const result = await explainScanFindings(prNumber, pr.title, findings, config.aiModel || 'auto')
      res.json({ ...result, prNumber, scanHash: (scanResult as any).scanHash || '', modelName: config.aiModel || 'auto' })
    } catch (err) {
      db.log('error', null, `AI scan explain: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to explain scan findings' })
    }
  })

  // ----- Save/Load AI Explanation -----
  app.post('/api/prs/:number/ai-explain/save', requireAuth(), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const { type } = req.body as { type: 'pr' | 'scan' }
      if (!type || !['pr', 'scan'].includes(type)) {
        return res.status(400).json({ error: 'type must be "pr" or "scan"' })
      }
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const scanResult = db.getLatestScanResult(prNumber)
      let findings: any[] = []
      try { findings = scanResult ? JSON.parse(scanResult.findingsJson || '[]') : [] } catch {}
      let result: { summary: string[]; argumentation: string }
      if (type === 'pr') {
        const files = await client.getPRFiles(prNumber)
        result = await explainPR(prNumber, pr.title, pr.author, files, config.aiModel || 'auto')
      } else {
        result = await explainScanFindings(prNumber, pr.title, findings, config.aiModel || 'auto')
      }
      db.saveExplanation(prNumber, type, result.summary, result.argumentation)
      db.log('ai_explanation_saved', prNumber, `Saved ${type} explanation`)
      res.json({ saved: true, ...result })
    } catch (err) {
      db.log('error', null, `Save explanation: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to save explanation' })
    }
  })

  app.get('/api/prs/:number/ai-explain/saved', requireAuth(), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const type = (req.query.type as string) || 'pr'
      if (!['pr', 'scan'].includes(type)) {
        return res.status(400).json({ error: 'type must be "pr" or "scan"' })
      }
      const row = db.getSavedExplanation(prNumber, type as 'pr' | 'scan')
      if (!row) return res.status(404).json({ error: 'No saved explanation found' })
      let summary: string[]
      try { summary = JSON.parse(row.summaryJson) } catch { summary = [] }
      res.json({ summary, argumentation: row.argumentation, savedAt: row.savedAt })
    } catch (err) {
      res.status(500).json({ error: 'Failed to get saved explanation' })
    }
  })

  // ----- Blacklist PRs -----
  app.post('/api/prs/:number/blacklist', requireAuth(), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const reason = (req.body?.reason as string) || ''
      if (db.getBlacklistPR(prNumber)) {
        return res.json({ blacklisted: true, message: 'PR already blacklisted' })
      }
      db.addBlacklistPR(prNumber, pr.owner, pr.repo, pr.title, pr.author, pr.sha, reason)
      db.log('pr_blacklisted', prNumber, `PR added to blacklist: ${reason}`)
      res.json({ blacklisted: true, prNumber })
    } catch (err) {
      db.log('error', null, `Blacklist add: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to blacklist PR' })
    }
  })

  app.delete('/api/prs/:number/blacklist', requireAuth(), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      db.removeBlacklistPR(prNumber)
      db.log('pr_unblacklisted', prNumber, 'PR removed from blacklist')
      res.json({ removed: true, prNumber })
    } catch (err) {
      res.status(500).json({ error: 'Failed to remove from blacklist' })
    }
  })

  app.get('/api/blacklist', requireAuth(), async (_req, res) => {
    try {
      const list = db.getAllBlacklistPRs()
      res.json(list)
    } catch (err) {
      res.status(500).json({ error: 'Failed to list blacklist' })
    }
  })

  // ----- AI Models -----
  app.get('/api/ai/models', (_req, res) => {
    const models = detectAllModels()
    res.json({ models, selected: config.aiModel || '' })
  })

  // ----- AI Status -----
  app.get('/api/ai/status', async (_req, res) => {
    const backend = detectAIBackend(config.aiModel)
    const models = detectAllModels()
    let health: any = null
    if (config.aiModel && config.aiModel !== 'auto') {
      health = await checkModelHealth(config.aiModel)
    }
    res.json({
      enabled: config.aiEnabled,
      autoAnalyze: config.autoAnalyze,
      aiModel: config.aiModel,
      backend,
      models,
      health,
    })
  })

  // ----- Check Run (create or update) -----
  app.post('/api/check-run', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = parseInt(req.body.prNumber as string, 10)
      const conclusion = (req.body.conclusion as string) || 'action_required'

      if (isNaN(prNumber)) {
        return res.status(400).json({ error: 'Invalid prNumber' })
      }

      const pr = db.getPRByNumber(prNumber)
      if (!pr) {
        return res.status(404).json({ error: 'PR not found in database' })
      }

      const validConclusions = ['action_required', 'success', 'failure', 'neutral', 'cancelled', 'timed_out']
      if (!validConclusions.includes(conclusion)) {
        return res.status(400).json({ error: `Invalid conclusion. Must be one of: ${validConclusions.join(', ')}` })
      }

      if (pr.checkRunId) {
        await client.updateCheckRun(pr.checkRunId, conclusion, `Check Run updated to ${conclusion} via API`)
        db.log('check_run_updated', prNumber, `Check Run #${pr.checkRunId} updated to ${conclusion}`)
        return res.json({ updated: true, checkRunId: pr.checkRunId, conclusion })
      }

      const checkRun = await client.createCheckRun(prNumber, pr.sha, conclusion, `Check Run created via API — ${conclusion}`)
      if (!checkRun || !checkRun.id) {
        return res.status(502).json({ error: 'Failed to create Check Run on GitHub' })
      }

      db.setCheckRunId(prNumber, checkRun.id)
      db.log('check_run_created', prNumber, `Check Run #${checkRun.id} created with conclusion ${conclusion}`)
      res.json({ created: true, checkRunId: checkRun.id, conclusion })
    } catch (err) {
      db.log('error', null, `Check Run API: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to manage Check Run' })
    }
  })

  // ----- Devices (authenticated) -----
  app.get('/api/devices', requireAuth(), apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const devices = db.listDevices().map(d => ({
        id: d.id,
        name: d.name,
        credentialId: d.credentialId.slice(0, 16) + '...',
        createdAt: d.createdAt,
        lastUsedAt: d.lastUsedAt,
      }))
      res.json(devices)
    } catch (err) {
      res.status(500).json({ error: 'Failed to list devices' })
    }
  })

  app.post('/api/devices/:credentialId/revoke', requireAuth(), requireCSRF(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), (req, res) => {
    try {
      const token = (req.body?.reAssertToken as string) || ''
      if (!token) return res.status(403).json({ error: 'Re-assertion token required' })
      const tokenRaw = db.getConfig(`reassert_token_${token}`)
      if (!tokenRaw) return res.status(403).json({ error: 'Invalid or expired re-assertion token' })
      const tokenData = JSON.parse(tokenRaw)
      if (Date.now() - tokenData.createdAt > tokenData.ttl) {
        db.setConfig(`reassert_token_${token}`, '')
        return res.status(403).json({ error: 'Re-assertion token expired' })
      }
      db.setConfig(`reassert_token_${token}`, '')
      const credentialId = req.params.credentialId as string
      const ok = queue.revokeDevice(credentialId)
      if (!ok) return res.status(404).json({ error: 'Device not found' })
      db.deleteSessionsByCredentialId(credentialId)
      res.json({ revoked: true })
    } catch (err) {
      res.status(500).json({ error: 'Failed to revoke device' })
    }
  })

  // ----- Lockdown (authenticated) -----
  app.post('/api/lockdown', requireAuth(), requireCSRF(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const token = (req.body?.reAssertToken as string) || ''
      if (!token) return res.status(403).json({ error: 'Re-assertion token required' })
      const tokenRaw = db.getConfig(`reassert_token_${token}`)
      if (!tokenRaw) return res.status(403).json({ error: 'Invalid or expired re-assertion token' })
      const tokenData = JSON.parse(tokenRaw)
      if (Date.now() - tokenData.createdAt > tokenData.ttl) {
        db.setConfig(`reassert_token_${token}`, '')
        return res.status(403).json({ error: 'Re-assertion token expired' })
      }
      db.setConfig(`reassert_token_${token}`, '')
      await queue.lockdown()
      res.json({ locked: true })
    } catch (err) {
      res.status(500).json({ error: 'Failed to activate lockdown' })
    }
  })

  app.post('/api/unlock', requireAuth(), requireCSRF(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const token = (req.body?.reAssertToken as string) || ''
      if (!token) return res.status(403).json({ error: 'Re-assertion token required' })
      const tokenRaw = db.getConfig(`reassert_token_${token}`)
      if (!tokenRaw) return res.status(403).json({ error: 'Invalid or expired re-assertion token' })
      const tokenData = JSON.parse(tokenRaw)
      if (Date.now() - tokenData.createdAt > tokenData.ttl) {
        db.setConfig(`reassert_token_${token}`, '')
        return res.status(403).json({ error: 'Re-assertion token expired' })
      }
      db.setConfig(`reassert_token_${token}`, '')
      await queue.unlock()
      res.json({ locked: false })
    } catch (err) {
      res.status(500).json({ error: 'Failed to deactivate lockdown' })
    }
  })

  // ----- Audit (authenticated) -----
  app.get('/api/audit', requireAuth(), apiRateLimiter(30, 60000), (req, res) => {
    try {
      const limit = Math.max(1, Math.min(parseInt(req.query.limit as string, 10) || 100, 500))
      const log = db.getAuditLog(limit)
      res.json(log)
    } catch (err) {
      res.status(500).json({ error: 'Failed to read audit log' })
    }
  })

  // ----- Token Info (authenticated) -----
  app.get('/api/github/token-info', requireAuth(), apiRateLimiter(30, 60000), async (_req, res) => {
    try {
      const info = await client.getTokenInfo()
      res.json(info)
    } catch (err) {
      db.log('error', null, `Token info: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to fetch token info' })
    }
  })

  // ----- Branch Protection Status -----
  app.get('/api/status/branch-protection', requireAuth(), apiRateLimiter(10, 60000), async (_req, res) => {
    try {
      const defaultBranch = await client.getDefaultBranch()
      const protection = await client.getBranchProtection(defaultBranch)
      const issues: string[] = []

      if (!protection.enabled) {
        issues.push(`Branch protection is not enabled on ${defaultBranch}`)
      } else {
        if (!protection.requiredStatusChecks.includes(config.githubStatusContext)) {
          issues.push(`Required status check "${config.githubStatusContext}" is missing from branch protection`)
        }
        if (!protection.adminEnforced) {
          issues.push('Admin bypass is enabled — administrators can push without status checks')
        }
        if (!protection.requiredReviews) {
          issues.push('Pull request reviews are not required')
        }
        if (protection.allowsForcePushes) {
          issues.push(`Force pushes are allowed on ${defaultBranch}`)
        }
      }

      res.json({
        ...protection,
        statusContext: config.githubStatusContext,
        issues,
        secure: issues.length === 0,
      })
    } catch (err) {
      db.log('error', null, `Branch protection check: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to check branch protection' })
    }
  })

  // ----- PR check details -----
  app.get('/api/prs/:number/checks', requireAuth(), apiRateLimiter(30, 60000), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const checks = await client.getCheckRunDetails(pr.sha)
      const rawDiff = await client.compareCommits(pr.sha + '~1', pr.sha).catch(() => null)
      const diff = rawDiff && rawDiff.files ? {
        files: rawDiff.files.length,
        additions: rawDiff.files.reduce((s: number, f: any) => s + (f.additions || 0), 0),
        deletions: rawDiff.files.reduce((s: number, f: any) => s + (f.deletions || 0), 0),
        fileDetails: rawDiff.files.map((f: any) => ({
          filename: f.filename,
          status: f.status,
          additions: f.additions || 0,
          deletions: f.deletions || 0,
          changes: (f.additions || 0) + (f.deletions || 0),
          sizeBytes: f.patch ? Buffer.byteLength(f.patch, 'utf-8') : 0,
        })),
      } : null
      const prFiles = db.getPRFiles(prNumber)
      const history = prFiles.length > 0
        ? db.getFileHistory(prFiles[0].filename).slice(0, 5)
        : []
      res.json({ checks, diff, prFiles, history })
    } catch (err) {
      db.log('error', null, `PR checks: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to fetch PR checks' })
    }
  })

  // ----- File history (timing graph data) -----
  app.get('/api/prs/:number/file-history/:filename', requireAuth(), apiRateLimiter(20, 60000), async (req, res) => {
    try {
      const filename = req.params.filename as string
      const history = db.getFileHistory(filename, 100)
      if (history.length === 0) {
        return res.json({ filename, history: [], workflow: [] })
      }
      const entries = history.map((h: any) => ({
        prNumber: h.prNumber,
        additions: h.additions,
        deletions: h.deletions,
        sizeBytes: h.sizeBytes,
        scannedAt: h.scannedAt,
        totalChanges: (h.additions || 0) + (h.deletions || 0),
      }))
      entries.reverse()
      let workflowHistory = db.getWorkflowHistory(filename)
      if (workflowHistory.length === 0) {
        // Auto-fetch workflow durations from GitHub on first chart view
        try {
          const defaultBranch = await client.getDefaultBranch()
          const wfData = await client.getWorkflowDurationsForFile(filename, defaultBranch)
          if (wfData.length > 0) {
            const wfEntries = wfData.map(w => ({
              sha: w.sha,
              prNumber: 0,
              checkName: w.checkName,
              durationMs: w.durationMs,
            }))
            db.storeWorkflowTimes(filename, wfEntries)
            workflowHistory = db.getWorkflowHistory(filename)
          }
        } catch (_e) {
          // Non-critical — chart shows what we have
        }
      }
      const wfEntries = workflowHistory.map(w => ({
        sha: w.sha,
        prNumber: w.prNumber,
        checkName: w.checkName,
        durationMs: w.durationMs,
        scannedAt: w.scannedAt,
      }))
      const maxChanges = Math.max(...entries.map((e: any) => e.totalChanges), 1)
      const maxSize = Math.max(...entries.map((e: any) => e.sizeBytes), 1)
      const maxDuration = Math.max(...wfEntries.map((w: any) => w.durationMs), 1)
      res.json({ filename, history: entries, workflow: wfEntries, maxChanges, maxSize, maxDuration })
    } catch (err) {
      db.log('error', null, `File history: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to fetch file history' })
    }
  })

  // ----- Workflow telemetry (from GitHub Actions workflow) -----
  app.post('/api/workflow/telemetry', apiRateLimiter(30, 60000), (req, res) => {
    const { entries, token } = req.body
    if (!token || token !== config.githubToken) {
      return res.status(401).json({ error: 'Invalid token' })
    }
    if (!Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'entries array required' })
    }
    db.storeWorkflowTelemetry(entries)
    res.json({ status: 'ok', stored: entries.length })
  })

  // ----- Workflow baselines -----
  app.get('/api/workflow/baselines', requireAuth(), apiRateLimiter(20, 60000), (_req, res) => {
    const records = db.getAllWorkflowRecords()
    const steps = db.getWorkflowSteps()
    const intel = analyzeWorkflowIntelligence(records, steps)
    res.json(intel)
  })

  // ----- Workflow intelligence for a specific PR -----
  app.get('/api/prs/:number/workflow-intel', requireAuth(), apiRateLimiter(20, 60000), (req, res) => {
    const prNumber = parseInt(String(req.params.number), 10)
    const records = db.getAllWorkflowRecords()
    const steps = db.getWorkflowSteps()
    const checkDurations: Record<string, number> = {}
    for (const r of records) {
      if (r.prNumber === prNumber) {
        checkDurations[r.checkName] = r.durationMs
      }
    }
    const intel = analyzeWorkflowIntelligence(records, steps, {
      currentPR: { number: prNumber, checkDurations },
    })
    res.json(intel)
  })

  // ----- CI Integrity (full report for a PR) -----
  app.get('/api/prs/:number/ci-integrity', requireAuth(), apiRateLimiter(10, 60000), async (req, res) => {
    const prNumber = parseInt(String(req.params.number), 10)
    try {
      const records = db.getAllWorkflowRecords()
      const steps = db.getWorkflowSteps()
      const prFiles = db.getPRFiles(prNumber) || []
      // Try to get PR files with patches (from scan context)
      const intel = analyzeWorkflowIntelligence(records, steps, {
        currentPR: { number: prNumber, checkDurations: {} },
        prFiles: prFiles.map((f: any) => ({ filename: f.filename, patch: f.status })),
      })
      res.json(intel)
    } catch (err) {
      res.status(500).json({ error: 'Failed to compute CI integrity' })
    }
  })

  // ----- Step telemetry ingestion -----
  app.post('/api/workflow/telemetry/steps', apiRateLimiter(60, 60000), (req, res) => {
    const { steps, token } = req.body
    if (!token || token !== config.githubToken) {
      return res.status(401).json({ error: 'Invalid token' })
    }
    if (!Array.isArray(steps) || steps.length === 0) {
      return res.status(400).json({ error: 'steps array required' })
    }
    db.storeWorkflowSteps(steps.map((s: any) => ({
      ...s,
      stepNumber: s.stepNumber || s.step_number || 0,
      durationMs: s.durationMs || s.duration_ms || 0,
      prNumber: s.prNumber || s.pr_number || 0,
    })))
    res.json({ status: 'ok', stored: steps.length })
  })

  // ----- CI Policy CRUD -----
  app.get('/api/policy', requireAuth(), (_req, res) => {
    const policy = db.getPolicy()
    res.json(policy || {})
  })

  app.post('/api/policy', requireAuth(), (req, res) => {
    const policy = req.body
    if (!policy || typeof policy !== 'object') {
      return res.status(400).json({ error: 'Policy object required' })
    }
    db.setPolicy('default', policy)
    res.json({ status: 'ok' })
  })

  // ----- Sentinel installer (generates GitHub Actions workflow YAML) -----
  app.get('/api/installer/sentinel-telemetry', requireAuth(), async (_req, res) => {
    const baseUrl = `${_req.protocol}://${_req.headers.host}`
    const ds = String.fromCharCode(36) // dollar sign to avoid template literal issues
    const yaml = [
      'name: Sentinel Telemetry',
      '',
      'on:',
      '  workflow_run:',
      '    workflows: ["*"]',
      '    types:',
      '      - completed',
      '',
      'jobs:',
      '  send-telemetry:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - name: Send timing data to Sentinel Oracle',
      '        env:',
      '          SENTINEL_URL: ' + JSON.stringify(baseUrl),
      '          SENTINEL_TOKEN: ' + JSON.stringify(config.githubToken),
      '        run: |',
      '          curl -s -X POST "' + ds + 'SENTINEL_URL/api/workflow/telemetry" \\',
      '            -H "Content-Type: application/json" \\',
      '            -d \'{"token": "' + ds + 'SENTINEL_TOKEN","entries": [{"checkName": "' + ds + '{{ github.workflow }} / ' + ds + '{{ github.job }}","durationMs": ' + ds + '{{ github.run_duration }},"prNumber": ' + ds + '{{ github.event.workflow_run.pull_requests[0].number || 0 }},"filename": "' + ds + '{{ github.workflow }}"}]}\'',
    ].join('\n')
    res.setHeader('Content-Type', 'text/plain')
    res.send(yaml)
  })

  // ----- Backfill history (full repo PR archive) -----
  let backfillRunning = false
  let backfillProgress = { total: 0, current: 0, errors: 0, lastError: '', done: false }

  app.get('/api/admin/backfill-status', requireAuth(), (_req, res) => {
    res.json(backfillProgress)
  })

  app.post('/api/admin/backfill-history', requireAuth(), async (req, res) => {
    if (backfillRunning) return res.status(409).json({ error: 'Backfill already running' })
    backfillRunning = true
    backfillProgress = { total: 0, current: 0, errors: 0, lastError: '', done: false }
    res.json({ status: 'started', message: 'Backfill started in background' })

    try {
      const checkpoint = db.getBackfillCheckpoint()
      const prs = await client.listAllPRs('closed')
      const merged = prs.filter((p: any) => p.merged_at)
      backfillProgress.total = merged.length
      db.log('backfill', null, `Starting backfill: ${merged.length} merged PRs total, checkpoint at PR #${checkpoint}`)

      for (const pr of merged) {
        if (pr.number <= checkpoint) continue
        try {
          const files = await client.getPRFiles(pr.number)
          if (files.length > 0) {
            db.storePRFiles(pr.number, files, 'authorized')
          }
          db.setBackfillCheckpoint(pr.number)
          backfillProgress.current = merged.indexOf(pr) + 1
        } catch (err: any) {
          backfillProgress.errors++
          backfillProgress.lastError = `PR #${pr.number}: ${err.message}`
          db.log('error', null, `Backfill PR #${pr.number}: ${err.message}`)
        }
        if (pr.number % 5 === 0) {
          db.log('backfill', null, `Backfill progress: PR #${pr.number} / ${merged[merged.length - 1].number}`)
        }
      }
      backfillProgress.done = true
      db.log('backfill', null, `Backfill complete: ${merged.length} PRs processed, ${backfillProgress.errors} errors`)
    } catch (err: any) {
      backfillProgress.lastError = err.message
      db.log('error', null, `Backfill failed: ${err.message}`)
    } finally {
      backfillRunning = false
    }
  })
  app.get('/api/metrics', requireAuth(), apiRateLimiter(20, 60000), (_req, res) => {
    try {
      const completed = db.getCompletedPRs()
      const pending = db.getPendingPRs()

      const totalMergeTime = completed
        .filter(p => p.authStatus === 'authorized' && p.authorizedAt)
        .map(p => ({
          prNumber: p.prNumber,
          title: p.title,
          author: p.author,
          createdAt: p.createdAt,
          authorizedAt: p.authorizedAt!,
          waitMs: p.authorizedAt! - p.createdAt,
          waitHours: ((p.authorizedAt! - p.createdAt) / 3600000).toFixed(1),
        }))

      const byAuthor: Record<string, { total: number; merged: number; rejected: number; totalWaitMs: number }> = {}
      for (const p of completed) {
        if (!byAuthor[p.author]) byAuthor[p.author] = { total: 0, merged: 0, rejected: 0, totalWaitMs: 0 }
        byAuthor[p.author].total++
        if (p.authStatus === 'authorized') {
          byAuthor[p.author].merged++
          if (p.authorizedAt) byAuthor[p.author].totalWaitMs += p.authorizedAt - p.createdAt
        }
        if (p.authStatus === 'rejected') byAuthor[p.author].rejected++
      }

      const authorStats = Object.entries(byAuthor).map(([author, stats]) => ({
        author,
        ...stats,
        avgWaitHours: stats.merged > 0 ? (stats.totalWaitMs / stats.merged / 3600000).toFixed(1) : '0',
      }))

      res.json({
        totalPrs: completed.length + pending.length,
        pending: pending.length,
        authorized: completed.filter(p => p.authStatus === 'authorized').length,
        rejected: completed.filter(p => p.authStatus === 'rejected').length,
        expired: completed.filter(p => p.authStatus === 'expired').length,
        recentMergeTimes: totalMergeTime.map(m => ({
          ...m,
          waitTime: m.waitHours,
        })),
        authorStats: authorStats.map(a => ({
          ...a,
          avgWait: a.avgWaitHours,
        })),
      })
    } catch (err) {
      res.status(500).json({ error: 'Failed to compute metrics' })
    }
  })

  // ----- Token Inventory (authenticated) -----
  const tokenScanner = new TokenInventoryScanner(client, db)

  app.get('/api/inventory/tokens', requireAuth(), apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const tokens = db.getAllTokens()
      res.json(tokens)
    } catch (err) {
      db.log('error', null, `List tokens: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to list tokens' })
    }
  })

  app.get('/api/inventory/tokens/stats', requireAuth(), apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const stats = db.getTokenStats()
      res.json(stats)
    } catch (err) {
      res.status(500).json({ error: 'Failed to get token stats' })
    }
  })

  app.post('/api/inventory/tokens/scan', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (_req, res) => {
    try {
      const result = await tokenScanner.fullScan()
      db.log('token_scan_complete', null, `Scan: ${result.tokensFound} new, ${result.tokensUpdated} updated`)
      res.json(result)
    } catch (err) {
      db.log('error', null, `Token scan: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to scan tokens' })
    }
  })

  app.get('/api/analytics/export', requireAuth(), apiRateLimiter(5, 60000), (_req, res) => {
    try {
      const pendingPRs = db.getPendingPRs()
      const completedPRs = db.getCompletedPRs()
      const auditLog = db.getAuditLog(10000)
      const devices = db.listDevices()
      const tokens = db.getAllTokens()
      const fileAverages = db.getRepoFileAverages()
      const allPRs = [...pendingPRs, ...completedPRs]
      res.json({
        exportedAt: new Date().toISOString(),
        summary: {
          totalPRs: allPRs.length,
          pendingPRs: pendingPRs.length,
          completedPRs: completedPRs.length,
          authorizedPRs: allPRs.filter(p => p.authStatus === 'authorized').length,
          rejectedPRs: allPRs.filter(p => p.authStatus === 'rejected').length,
          expiredPRs: allPRs.filter(p => p.authStatus === 'expired').length,
          registeredDevices: devices.length,
          totalAuditEntries: auditLog.length,
          totalTokens: tokens.length,
          trackedFiles: fileAverages.length,
        },
        pullRequests: allPRs.map(p => ({
          prNumber: p.prNumber,
          title: p.title,
          author: p.author,
          sha: p.sha,
          ciStatus: p.ciStatus,
          sentinelStatus: p.sentinelStatus,
          authStatus: p.authStatus,
          createdAt: p.createdAt,
          authorizedAt: p.authorizedAt,
          deviceName: p.deviceName,
        })),
        auditLog: auditLog.map(e => ({
          timestamp: e.timestamp,
          action: e.action,
          prNumber: e.prNumber,
          detail: e.detail,
        })),
        devices: devices.map(d => ({
          name: d.name,
          credentialId: d.credentialId,
          counter: d.counter,
          createdAt: d.createdAt,
          lastUsedAt: d.lastUsedAt,
        })),
        tokens: tokens.map(t => ({
          tokenType: t.tokenType,
          name: t.name,
          source: t.source,
          scopes: t.scopes,
          firstSeenAt: t.firstSeenAt,
          lastSeenAt: t.lastSeenAt,
          expiresAt: t.expiresAt,
          riskScore: t.riskScore,
        })),
        fileAverages: fileAverages.map(f => ({
          filename: f.filename,
          avgAdditions: f.avgAdditions,
          avgDeletions: f.avgDeletions,
          avgSizeBytes: f.avgSizeBytes,
          prCount: f.count,
        })),
      })
    } catch (err) {
      res.status(500).json({ error: 'Failed to export analytics data' })
    }
  })

  app.post('/api/inventory/tokens/:id/refresh', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const result = await tokenScanner.scanGitHubTokens()
      res.json(result)
    } catch (err) {
      db.log('error', null, `Refresh token: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to refresh token' })
    }
  })

  app.delete('/api/inventory/tokens/:id', requireAuth(), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), (req, res) => {
    try {
      const id = parseInt(req.params.id as string, 10)
      if (isNaN(id)) return res.status(400).json({ error: 'Invalid token id' })
      db.deleteToken(id)
      db.log('token_deleted', null, `Token #${id} removed from inventory`)
      res.json({ deleted: true })
    } catch (err) {
      res.status(500).json({ error: 'Failed to delete token' })
    }
  })

  app.get('/api/inventory/tokens/drift', requireAuth(), apiRateLimiter(10, 60000), async (_req, res) => {
    try {
      const drift = await tokenScanner.detectDrift()
      res.json(drift)
    } catch (err) {
      db.log('error', null, `Drift check: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to check drift' })
    }
  })

  function verifyGitHubWebhook(payload: string, signature: string, secret: string): boolean {
    if (!secret) return false
    const sig = signature.startsWith('sha256=') ? signature.slice(7) : signature
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex')
    if (sig.length !== expected.length) return false
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
  }

  // ----- Webhook receiver for GitHub events -----
  app.post('/api/webhook/github', express.raw({ type: 'application/json' }), async (req, res) => {
    try {
      const event = req.headers['x-github-event'] as string
      const delivery = req.headers['x-github-delivery'] as string
      const signature = req.headers['x-hub-signature-256'] as string
      if (!verifyGitHubWebhook(req.body.toString(), signature, config.githubWebhookSecret || '')) {
        return res.status(401).json({ error: 'Invalid webhook signature' })
      }
      const body = typeof req.body === 'object' ? req.body : JSON.parse(req.body.toString())

      if (!event || !delivery) {
        return res.status(400).json({ error: 'Missing GitHub webhook headers' })
      }

      db.log('webhook_received', null, `Event: ${event}, Delivery: ${delivery.slice(0, 8)}...`)

      if (event === 'pull_request') {
        const action = body.action
        const pr = body.pull_request
        if (!pr) return res.status(200).json({ ok: true })

        if (['opened', 'synchronize', 'reopened'].includes(action)) {
          db.log('webhook_pr_event', pr.number, `PR #${pr.number} ${action} by ${pr.user?.login}`)
          if (config.autoAnalyze && config.aiEnabled) {
            setImmediate(async () => {
              try {
                const files = await client.getPRFiles(pr.number)
                const scanHash = computeScanHash(files, pr.head?.sha || '')
                if (!db.hasAnalysisHash(pr.number, scanHash)) {
                  const analysis = await aiAnalyzePR(pr.number, pr.title || '', pr.user?.login || '', pr.body || '', '', pr.head?.sha || '', files, pr.head?.sha || '', db, config.aiModel || 'auto')
                  db.saveAnalysisResult(pr.number, scanHash, {
                    analysisJson: JSON.stringify(analysis),
                    reviewPriority: analysis.priority.reviewPriority,
                    impactLevel: analysis.priority.impactLevel,
                    complexity: analysis.priority.estimatedComplexity,
                    injectionDetected: analysis.instructionManipulation.length > 0,
                    injectionAttemptsJson: JSON.stringify(analysis.instructionManipulation),
                  })
                  db.log('ai_analyzed', pr.number, `Webhook auto-analyze: priority=${analysis.priority.reviewPriority}`)
                }
              } catch {}
            })
          }
        }

        if (action === 'closed' && pr.merged) {
          const existing = db.getPRByNumber(pr.number)
          if (existing && existing.authStatus !== 'authorized') {
            db.log('unauthorized_merge_detected', pr.number,
              `PR #${pr.number} was merged without Oracle authorization by ${pr.merged_by?.login || 'unknown'}`
            )
          }
        }
      }

      if (event === 'push') {
        const ref = body.ref
        if (ref === 'refs/heads/main' || ref === 'refs/heads/master') {
          db.log('push_to_main', null, `Push to ${ref} by ${body.pusher?.name || 'unknown'}`)
        }
      }

      res.status(200).json({ ok: true })
    } catch (err) {
      db.log('error', null, `Webhook processing error: ${err instanceof Error ? err.message : err}`)
      res.status(200).json({ ok: true })
    }
  })

  // ----- GitHub Config (unauthenticated in setup mode, authenticated otherwise) -----
  function configAuth(req: any, res: any, next: () => void): void {
    const isSetup = !config.githubAppId || !config.githubOwner || !config.githubRepo
    if (isSetup) return next()
    requireAuth()(req, res, next)
  }

  app.get('/api/config/github-status', (_req, res) => {
    res.json({
      configured: !!config.githubAppId && !!config.githubOwner && !!config.githubRepo,
      hasPat: !!config.githubToken,
      hasApp: !!config.githubAppId && !!config.githubInstallationId,
      appId: config.githubAppId || '',
      installationId: config.githubInstallationId || '',
      owner: config.githubOwner || '',
      repo: config.githubRepo || '',
      privateKeyConfigured: !!config.githubPrivateKeyPath || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY_PATH,
      authMode: client.authMode || 'none',
      scanEnabled: config.scanEnabled,
      webhookSecretConfigured: !!config.githubWebhookSecret,
      serverOrigin: config.serverOrigin,
      webhookUrl: config.serverOrigin + '/api/webhook/github',
    })
  })

  app.post('/api/config/github', configAuth, (req, res) => {
    try {
      const { appId, installationId, privateKey, privateKeyPath, owner, repo } = req.body
      if (!owner || !repo) {
        return res.status(400).json({ error: 'Owner and repository are required' })
      }
      const toSave: Record<string, unknown> = { githubOwner: owner, githubRepo: repo }
      if (appId) toSave.githubAppId = String(appId)
      if (installationId) toSave.githubInstallationId = String(installationId)
      let resolvedKeyPath: string | undefined
      if (privateKey && typeof privateKey === 'string' && privateKey.includes('BEGIN')) {
        resolvedKeyPath = path.join(config.dataDir, 'private-key.pem')
        fs.writeFileSync(resolvedKeyPath, privateKey, { mode: 0o600 })
      } else if (privateKeyPath && typeof privateKeyPath === 'string') {
        const normalizedPath = path.resolve(privateKeyPath)
        if (!fs.existsSync(normalizedPath)) {
          return res.status(400).json({ error: `Private key file not found: ${normalizedPath}` })
        }
        const pemContent = fs.readFileSync(normalizedPath, 'utf-8')
        if (!pemContent.includes('BEGIN') || !pemContent.includes('PRIVATE KEY')) {
          return res.status(400).json({ error: 'File does not appear to be a valid PEM private key' })
        }
        resolvedKeyPath = path.join(config.dataDir, 'private-key.pem')
        fs.writeFileSync(resolvedKeyPath, pemContent, { mode: 0o600 })
      }
      if (resolvedKeyPath) {
        toSave.githubPrivateKeyPath = resolvedKeyPath
        config.githubPrivateKeyPath = resolvedKeyPath
      }
      if (appId) config.githubAppId = String(appId)
      if (installationId) config.githubInstallationId = String(installationId)
      config.githubOwner = owner
      config.githubRepo = repo
      saveConfig(toSave)
      db.log('config_github', null, `GitHub config updated: ${owner}/${repo}`)
      res.json({ success: true, message: 'Configuration saved. Restart server to apply changes.' })
    } catch (err) {
      db.log('error', null, `GitHub config save: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to save configuration' })
    }
  })

  app.post('/api/config/webhook', configAuth, (req, res) => {
    try {
      const { secret } = req.body
      if (typeof secret !== 'string') {
        return res.status(400).json({ error: 'Secret must be a string' })
      }
      config.githubWebhookSecret = secret
      saveConfig({ githubWebhookSecret: secret })
      db.log('config_webhook', null, 'Webhook secret updated')
      res.json({ success: true })
    } catch (err) {
      db.log('error', null, `Webhook save: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to save webhook secret' })
    }
  })

  app.post('/api/config/settings', configAuth, (req, res) => {
    try {
      const { scanEnabled, autoScan, aiEnabled, autoAnalyze, securityInbox, analystQueue, challengeTtlMs, approveReasonRequired, aiModel } = req.body
      const toSave: Record<string, unknown> = {}
      if (typeof scanEnabled === 'boolean') {
        toSave.scanEnabled = scanEnabled
        config.scanEnabled = scanEnabled
      }
      if (typeof autoScan === 'boolean') {
        toSave.autoScan = autoScan
        config.autoScan = autoScan
      }
      if (typeof aiEnabled === 'boolean') {
        toSave.aiEnabled = aiEnabled
        config.aiEnabled = aiEnabled
      }
      if (typeof autoAnalyze === 'boolean') {
        toSave.autoAnalyze = autoAnalyze
        config.autoAnalyze = autoAnalyze
      }
      if (typeof securityInbox === 'boolean') {
        toSave.securityInbox = securityInbox
        config.securityInbox = securityInbox
      }
      if (typeof analystQueue === 'boolean') {
        toSave.analystQueue = analystQueue
        config.analystQueue = analystQueue
      }
      if (typeof challengeTtlMs === 'number' && challengeTtlMs >= 30000) {
        toSave.challengeTtlMs = challengeTtlMs
        config.challengeTtlMs = challengeTtlMs
      }
      if (typeof approveReasonRequired === 'boolean') {
        toSave.approveReasonRequired = approveReasonRequired
        config.approveReasonRequired = approveReasonRequired
      }
      if (typeof aiModel === 'string') {
        toSave.aiModel = aiModel
        config.aiModel = aiModel
      }
      if (Object.keys(toSave).length === 0) {
        return res.status(400).json({ error: 'No valid settings provided' })
      }
      saveConfig(toSave)
      db.log('config_settings', null, `Settings updated: ${Object.keys(toSave).join(', ')}`)
      res.json({ success: true })
    } catch (err) {
      db.log('error', null, `Settings save: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to save settings' })
    }
  })

  // ----- Security DNA -----
  app.get('/api/dna', requireAuth(), async (_req, res) => {
    try {
      const owner = config.githubOwner || ''
      const repo = config.githubRepo || ''
      if (!owner || !repo) {
        return res.json({ current: null, history: [], changes: [], summary: 'No repository configured', snapshotCount: 0 })
      }
      const snapshots = db.getCapabilitySnapshots(owner, repo, 90)
      if (snapshots.length === 0) {
        return res.json({ current: null, history: [], changes: [], summary: 'No snapshots yet. Scan a PR to generate DNA.', snapshotCount: 0 })
      }
      const current = snapshots[snapshots.length - 1].snapshot
      const history = snapshots.map(s => s.snapshot)
      const report = buildDNAReport(current, history.slice(0, -1))
      res.json(report)
    } catch (err) {
      db.log('error', null, `DNA fetch: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to fetch DNA' })
    }
  })

  // ----- Status -----
  app.get('/api/status', (_req, res) => {
    const pendingCount = db.getPendingPRs().length
    const devices = db.listDevices()
    res.json({
      uptime: process.uptime(),
      pendingPRs: pendingCount,
      registeredDevices: devices.length,
      locked: queue.isLocked(),
      setupRequired: !db.getConfig('enrollment_completed'),
      authMode: client.authMode,
      scanEnabled: config.scanEnabled,
      autoScan: config.autoScan,
      aiEnabled: config.aiEnabled,
      autoAnalyze: config.autoAnalyze,
      securityInbox: config.securityInbox,
      analystQueue: config.analystQueue,
      passwordRequired: !!config.passwordHash,
      githubConfigured: !!config.githubAppId && !!config.githubOwner && !!config.githubRepo,
      version: '1.0.0',
    })
  })

  // ----- Polling -----
  let pollInterval: ReturnType<typeof setTimeout> | null = null
  let pollFailCount = 0
  const POLL_BASE_MS = 30000
  const POLL_MAX_MS = 1800000

  function schedulePoll(delayMs: number) {
    pollInterval = setTimeout(async function pollCycle() {
      try {
        if (queue.isLocked()) {
          schedulePoll(delayMs)
          return
        }
        const defaultBranch = await client.getDefaultBranch()
        const result = await pollPRs(client, db, defaultBranch)
        pollFailCount = 0
        queue.expireStaleChallenges()
        const expiredChallengeCount = db.pruneExpiredWebAuthnChallenges(config.challengeTtlMs)
        if (expiredChallengeCount > 0) {
          db.log('cleanup', null, `Cleaned up ${expiredChallengeCount} expired WebAuthn challenges`)
        }
        if (result.newPRs > 0 || result.updatedPRs > 0) {
          db.log('poll_complete', null, `Polled: ${result.newPRs} new, ${result.updatedPRs} updated`)
        }
        // Auto-scan new/updated PRs if autoScan is enabled
        if (config.autoScan && config.scanEnabled) {
          const pending = db.getPendingPRs()
          for (const pr of pending) {
            try {
              const files = await client.getPRFiles(pr.prNumber)
              if (files.length === 0) continue
              db.storePRFiles(pr.prNumber, files)
              const scanHash = computeScanHash(files, pr.sha)
              if (!db.hasScanHash(pr.prNumber, scanHash)) {
                const sResult = await scanPRFiles(files, pr.prNumber, config.githubOwner, config.githubRepo, pr.sha)
                db.saveScanResult(pr.prNumber, scanHash, sResult)
                db.log('pr_scanned', pr.prNumber, `Auto-scan: risk ${sResult.riskScore} (${sResult.critical}C ${sResult.high}H ${sResult.medium}M ${sResult.low}L)`)
              }
            } catch {}
          }
        }
        if (config.autoAnalyze && config.aiEnabled) {
          const pending = db.getPendingPRs()
          for (const pr of pending) {
            try {
              const files = await client.getPRFiles(pr.prNumber)
              if (files.length === 0) continue
              const scanHash = computeScanHash(files, pr.sha)
              if (!db.hasAnalysisHash(pr.prNumber, scanHash)) {
                const analysis = await aiAnalyzePR(pr.prNumber, pr.title, pr.author, pr.title, '', pr.sha, files, pr.sha, db, config.aiModel || 'auto')
                db.saveAnalysisResult(pr.prNumber, scanHash, {
                  analysisJson: JSON.stringify(analysis),
                  reviewPriority: analysis.priority.reviewPriority,
                  impactLevel: analysis.priority.impactLevel,
                  complexity: analysis.priority.estimatedComplexity,
                  injectionDetected: analysis.instructionManipulation.length > 0,
                  injectionAttemptsJson: JSON.stringify(analysis.instructionManipulation),
                })
                db.log('ai_analyzed', pr.prNumber, `Auto-analyze: priority=${analysis.priority.reviewPriority}`)
              }
            } catch {}
          }
        }
        const lastTokenScan = parseInt(db.getConfig('last_token_scan') || '0', 10)
        if (Date.now() - lastTokenScan > 3600000) {
          try {
            const scanResult = await tokenScanner.scanGitHubTokens()
            if (scanResult.tokensFound > 0 || scanResult.tokensUpdated > 0) {
              db.log('token_scan_auto', null, `Auto-scan: ${scanResult.tokensFound} new, ${scanResult.tokensUpdated} updated`)
            }
            db.setConfig('last_token_scan', String(Date.now()))
          } catch {}
        }
        schedulePoll(POLL_BASE_MS)
      } catch (err) {
        pollFailCount++
        const backoff = Math.min(POLL_BASE_MS * Math.pow(2, pollFailCount - 1), POLL_MAX_MS)
        if (pollFailCount <= 3 || pollFailCount % 10 === 0) {
          db.log('error', null, `Poll failed (x${pollFailCount}): ${err instanceof Error ? err.message : err} — next retry in ${Math.round(backoff / 1000)}s`)
        }
        schedulePoll(backoff)
      }
    }, delayMs)
  }

  function startPolling() {
    stopPolling()
    schedulePoll(POLL_BASE_MS)
  }

  function stopPolling() {
    if (pollInterval) {
      clearTimeout(pollInterval)
      pollInterval = null
    }
  }

  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = err.status || 400
    res.status(status).json({ error: err.message || 'Bad request' })
  })

  return { app, startPolling, stopPolling }
}
