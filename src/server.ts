import express from 'express'
import cookieParser from 'cookie-parser'
import * as path from 'path'
import type { Config } from './config'
import type { DatabaseStore } from './storage/database'
import type { GitHubClient } from './github/client'
import { AuthorizationQueue } from './queue/authorization'
import { pollPRs } from './github/monitor'
import { securityHeaders, corsBlock, auditLogger } from './middleware/security'
import { requireAuth, createSessionCookie, clearSessionCookie, getSessionTTL } from './middleware/session'
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

function generateEnrollmentToken(): string {
  const { randomBytes } = require('crypto')
  return randomBytes(16).toString('hex')
}

let _enrollmentToken: string | null = null
let _enrollmentUsed = false

export function getEnrollmentToken(): string {
  return _enrollmentToken || ''
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
  console.log(`  Enrollment token: ${_enrollmentToken}`)
  console.log(`  Token refreshes every ${config.enrollmentTokenTtlMs / 1000}s — check terminal for updates`)
  console.log(`  POST /api/setup/begin  {"enrollmentToken":"${_enrollmentToken}","deviceName":"..."}`)
  console.log(`  =============================\n`)
  db.log('enrollment_token_created', null, 'Enrollment token generated (one-time)')

  // Auto-refresh enrollment token
  const interval = setInterval(() => {
    if (_enrollmentUsed || db.getConfig('enrollment_completed') === 'true') {
      clearInterval(interval)
      return
    }
    _enrollmentToken = generateEnrollmentToken()
    console.log(`\n  ===== ENROLLMENT TOKEN REFRESHED =====`)
    console.log(`  New token: ${_enrollmentToken}`)
    console.log(`  POST /api/setup/begin  {"enrollmentToken":"${_enrollmentToken}","deviceName":"..."}`)
    console.log(`  =====================================\n`)
    db.log('enrollment_token_refreshed', null, 'Enrollment token refreshed')
  }, config.enrollmentTokenTtlMs)

  try {
    require('fs').writeFileSync(require('os').homedir() + '\\.sentinel-oracle\\.enrollment_token', _enrollmentToken, 'utf8')
  } catch {}
}

export function createApp(config: Config, db: DatabaseStore, client: GitHubClient) {
  const app = express()
  const rpId = getRpId(config)
  const queue = new AuthorizationQueue(db, client, config.challengeTtlMs, config.serverOrigin, rpId)

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
  app.use(cookieParser(config.encryptionKey.toString('hex')))
  app.use(express.static(path.join(__dirname, '..', 'public')))
  app.get('/authorize', (_req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'authorize.html'))
  })

  // ----- WebAuthn Registration (authenticated) -----
  app.post('/api/webauthn/register/begin', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { deviceName } = req.body
      if (!deviceName || typeof deviceName !== 'string') {
        return res.status(400).json({ error: 'deviceName required' })
      }
      const result = await generateRegistration(deviceName, db, config.serverOrigin, rpId)
      res.json(result)
    } catch (err) {
      db.log('error', null, `WebAuthn register begin: ${err}`)
      res.status(500).json({ error: 'Registration initialization failed' })
    }
  })

  app.post('/api/webauthn/register/complete', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
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
      db.log('error', null, `WebAuthn register complete: ${err}`)
      res.status(500).json({ error: 'Registration completion failed' })
    }
  })

  // ----- WebAuthn Assertion -----
  app.post('/api/webauthn/assert/begin', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = req.body?.prNumber ? parseInt(req.body.prNumber, 10) : undefined
      const result = await generateAssertion(db, config.serverOrigin, rpId, prNumber)
      res.json(result)
    } catch (err) {
      db.log('error', null, `WebAuthn assert begin: ${err}`)
      res.status(500).json({ error: 'Assertion initialization failed' })
    }
  })

  app.post('/api/webauthn/assert/complete', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { credential, challenge } = req.body
      const result = await verifyAssertion(credential, challenge, db, config.serverOrigin, rpId)
      if (!result.verified) {
        return res.status(401).json({ error: 'Authentication failed' })
      }
      const device = db.getDeviceByCredentialId(result.credentialId)

      // Create session only if this is a dashboard login (no PR number in assertion)
      // Phone authorizations (PR-bound) do NOT create sessions
      if (result.credentialId && !result.prNumber) {
        const sessionId = db.createSession(result.credentialId, device?.name || 'unknown', getSessionTTL())
        res.setHeader('Set-Cookie', createSessionCookie(sessionId))
        db.log('session_created', null, `Session for device "${device?.name || 'unknown'}"`)
      }

      db.log('authenticated', null, `Device "${device?.name || 'unknown'}" authenticated`)
      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `WebAuthn assert complete: ${err}`)
      res.status(500).json({ error: 'Assertion completion failed' })
    }
  })

  // ----- Session -----
  app.get('/api/session/check', (req, res) => {
    const sessionId = req.cookies?.sentinel_session
    if (!sessionId) return res.json({ authenticated: false })
    const session = db.getSession(sessionId)
    if (!session) {
      res.setHeader('Set-Cookie', clearSessionCookie())
      return res.json({ authenticated: false })
    }
    res.json({ authenticated: true, deviceName: session.deviceName })
  })

  app.post('/api/session/logout', (req, res) => {
    const sessionId = req.cookies?.sentinel_session
    if (sessionId) {
      db.deleteSession(sessionId)
      db.log('session_logout', null, 'Session explicitly terminated')
    }
    res.setHeader('Set-Cookie', clearSessionCookie())
    res.json({ loggedOut: true })
  })

  // ----- Debug: verify enrollment token -----
  app.get('/api/debug/enrollment', (_req, res) => {
    console.log('[_enrollmentToken]', _enrollmentToken, '_enrollmentUsed:', _enrollmentUsed)
    res.json({ token: _enrollmentToken, used: _enrollmentUsed })
  })

  // ----- Enrollment password management -----
  app.post('/api/config/password', requireAuth(db), authRateLimiter(5, 60000), (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body
      if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ error: 'Password must be at least 4 characters' })
      }
      if (config.passwordHash && !verifyPassword(currentPassword, config.passwordHash)) {
        return res.status(403).json({ error: 'Current password is incorrect' })
      }
      config.passwordHash = hashPassword(newPassword)
      saveConfig({ passwordHash: config.passwordHash })
      db.log('password_set', null, 'Enrollment password was set or changed')
      res.json({ success: true })
    } catch (err) {
      db.log('error', null, `Password change: ${err}`)
      res.status(500).json({ error: 'Failed to set password' })
    }
  })

  // ----- Setup / First Device Enrollment -----
  app.post('/api/setup/begin', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { enrollmentToken, deviceName } = req.body
      console.log('[setup/begin] received token:', JSON.stringify(enrollmentToken), 'expected:', _enrollmentToken, 'used:', _enrollmentUsed)
      if (_enrollmentUsed || !_enrollmentToken) {
        return res.status(403).json({ error: 'Enrollment not available — already completed or disabled' })
      }
      if (!enrollmentToken || enrollmentToken !== _enrollmentToken) {
        return res.status(403).json({ error: 'Invalid enrollment token' })
      }
      if (!deviceName || typeof deviceName !== 'string') {
        return res.status(400).json({ error: 'deviceName required' })
      }

      const result = await generateRegistration('admin-' + deviceName, db, config.serverOrigin, rpId)
      res.json(result)
    } catch (err) {
      db.log('error', null, `Setup begin: ${err}`)
      res.status(500).json({ error: 'Setup initialization failed' })
    }
  })

  app.post('/api/setup/complete', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const { credential, challenge, deviceName, enrollmentToken } = req.body
      console.log('[setup/complete] received token:', JSON.stringify(enrollmentToken), 'expected:', _enrollmentToken, 'used:', _enrollmentUsed)
      if (_enrollmentUsed || !_enrollmentToken) {
        return res.status(403).json({ error: 'Enrollment not available' })
      }
      if (!enrollmentToken || enrollmentToken !== _enrollmentToken) {
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

      // Auto-create session
      const sessionId = db.createSession(result.credentialId, deviceName || 'Admin Device', getSessionTTL())
      res.setHeader('Set-Cookie', createSessionCookie(sessionId))

      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `Setup complete: ${err}`)
      res.status(500).json({ error: 'Setup completion failed' })
    }
  })

  // ----- Authorization (authenticated) -----
  app.get('/api/prs', requireAuth(db), apiRateLimiter(30, 60000), async (_req, res) => {
    try {
      try {
        await pollPRs(client, db)
      } catch {}
      const prs = queue.getPendingPRs()
      res.json(prs)
    } catch (err) {
      db.log('error', null, `List PRs: ${err}`)
      res.status(500).json({ error: 'Failed to list PRs' })
    }
  })

  app.get('/api/prs/history', requireAuth(db), apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const prs = db.getCompletedPRs()
      res.json(prs)
    } catch (err) {
      db.log('error', null, `List history: ${err}`)
      res.status(500).json({ error: 'Failed to list history' })
    }
  })

  app.post('/api/prs/:number/authorize', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const challenge = queue.initiateAuthorization(prNumber)
      if (!challenge) {
        const locked = queue.isLocked()
        return res.status(locked ? 423 : 404).json({
          error: locked ? 'System is locked down' : 'PR not found or not awaiting authorization',
        })
      }
      res.json(challenge)
    } catch (err) {
      db.log('error', null, `Initiate authorization: ${err}`)
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

      // Enrollment password verification
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

      res.json({ authorized: true, prNumber, merged: true })
    } catch (err) {
      db.log('error', null, `Confirm authorization: ${err}`)
      res.status(500).json({ error: 'Failed to confirm authorization' })
    }
  })

  app.post('/api/prs/:number/reject', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const { reason } = req.body
      await queue.rejectAuthorization(prNumber, reason)
      res.json({ rejected: true, prNumber })
    } catch (err) {
      db.log('error', null, `Reject authorization: ${err}`)
      res.status(500).json({ error: 'Failed to reject authorization' })
    }
  })

  // ----- Devices (authenticated) -----
  app.get('/api/devices', requireAuth(db), apiRateLimiter(30, 60000), (_req, res) => {
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

  app.post('/api/devices/:credentialId/revoke', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), (req, res) => {
    try {
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
  app.post('/api/lockdown', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (_req, res) => {
    try {
      await queue.lockdown()
      res.json({ locked: true })
    } catch (err) {
      res.status(500).json({ error: 'Failed to activate lockdown' })
    }
  })

  app.post('/api/unlock', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (_req, res) => {
    try {
      await queue.unlock()
      res.json({ locked: false })
    } catch (err) {
      res.status(500).json({ error: 'Failed to deactivate lockdown' })
    }
  })

  // ----- Audit (authenticated) -----
  app.get('/api/audit', requireAuth(db), apiRateLimiter(30, 60000), (req, res) => {
    try {
      const limit = Math.max(1, Math.min(parseInt(req.query.limit as string, 10) || 100, 500))
      const log = db.getAuditLog(limit)
      res.json(log)
    } catch (err) {
      res.status(500).json({ error: 'Failed to read audit log' })
    }
  })

  // ----- Token Info (authenticated) -----
  app.get('/api/github/token-info', requireAuth(db), apiRateLimiter(30, 60000), async (_req, res) => {
    try {
      const info = await client.getTokenInfo()
      res.json(info)
    } catch (err) {
      db.log('error', null, `Token info: ${err}`)
      res.status(500).json({ error: 'Failed to fetch token info' })
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
      version: '1.0.0',
    })
  })

  // ----- Polling -----
  let pollInterval: ReturnType<typeof setInterval> | null = null

  function startPolling(intervalMs = 30000) {
    if (pollInterval) clearInterval(pollInterval)
    pollInterval = setInterval(async () => {
      try {
        if (queue.isLocked()) return
        const result = await pollPRs(client, db)
        queue.expireStaleChallenges()
        if (result.newPRs > 0 || result.updatedPRs > 0) {
          db.log('poll_complete', null, `Polled: ${result.newPRs} new, ${result.updatedPRs} updated`)
        }
      } catch (err) {
        db.log('error', null, `Poll failed: ${err}`)
      }
    }, intervalMs)
  }

  function stopPolling() {
    if (pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
    }
  }

  // Error handler — returns JSON for body parser / validation errors
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = err.status || 400
    res.status(status).json({ error: err.message || 'Bad request' })
  })

  return { app, startPolling, stopPolling }
}
