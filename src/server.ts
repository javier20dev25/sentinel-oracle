import crypto from 'crypto'
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
      db.log('error', null, `WebAuthn register begin: ${err instanceof Error ? err.message : err}`)
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
      db.log('error', null, `WebAuthn register complete: ${err instanceof Error ? err.message : err}`)
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
      db.log('error', null, `WebAuthn assert begin: ${err instanceof Error ? err.message : err}`)
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

      if (result.credentialId && !result.prNumber) {
        const sessionId = db.createSession(result.credentialId, device?.name || 'unknown', getSessionTTL())
        res.setHeader('Set-Cookie', createSessionCookie(sessionId))
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
    const sessionId = req.signedCookies?.sentinel_session
    if (!sessionId) return res.json({ authenticated: false })
    const session = db.getSession(sessionId)
    if (!session) {
      res.setHeader('Set-Cookie', clearSessionCookie())
      return res.json({ authenticated: false })
    }
    res.json({ authenticated: true, deviceName: session.deviceName })
  })

  app.post('/api/session/logout', (req, res) => {
    const sessionId = req.signedCookies?.sentinel_session
    if (sessionId) {
      db.deleteSession(sessionId)
      db.log('session_logout', null, 'Session explicitly terminated')
    }
    res.setHeader('Set-Cookie', clearSessionCookie())
    res.json({ loggedOut: true })
  })

  // ----- Enrollment -----
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
      db.log('error', null, `Password change: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to set password' })
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

      const sessionId = db.createSession(result.credentialId, deviceName || 'Admin Device', getSessionTTL())
      res.setHeader('Set-Cookie', createSessionCookie(sessionId))

      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `Setup complete: ${err instanceof Error ? err.message : err}`)
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
      db.log('error', null, `List PRs: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to list PRs' })
    }
  })

  app.get('/api/prs/history', requireAuth(db), apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const prs = db.getCompletedPRs()
      res.json(prs)
    } catch (err) {
      db.log('error', null, `List history: ${err instanceof Error ? err.message : err}`)
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
      db.log('error', null, `Initiate authorization: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to initiate authorization' })
    }
  })

  app.post('/api/prs/:number/confirm', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
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

  app.post('/api/prs/:number/reject', requireAuth(db), authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const { reason } = req.body
      await queue.rejectAuthorization(prNumber, reason)
      res.json({ rejected: true, prNumber })
    } catch (err) {
      db.log('error', null, `Reject authorization: ${err instanceof Error ? err.message : err}`)
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
      db.log('error', null, `Token info: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to fetch token info' })
    }
  })

  // ----- Branch Protection Status -----
  app.get('/api/status/branch-protection', requireAuth(db), apiRateLimiter(10, 60000), async (_req, res) => {
    try {
      const protection = await client.getBranchProtection('main')
      const issues: string[] = []

      if (!protection.enabled) {
        issues.push('Branch protection is not enabled on main')
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
          issues.push('Force pushes are allowed on main')
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
  app.get('/api/prs/:number/checks', requireAuth(db), apiRateLimiter(30, 60000), async (req, res) => {
    try {
      const prNumber = parseInt(req.params.number as string, 10)
      const pr = db.getPRByNumber(prNumber)
      if (!pr) return res.status(404).json({ error: 'PR not found' })
      const checks = await client.getCheckRunDetails(pr.sha)
      const diff = await client.compareCommits(pr.sha + '~1', pr.sha).catch(() => null)
      res.json({ checks, diff })
    } catch (err) {
      db.log('error', null, `PR checks: ${err instanceof Error ? err.message : err}`)
      res.status(500).json({ error: 'Failed to fetch PR checks' })
    }
  })

  // ----- Metrics -----
  app.get('/api/metrics', requireAuth(db), apiRateLimiter(20, 60000), (_req, res) => {
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
        totalPRs: completed.length + pending.length,
        pendingPRs: pending.length,
        authorizedPRs: completed.filter(p => p.authStatus === 'authorized').length,
        rejectedPRs: completed.filter(p => p.authStatus === 'rejected').length,
        expiredPRs: completed.filter(p => p.authStatus === 'expired').length,
        totalMergeTime,
        authorStats,
      })
    } catch (err) {
      res.status(500).json({ error: 'Failed to compute metrics' })
    }
  })

  function verifyGitHubWebhook(payload: string, signature: string, secret: string): boolean {
    if (!secret) return true
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
        db.log('error', null, `Poll failed: ${err instanceof Error ? err.message : err}`)
      }
    }, intervalMs)
  }

  function stopPolling() {
    if (pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
    }
  }

  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = err.status || 400
    res.status(status).json({ error: err.message || 'Bad request' })
  })

  return { app, startPolling, stopPolling }
}
