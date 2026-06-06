import express from 'express'
import * as path from 'path'
import type { Config } from './config'
import type { DatabaseStore } from './storage/database'
import type { GitHubClient } from './github/client'
import { AuthorizationQueue } from './queue/authorization'
import { pollPRs } from './github/monitor'
import { securityHeaders, corsBlock, auditLogger } from './middleware/security'
import { authRateLimiter, apiRateLimiter } from './middleware/rateLimit'
import {
  generateRegistration,
  verifyRegistration,
  generateAssertion,
  verifyAssertion,
  getRpId,
} from './auth/webauthn'

export function createApp(config: Config, db: DatabaseStore, client: GitHubClient) {
  const app = express()
  const rpId = getRpId(config)
  const queue = new AuthorizationQueue(db, client, config.challengeTtlMs, config.serverOrigin, rpId)

  app.disable('x-powered-by')

  app.use(securityHeaders())
  app.use(corsBlock)
  app.use(auditLogger(db))
  app.use(express.json({ limit: '1mb' }))
  app.use(express.static(path.join(__dirname, '..', 'public')))

  // ----- WebAuthn Registration -----
  app.post('/api/webauthn/register/begin', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
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

  app.post('/api/webauthn/register/complete', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
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
      db.log('authenticated', null, `Device "${device?.name || 'unknown'}" authenticated`)
      res.json({ verified: true, credentialId: result.credentialId })
    } catch (err) {
      db.log('error', null, `WebAuthn assert complete: ${err}`)
      res.status(500).json({ error: 'Assertion completion failed' })
    }
  })

  // ----- Authorization -----
  app.get('/api/prs', apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const prs = queue.getPendingPRs()
      res.json(prs)
    } catch (err) {
      db.log('error', null, `List PRs: ${err}`)
      res.status(500).json({ error: 'Failed to list PRs' })
    }
  })

  app.post('/api/prs/:number/authorize', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), (req, res) => {
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
      const { challengeId, credential, challenge: webauthnChallenge, reason } = req.body

      if (!challengeId) return res.status(400).json({ error: 'challengeId required' })
      if (!credential) return res.status(400).json({ error: 'credential (WebAuthn assertion) required' })
      if (!webauthnChallenge) return res.status(400).json({ error: 'challenge (WebAuthn challenge) required' })

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

  app.post('/api/prs/:number/reject', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (req, res) => {
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

  // ----- Devices -----
  app.get('/api/devices', apiRateLimiter(30, 60000), (_req, res) => {
    try {
      const devices = db.listDevices().map(d => ({
        id: d.id,
        name: d.name,
        credentialId: d.credentialId,
        createdAt: d.createdAt,
        lastUsedAt: d.lastUsedAt,
      }))
      res.json(devices)
    } catch (err) {
      res.status(500).json({ error: 'Failed to list devices' })
    }
  })

  app.post('/api/devices/:credentialId/revoke', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), (req, res) => {
    try {
      const credentialId = req.params.credentialId as string
      const ok = queue.revokeDevice(credentialId)
      if (!ok) return res.status(404).json({ error: 'Device not found' })
      res.json({ revoked: true })
    } catch (err) {
      res.status(500).json({ error: 'Failed to revoke device' })
    }
  })

  // ----- Lockdown -----
  app.post('/api/lockdown', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (_req, res) => {
    try {
      await queue.lockdown()
      res.json({ locked: true })
    } catch (err) {
      res.status(500).json({ error: 'Failed to activate lockdown' })
    }
  })

  app.post('/api/unlock', authRateLimiter(config.rateLimitAuth, config.rateLimitWindowMs), async (_req, res) => {
    try {
      await queue.unlock()
      res.json({ locked: false })
    } catch (err) {
      res.status(500).json({ error: 'Failed to deactivate lockdown' })
    }
  })

  // ----- Audit -----
  app.get('/api/audit', apiRateLimiter(30, 60000), (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 100
      const log = db.getAuditLog(Math.min(limit, 500))
      res.json(log)
    } catch (err) {
      res.status(500).json({ error: 'Failed to read audit log' })
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

  return { app, startPolling, stopPolling }
}
