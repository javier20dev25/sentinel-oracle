import type { DatabaseStore, PendingPR } from '../storage/database'
import { createAuthChallenge } from '../auth/challenge'
import type { ChallengeResult } from '../auth/challenge'
import { verifyAssertion } from '../auth/webauthn'
import { verifyChallengeToken } from '../crypto/signing'
import type { GitHubClient } from '../github/client'
import { logEvent } from '../logger'

const QR_MAX_AGE_MS = 45000

export class AuthorizationQueue {
  private db: DatabaseStore
  private client: GitHubClient
  private challengeTtlMs: number
  private serverOrigin: string
  private rpId: string

  constructor(db: DatabaseStore, client: GitHubClient, challengeTtlMs: number, serverOrigin: string, rpId: string) {
    this.db = db
    this.client = client
    this.challengeTtlMs = challengeTtlMs
    this.serverOrigin = serverOrigin
    this.rpId = rpId
  }

  isLocked(): boolean {
    const val = this.db.getConfig('system_lockdown')
    return val === 'true'
  }

  setLocked(locked: boolean): void {
    this.db.setConfig('system_lockdown', locked ? 'true' : 'false')
  }

  getPendingPRs(): PendingPR[] {
    return this.db.getPendingPRs()
  }

  async initiateAuthorization(prNumber: number): Promise<ChallengeResult | null> {
    if (this.isLocked()) return null

    const pr = this.db.getPRByNumber(prNumber)
    if (!pr) return null
    if (pr.authStatus !== 'pending') return null

    const challenge = await createAuthChallenge(prNumber, this.db, this.challengeTtlMs, this.serverOrigin)
    this.db.log('challenge_created', prNumber, `Challenge ${challenge.challengeId} created with TTL ${this.challengeTtlMs}ms`)
    return challenge
  }

  async confirmAuthorization(
    prNumber: number,
    challengeId: string,
    webauthnCredential: unknown,
    webauthnChallenge: string,
    reason?: string,
  ): Promise<{ success: boolean; error?: string; merged?: boolean }> {
    if (this.isLocked()) {
      return { success: false, error: 'System is locked down' }
    }

    // 1. Read challenge data (without consuming)
    const challenge = this.db.getChallenge(challengeId)
    if (!challenge) {
      return { success: false, error: 'Challenge expired or invalid' }
    }
    if (challenge.used !== 0) {
      return { success: false, error: 'Challenge already used' }
    }
    if (challenge.prNumber !== prNumber) {
      return { success: false, error: 'Challenge does not match PR' }
    }

    // 2. Verify HMAC signature on QR payload (fail fast before expensive WebAuthn)
    try {
      const payload = JSON.parse(challenge.data)
      if (!payload.sig) {
        this.db.log('hmac_missing', prNumber, `QR payload missing signature for challenge ${challengeId}`)
        return { success: false, error: 'Challenge missing integrity signature' }
      }
      const valid = verifyChallengeToken(
        { challengeId, prNumber, timestamp: payload.ts, signature: payload.sig },
        this.challengeTtlMs,
      )
      if (!valid) {
        this.db.log('hmac_verify_failed', prNumber, `QR signature verification failed for challenge ${challengeId}`)
        return { success: false, error: 'Challenge integrity check failed' }
      }
    } catch {
      return { success: false, error: 'Challenge data malformed' }
    }

    // 3. Consume challenge first (atomic — prevents double-use race)
    const consumed = this.db.consumeChallenge(challengeId)
    if (!consumed) {
      this.db.log('challenge_race_lost', prNumber, `Challenge ${challengeId} consumed by concurrent request`)
      return { success: false, error: 'Challenge already used' }
    }

    // 4. Verify WebAuthn assertion (PR-bound)
    const assertionResult = await verifyAssertion(
      webauthnCredential,
      webauthnChallenge,
      this.db,
      this.serverOrigin,
      this.rpId,
      prNumber,
    )
    if (!assertionResult.verified) {
      this.db.log('webauthn_failed', prNumber, `WebAuthn assertion verification failed for challenge ${challengeId}`)
      return { success: false, error: 'Biometric authentication failed' }
    }

    const pr = this.db.getPRByNumber(prNumber)
    if (!pr) {
      return { success: false, error: 'PR not found' }
    }

    // 5. Re-check lockdown before granting (TOCTOU prevention)
    if (this.isLocked()) {
      this.db.log('lockdown_blocked', prNumber, `Authorization blocked by lockdown after WebAuthn verification`)
      return { success: false, error: 'System was locked during authorization' }
    }

    // 6. Grant authorization
    const device = this.db.getDeviceByCredentialId(assertionResult.credentialId)
    const deviceName = device?.name || assertionResult.credentialId.slice(0, 16) + '...'
    this.db.setAuthStatus(prNumber, 'authorized', deviceName)
    const detail = `Authorized by ${deviceName}${reason ? ` — ${reason}` : ''}`
    this.db.log('authorization_granted', prNumber, detail)
    logEvent('PR #' + prNumber + ' authorized', deviceName)

    let statusOk = false
    try {
      if (pr.checkRunId) {
        await this.client.updateCheckRun(pr.checkRunId, 'success', `Authorized by ${deviceName}${reason ? ` — ${reason}` : ''}`)
      }
      statusOk = true
    } catch (err) {
      this.db.log('check_run_update_failed', prNumber, `Check Run update failed: ${err}`)
    }

    // 7. Execute merge
    let merged = false
    try {
      merged = await this.client.mergePR(prNumber, pr.sha)
      if (merged) {
        this.db.log('merge_executed', prNumber, 'PR merged by Sentinel Oracle')
        logEvent('PR #' + prNumber + ' merged', pr.sha.slice(0, 7))
      } else {
        this.db.log('merge_failed', prNumber, 'GitHub merge API returned non-success')
        logEvent('PR #' + prNumber + ' merge failed', 'GitHub API returned non-success')
      }
    } catch (err) {
      this.db.log('merge_failed', prNumber, `Merge execution failed: ${err}`)
      logEvent('PR #' + prNumber + ' merge error', String(err))
    }

    if (!statusOk) {
      return { success: true, merged, error: 'Authorized but failed to update GitHub status' }
    }

    return { success: true, merged }
  }

  async rejectAuthorization(prNumber: number, reason?: string): Promise<void> {
    this.db.setAuthStatus(prNumber, 'rejected')
    this.db.log('authorization_rejected', prNumber, `Rejected by administrator${reason ? `: ${reason}` : ''}`)

    const pr = this.db.getPRByNumber(prNumber)
    if (pr && pr.checkRunId) {
      try {
        await this.client.updateCheckRun(pr.checkRunId, 'failure', `Authorization rejected${reason ? `: ${reason}` : ''}`)
      } catch {}
    }
  }

  expireStaleChallenges(): number {
    let count = 0
    const prs = this.db.getPendingPRs()
    for (const pr of prs) {
      if (pr.authStatus === 'pending') {
        const old = Date.now() - pr.createdAt
        if (old > 3600000) {
          this.db.setAuthStatus(pr.prNumber, 'expired')
          this.db.log('authorization_expired', pr.prNumber, 'PR authorization expired after 1 hour')
          if (pr.checkRunId) {
            this.client.updateCheckRun(pr.checkRunId, 'timed_out', 'Authorization request expired after 1 hour').catch(() => {})
          }
          count++
        }
      }
    }
    return count
  }

  async lockdown(): Promise<void> {
    this.setLocked(true)
    this.db.log('lockdown_activated', null, 'Emergency lockdown activated — all pending authorizations rejected')
    logEvent('LOCKDOWN ACTIVATED', 'All pending authorizations rejected')

    const prs = this.db.getPendingPRs()
    for (const pr of prs) {
      if (pr.authStatus === 'pending') {
        this.db.setAuthStatus(pr.prNumber, 'rejected')
        if (pr.checkRunId) {
          try {
            await this.client.updateCheckRun(pr.checkRunId, 'failure', 'System locked down')
          } catch {}
        }
      }
    }
  }

  async unlock(): Promise<void> {
    this.setLocked(false)
    this.db.log('lockdown_deactivated', null, 'Emergency lockdown deactivated')
    logEvent('LOCKDOWN DEACTIVATED')
  }

  revokeDevice(credentialId: string): boolean {
    const device = this.db.getDeviceByCredentialId(credentialId)
    if (!device) return false
    this.db.deleteDevice(credentialId)
    this.db.log('device_revoked', null, `Device "${device.name}" (${credentialId.slice(0, 16)}...) revoked`)
    return true
  }
}
