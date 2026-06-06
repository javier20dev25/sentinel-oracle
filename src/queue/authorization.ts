import type { DatabaseStore, PendingPR } from '../storage/database'
import { createAuthChallenge } from '../auth/challenge'
import type { ChallengeResult } from '../auth/challenge'
import { verifyAssertion } from '../auth/webauthn'
import type { GitHubClient } from '../github/client'

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

  initiateAuthorization(prNumber: number): ChallengeResult | null {
    if (this.isLocked()) return null

    const pr = this.db.getPRByNumber(prNumber)
    if (!pr) return null
    if (pr.authStatus !== 'pending') return null

    const challenge = createAuthChallenge(prNumber, this.db, this.challengeTtlMs, this.serverOrigin)
    this.db.log('challenge_created', prNumber, `Challenge ${challenge.challengeId} created with TTL ${this.challengeTtlMs}ms`)
    return challenge
  }

  async confirmAuthorization(
    prNumber: number,
    challengeId: string,
    webauthnCredential: unknown,
    webauthnChallenge: string,
    reason?: string,
  ): Promise<{ success: boolean; error?: string }> {
    if (this.isLocked()) {
      return { success: false, error: 'System is locked down' }
    }

    // 1. Verify WebAuthn assertion (PR-bound)
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

    // 2. Consume QR challenge
    const consumed = this.db.consumeChallenge(challengeId)
    if (!consumed) {
      return { success: false, error: 'Challenge expired or already used' }
    }
    if (consumed.prNumber !== prNumber) {
      return { success: false, error: 'Challenge does not match PR' }
    }

    const pr = this.db.getPRByNumber(prNumber)
    if (!pr) {
      return { success: false, error: 'PR not found' }
    }

    // 3. Grant authorization
    this.db.setAuthStatus(prNumber, 'authorized')
    const detail = `Authorized by ${assertionResult.credentialId.slice(0, 16)}...${reason ? ` Reason: ${reason}` : ''}`
    this.db.log('authorization_granted', prNumber, detail)

    let statusOk = false
    try {
      await this.client.setCommitStatus(pr.sha, 'success', 'Authorized via physical authentication')
      statusOk = true
    } catch (err) {
      this.db.log('status_update_failed', prNumber, `GitHub status update failed: ${err}`)
    }

    // 4. Execute merge
    let merged = false
    try {
      merged = await this.client.mergePR(prNumber, pr.sha)
      if (merged) {
        this.db.log('merge_executed', prNumber, 'PR merged by Sentinel Oracle')
      } else {
        this.db.log('merge_failed', prNumber, 'GitHub merge API returned non-success')
      }
    } catch (err) {
      this.db.log('merge_failed', prNumber, `Merge execution failed: ${err}`)
    }

    if (!statusOk) {
      return { success: true, error: 'Authorized but failed to update GitHub status' }
    }

    return { success: true }
  }

  async rejectAuthorization(prNumber: number, reason?: string): Promise<void> {
    this.db.setAuthStatus(prNumber, 'rejected')
    this.db.log('authorization_rejected', prNumber, `Rejected by administrator${reason ? `: ${reason}` : ''}`)

    const pr = this.db.getPRByNumber(prNumber)
    if (pr) {
      try {
        await this.client.setCommitStatus(pr.sha, 'failure', 'Authorization rejected')
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
          count++
        }
      }
    }
    return count
  }

  async lockdown(): Promise<void> {
    this.setLocked(true)
    this.db.log('lockdown_activated', null, 'Emergency lockdown activated — all pending authorizations rejected')

    const prs = this.db.getPendingPRs()
    for (const pr of prs) {
      if (pr.authStatus === 'pending') {
        this.db.setAuthStatus(pr.prNumber, 'rejected')
        try {
          await this.client.setCommitStatus(pr.sha, 'failure', 'System locked down')
        } catch {}
      }
    }
  }

  async unlock(): Promise<void> {
    this.setLocked(false)
    this.db.log('lockdown_deactivated', null, 'Emergency lockdown deactivated')
  }

  revokeDevice(credentialId: string): boolean {
    const device = this.db.getDeviceByCredentialId(credentialId)
    if (!device) return false
    this.db.deleteDevice(credentialId)
    this.db.log('device_revoked', null, `Device "${device.name}" (${credentialId.slice(0, 16)}...) revoked`)
    return true
  }
}
