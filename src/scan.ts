import { loadConfig } from './config'
import { GitHubClient } from './github/client'
import type { GitHubAppConfig } from './github/auth'
import { scanPRFiles } from './scanner/index'
import { applyConfiguredCloud } from './cloud/account'
import { initHmacKey } from './crypto/signing'
import { createHash } from 'node:crypto'
import { newOracleExecutionId, resolveOracleGroupScanContext, reserveOracleGroupScan, settleOracleGroupScan } from './cloud/group-local-scan'

function resolveCredentials(config: ReturnType<typeof loadConfig>): string | GitHubAppConfig {
  const hasPat = !!config.githubToken
  const hasEnvKey = !!process.env.SENTINEL_GITHUB_PRIVATE_KEY || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY_PATH
  const hasApp = !!config.githubAppId && !!config.githubInstallationId && (!!config.githubPrivateKeyPath || hasEnvKey)

  if (hasApp) {
    return {
      appId: config.githubAppId,
      installationId: config.githubInstallationId,
      privateKeyPath: config.githubPrivateKeyPath,
    }
  }
  if (hasPat) {
    return config.githubToken
  }
  throw new Error('No GitHub credentials configured. Set githubToken or GitHub App credentials.')
}

export async function runScan(): Promise<void> {
  const config = loadConfig()
  if (!config.githubOwner || !config.githubRepo) {
    throw new Error('Repository not configured. Set githubOwner and githubRepo.')
  }

  applyConfiguredCloud(config)
  initHmacKey(config.hmacSeed)
  // Group mode is opt-in and fail-closed. With no group mode configured the
  // existing local/offline workflow remains independent of Cloud billing.
  const groupScan = resolveOracleGroupScanContext(config)
  const client = new GitHubClient(resolveCredentials(config), config.githubOwner, config.githubRepo, config.githubStatusContext)

  console.log(`Scanning ${config.githubOwner}/${config.githubRepo} (${groupScan ? 'group-authorized local' : 'independent local'} mode)...`)

  let scannedCount = 0
  let errorCount = 0

  const prs = await client.listOpenPRs()
  for (const pr of prs) {
    try {
      console.log(`  PR #${pr.number}: ${pr.title}`)
      const files = await client.getPRFiles(pr.number)
      const scanHash = createHash('sha256').update(pr.sha).update(JSON.stringify(files.map((file) => ({ filename: file.filename, patch: file.patch ?? '' })))).digest('hex')
      const executionId = newOracleExecutionId()
      const groupReservation = groupScan
        ? await reserveOracleGroupScan(groupScan, pr.number, pr.sha, scanHash, `${config.githubOwner}/${config.githubRepo}`)
        : null
      const startedAt = Date.now()
      let result
      try {
        result = await scanPRFiles(files, pr.number, config.githubOwner, config.githubRepo, pr.sha, scanHash)
      } catch (error) {
        if (groupScan && groupReservation) {
          try {
            await settleOracleGroupScan(groupScan, groupReservation.reservationId, 'FAILED', {
              executionId, commitSha: pr.sha, pullRequest: pr.number, toolVersion: 'sentinel-oracle/1.0.2', durationMs: Date.now() - startedAt,
              findings: { critical: 0, high: 0, medium: 0, low: 0 },
            })
          } catch { /* Cloud expires abandoned reservations if offline */ }
        }
        throw error
      }
      if (groupScan && groupReservation) {
        try {
          await settleOracleGroupScan(groupScan, groupReservation.reservationId, 'COMPLETED', {
            executionId, commitSha: pr.sha, pullRequest: pr.number, toolVersion: 'sentinel-oracle/1.0.2', durationMs: Date.now() - startedAt,
            findings: { critical: result.critical, high: result.high, medium: result.medium, low: result.low },
          })
        } catch {
          throw new Error('Local scan completed, but Cloud quota/activity settlement failed; the result is not reported as group-settled.')
        }
      }
      scannedCount++
      console.log(`    State: ${result.state} — Risk: ${result.riskScore} (${result.findings.length} findings, ${Object.keys(result.intel || {}).length} intel modules)`)
      if (result.stateReasons.length > 0) {
        for (const r of result.stateReasons.slice(0, 8)) console.log(`      - ${r}`)
      }
    } catch (err: any) {
      errorCount++
      console.error(`    ERROR: ${err.message}`)
    }
  }

  console.log(`\nDone. ${scannedCount} PRs scanned, ${errorCount} errors.`)
}
