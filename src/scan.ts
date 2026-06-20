import { loadConfig } from './config'
import { GitHubClient } from './github/client'
import type { GitHubAppConfig } from './github/auth'
import { scanPRFiles } from './scanner/index'
import { initHmacKey } from './crypto/signing'

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

  initHmacKey(config.hmacSeed)
  const client = new GitHubClient(resolveCredentials(config), config.githubOwner, config.githubRepo, config.githubStatusContext)

  console.log(`Scanning ${config.githubOwner}/${config.githubRepo}...`)

  let scannedCount = 0
  let errorCount = 0

  const prs = await client.listOpenPRs()
  for (const pr of prs) {
    try {
      console.log(`  PR #${pr.number}: ${pr.title}`)
      const files = await client.getPRFiles(pr.number)
      const result = await scanPRFiles(files, pr.number, config.githubOwner, config.githubRepo, pr.sha)
      scannedCount++
      console.log(`    Risk: ${result.riskScore} (${result.findings.length} findings, ${Object.keys(result.intel || {}).length} intel modules)`)
    } catch (err: any) {
      errorCount++
      console.error(`    ERROR: ${err.message}`)
    }
  }

  console.log(`\nDone. ${scannedCount} PRs scanned, ${errorCount} errors.`)
}
