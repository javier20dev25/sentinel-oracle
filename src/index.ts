// Force public DNS + IPv4-first (avoids getaddrinfo ENOTFOUND on some Windows networks)
import { setDefaultResultOrder, setServers, promises as dns } from 'dns'
setServers(['8.8.8.8', '1.1.1.1'])
setDefaultResultOrder('ipv4first')

import { loadConfig } from './config'
import { DatabaseStore } from './storage/database'
import { GitHubClient } from './github/client'
import { createApp, initEnrollment } from './server'
import { initHmacKey } from './crypto/signing'
import { printStartupBanner } from './startup'
import * as fs from 'fs'
import * as https from 'https'

function ensureCredentials(config: ReturnType<typeof loadConfig>) {
  const missing: string[] = []
  if (config.githubToken) {
    // PAT mode - ok
  } else if (config.githubAppId && config.githubInstallationId && config.githubPrivateKeyPath) {
    // GitHub App mode - ok
  } else {
    missing.push('githubToken OR (githubAppId + githubInstallationId + githubPrivateKeyPath)')
  }
  if (!config.githubOwner) missing.push('githubOwner')
  if (!config.githubRepo) missing.push('githubRepo')
  if (missing.length > 0) {
    console.error(`Missing required config: ${missing.join(', ')}`)
    console.error(`Set them in ${require('os').homedir()}\\.sentinel-oracle\\config.json`)
    gracefulExit(1)
  }
}

function validatePermissions(configDir: string): void {
  const items = [
    { path: configDir, required: 'dir' },
    { path: `${configDir}\\config.json`, required: 'optional' },
    { path: `${configDir}\\server.key`, required: 'file' },
    { path: `${configDir}\\server.cert`, required: 'file' },
    { path: `${configDir}\\.encryption_key`, required: 'file' },
  ]
  for (const item of items) {
    try {
      const stat = fs.statSync(item.path)
      if (item.required !== 'dir' && !stat.isFile()) {
        if (item.required === 'file') {
          console.error(`[security] Expected file not found: ${item.path}`)
          gracefulExit(1)
        }
      }
    } catch {
      if (item.required === 'file') {
        console.error(`[security] Missing required file: ${item.path}`)
        gracefulExit(1)
      }
    }
  }
}

function getHttpsOptions(configDir: string): { key: string; cert: string } {
  const keyPath = `${configDir}\\server.key`
  const certPath = `${configDir}\\server.cert`

  try {
    return {
      key: fs.readFileSync(keyPath, 'utf8'),
      cert: fs.readFileSync(certPath, 'utf8'),
    }
  } catch {
    console.error('TLS certificates not found. Generate them:')
    console.error(`  openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 365 -nodes`)
    gracefulExit(1)
  }
}

// Windows libuv bug: direct process.exit with pending handles => assertion
function gracefulExit(code: number): never {
  setTimeout(() => process.exit(code), 100)
  throw new Error('exiting')
}

async function main() {
  // Buffer config warnings to print after banner
  const configWarnings: string[] = []
  const origWarn = console.warn
  console.warn = (msg: string) => { configWarnings.push(String(msg)) }
  const config = loadConfig()
  console.warn = origWarn

  ensureCredentials(config)
  validatePermissions(config.dataDir)

  const db = new DatabaseStore(config.dataDir, config.encryptionKey)
  initHmacKey(config.encryptionKey)
  initEnrollment(config, db)
  const client = new GitHubClient(config.githubToken, config.githubOwner, config.githubRepo, config.githubStatusContext)

  // Warm DNS cache for GitHub API (avoids intermittent ENOTFOUND on some Windows networks)
  try {
    await dns.resolve('api.github.com')
  } catch {}

  const skipVerify = process.env.SENTINEL_SKIP_TOKEN_VERIFY === '1'
  if (skipVerify) {
    configWarnings.push('[dev] SENTINEL_SKIP_TOKEN_VERIFY=1 — GitHub token verification skipped')
  } else {
    const valid = await client.verifyToken()
    if (!valid) {
      console.error('GitHub token verification failed — check token permissions')
      console.error('Set SENTINEL_SKIP_TOKEN_VERIFY=1 to skip (development only)')
      gracefulExit(1)
    }
  }

  const { app, startPolling, stopPolling } = createApp(config, db, client)

  const httpsOptions = getHttpsOptions(config.dataDir)

  const server = https.createServer(httpsOptions, app)
  server.listen(config.port, config.host, () => {
    printStartupBanner(config, db)
    for (const w of configWarnings) {
      console.error(w)
    }
    const wasLocked = db.getConfig('system_lockdown') === 'true'
    if (wasLocked) {
      console.error('[lockdown] System was in lockdown mode at shutdown — restoring')
    }
  })

  startPolling()

  process.on('SIGINT', () => {
    stopPolling()
    db.close()
    server.close()
    gracefulExit(0)
  })

  process.on('SIGTERM', () => {
    stopPolling()
    db.close()
    server.close()
    gracefulExit(0)
  })
}

main().catch(err => {
  console.error(err)
  gracefulExit(1)
})
