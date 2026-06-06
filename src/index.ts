import { loadConfig } from './config'
import { DatabaseStore } from './storage/database'
import { GitHubClient } from './github/client'
import { createApp } from './server'
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
    process.exit(1)
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
          process.exit(1)
        }
      }
    } catch {
      if (item.required === 'file') {
        console.error(`[security] Missing required file: ${item.path}`)
        process.exit(1)
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
    process.exit(1)
  }
}

function main() {
  const config = loadConfig()
  ensureCredentials(config)
  validatePermissions(config.dataDir)

  const db = new DatabaseStore(config.dataDir)
  const client = new GitHubClient(config.githubToken, config.githubOwner, config.githubRepo, config.githubStatusContext)

  client.verifyToken().then(valid => {
    if (!valid) {
      console.error('GitHub token verification failed — check token permissions')
      process.exit(1)
    }
  })

  const { app, startPolling, stopPolling } = createApp(config, db, client)

  const httpsOptions = getHttpsOptions(config.dataDir)

  const server = https.createServer(httpsOptions, app)
  server.listen(config.port, config.host, () => {
    console.log(`Sentinel Oracle running on https://${config.bindAddress}:${config.port}`)
    console.log(`Dashboard: https://${config.bindAddress}:${config.port}`)
    console.log(`RP ID:     ${config.rpId}`)
    console.log(`Origin:    ${config.serverOrigin}`)
  })

  // Recover lockdown state
  const wasLocked = db.getConfig('system_lockdown') === 'true'
  if (wasLocked) {
    console.warn('[lockdown] System was in lockdown mode at shutdown — restoring')
  }

  startPolling()

  process.on('SIGINT', () => {
    console.log('Shutting down...')
    stopPolling()
    db.close()
    server.close()
    process.exit(0)
  })

  process.on('SIGTERM', () => {
    console.log('Shutting down...')
    stopPolling()
    db.close()
    server.close()
    process.exit(0)
  })
}

main()
