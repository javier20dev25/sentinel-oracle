import { setDefaultResultOrder } from 'dns'
import * as fs from 'fs'
import * as readline from 'readline'
setDefaultResultOrder('ipv4first')

const packageJson = JSON.parse(fs.readFileSync(__dirname + '/../package.json', 'utf8'))

const args = process.argv.slice(2)
const noAuth = args.includes('--noauth')
if (noAuth) {
  console.log(' [--noauth] WebAuthn session auth DISABLED — all requests accepted without authentication')
}

if (args.includes('--help') || args.includes('-h')) {
  console.log(`sentinel-oracle v${packageJson.version}

Usage:
  sentinel-oracle                    Start the HTTPS server (default)
  sentinel-oracle start              Start the server
  sentinel-oracle scan               Run a one-time security scan on the configured repository
  sentinel-oracle --version, -v      Print version
  sentinel-oracle --help, -h         Print this help
  sentinel-oracle --noauth           Start without WebAuthn session authentication

Environment:
  SENTINEL_CONFIG_DIR    Configuration directory (default: ~/.config/sentinel-oracle)
  SENTINEL_PORT          HTTPS server port (default: 8443)
  SENTINEL_HOST          Bind address (default: localhost)
  NODE_OPTIONS           Passed to Node.js (e.g. --max-old-space-size=4096)

Documentation: https://github.com/javier20dev25/sentinel-oracle`)
  process.exit(0)
}
if (args.includes('--version') || args.includes('-v')) {
  console.log(packageJson.version)
  process.exit(0)
}

import { loadConfig } from './config'
import { DatabaseStore } from './storage/database'
import { GitHubClient } from './github/client'
import type { GitHubAppConfig } from './github/auth'
import { createApp, initEnrollment } from './server'
import { initHmacKey } from './crypto/signing'
import { printBanner, printHealthSummary } from './startup'
import { runSetupWizard } from './setup-wizard'
import * as https from 'https'

function resolveCredentials(config: ReturnType<typeof loadConfig>): { tokenOrConfig: string | GitHubAppConfig; warnings: string[] } {
  const warnings: string[] = []

  const hasPat = !!config.githubToken
  const hasEnvKey = !!process.env.SENTINEL_GITHUB_PRIVATE_KEY || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY_PATH
  const hasApp = !!config.githubAppId && !!config.githubInstallationId && (!!config.githubPrivateKeyPath || hasEnvKey)

  if (!hasPat && !hasApp) {
    return {
      tokenOrConfig: '',
      warnings: ['GitHub not configured — starting in setup mode. Configure via Web UI.'],
    }
  }

  if (hasPat && hasApp) {
    warnings.push('Both githubToken and GitHub App credentials provided — using GitHub App mode')
  }

  if (hasApp) {
    if (config.githubPrivateKeyPath && !hasEnvKey && !fs.existsSync(config.githubPrivateKeyPath)) {
      console.error(`GitHub App private key not found at: ${config.githubPrivateKeyPath}`)
      process.exit(1)
    }
    return {
      tokenOrConfig: {
        appId: config.githubAppId,
        installationId: config.githubInstallationId,
        privateKeyPath: config.githubPrivateKeyPath,
      },
      warnings,
    }
  }

  if (hasPat) {
    return { tokenOrConfig: config.githubToken, warnings }
  }

  console.error(
    'Missing credentials: provide either githubToken (PAT) OR ' +
    '(githubAppId + githubInstallationId + githubPrivateKeyPath) ' +
    'or set SENTINEL_GITHUB_PRIVATE_KEY / SENTINEL_GITHUB_PRIVATE_KEY_PATH env vars',
  )
  process.exit(1)
}

function ensureCredentials(config: ReturnType<typeof loadConfig>): boolean {
  const missing: string[] = []
  const hasPat = !!config.githubToken
  const hasEnvKey = !!process.env.SENTINEL_GITHUB_PRIVATE_KEY || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY_PATH
  const hasApp = !!config.githubAppId && !!config.githubInstallationId && (!!config.githubPrivateKeyPath || hasEnvKey)

  if (!hasPat && !hasApp) {
    missing.push('githubToken OR (githubAppId + githubInstallationId + githubPrivateKeyPath)')
  }
  if (!config.githubOwner) missing.push('githubOwner')
  if (!config.githubRepo) missing.push('githubRepo')
  if (missing.length > 0) {
    console.warn(`[setup] Missing GitHub config: ${missing.join(', ')}`)
    console.warn(`[setup] Server will start in setup mode — configure via web UI`)
    return false
  }
  return true
}

function validatePermissions(configDir: string): void {
  const items = [
    { path: configDir, required: 'dir' },
    { path: `${configDir}\\config.json`, required: 'optional' },
    { path: `${configDir}\\server.key`, required: 'file' },
    { path: `${configDir}\\server.cert`, required: 'file' },
    { path: `${configDir}\\private-key.pem`, required: 'optional' },
    { path: `${configDir}\\.encryption_key`, required: 'file' },
    { path: `${configDir}\\.cookie_secret`, required: 'file' },
    { path: `${configDir}\\.hmac_seed`, required: 'file' },
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

function gracefulExit(code: number): never {
  setTimeout(() => process.exit(code), 100)
  throw new Error('exiting')
}

async function main() {
  const configWarnings: string[] = []
  const origWarn = console.warn
  console.warn = (msg: string) => { configWarnings.push(String(msg)) }
  const config = loadConfig()
  console.warn = origWarn

  ensureCredentials(config)
  validatePermissions(config.dataDir)

  const { tokenOrConfig, warnings } = resolveCredentials(config)
  configWarnings.push(...warnings)

  const db = new DatabaseStore(config.dataDir, config.encryptionKey)
  initHmacKey(config.hmacSeed)
  initEnrollment(config, db)

  let client = new GitHubClient(tokenOrConfig, config.githubOwner, config.githubRepo, config.githubStatusContext)

  let valid = false
  const isTty = process.stdout.isTTY
  const hasApp = !!config.githubAppId && !!config.githubInstallationId && (!!config.githubPrivateKeyPath || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY || !!process.env.SENTINEL_GITHUB_PRIVATE_KEY_PATH)

  function startSetupMode(msg: string) {
    console.log()
    console.log(` ${msg}`)
    console.log(' Starting in setup mode — configure via the Web UI.')
    console.log()
  }

  // Check if GitHub App is configured but verify fails — skip PAT wizard
  if (tokenOrConfig && typeof tokenOrConfig !== 'string') {
    valid = await client.verifyToken()
    if (!valid) {
      console.log()
      console.log(' GitHub App verification failed — check clock sync and private key.')
      console.log(' Starting in setup mode. Configure GitHub or fix the App credentials')
      console.log(' via the Web UI (Settings > GitHub Config).')
      console.log()
    } else {
      configWarnings.push(`[auth] Using ${client.authMode} authentication`)
    }
  } else if (process.env.SENTINEL_SKIP_TOKEN_VERIFY === '1') {
    configWarnings.push('[dev] SENTINEL_SKIP_TOKEN_VERIFY=1 — GitHub token verification skipped')
  } else if (!tokenOrConfig && isTty) {
    // ─── No credentials at all → offer menu ───
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    console.log()
    console.log(' GitHub not configured.')
    console.log()
    console.log('  1 — Configure via terminal (fine-grained PAT)')
    console.log('  2 — Configure via Web UI  (start server, then set up from browser)')
    console.log()
    const answer = await new Promise<string>(resolve => rl.question(' Choose (1/2): ', resolve))
    rl.close()

    if (answer.trim() === '1') {
      const result = await runSetupWizard(config.githubOwner, config.githubRepo)
      if (result) {
        const reloaded = loadConfig()
        const r = resolveCredentials(reloaded)
        configWarnings.push(...r.warnings)
        client = new GitHubClient(r.tokenOrConfig, reloaded.githubOwner, reloaded.githubRepo, reloaded.githubStatusContext)
        Object.assign(config, reloaded)
        valid = await client.verifyToken()
      }
    }
    if (!valid) startSetupMode('Configure a PAT or GitHub App from the Web UI.')
  } else if (tokenOrConfig && isTty && typeof tokenOrConfig === 'string') {
    // ─── PAT configured but may be invalid → verify first ───
    valid = await client.verifyToken()
    if (!valid) {
      console.log()
      console.log(' Saved PAT is invalid or expired.')
      console.log()
      console.log('  1 — Replace with a new PAT')
      console.log('  2 — Start in setup mode (configure via Web UI)')
      console.log()
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
      const answer = await new Promise<string>(resolve => rl.question(' Choose (1/2): ', resolve))
      rl.close()

      if (answer.trim() === '1') {
        const result = await runSetupWizard(config.githubOwner, config.githubRepo)
        if (result) {
          const reloaded = loadConfig()
          const r = resolveCredentials(reloaded)
          configWarnings.push(...r.warnings)
          client = new GitHubClient(r.tokenOrConfig, reloaded.githubOwner, reloaded.githubRepo, reloaded.githubStatusContext)
          Object.assign(config, reloaded)
          valid = await client.verifyToken()
        }
      }
      if (!valid) startSetupMode('Fix the PAT or switch to GitHub App from the Web UI.')
    } else {
      configWarnings.push(`[auth] Using ${client.authMode} authentication`)
    }
  } else if (!isTty) {
    console.error('No GitHub token configured — run with SENTINEL_SKIP_TOKEN_VERIFY=1 to skip')
    gracefulExit(1)
  }

  const setupMode = !valid
  if (setupMode) {
    configWarnings.push('[setup] Server running in setup mode — configure via the Web UI')
  }

  const { app, startPolling, stopPolling } = createApp(config, db, client, noAuth)

  const httpsOptions = getHttpsOptions(config.dataDir)

  const server = https.createServer(httpsOptions, app)
  server.listen(config.port, config.host, () => {
    printBanner(config, db)
    for (const w of configWarnings) {
      console.error(w)
    }
    printHealthSummary(config)
    const wasLocked = db.getConfig('system_lockdown') === 'true'
    if (wasLocked) {
      console.error('[lockdown] System was in lockdown mode at shutdown — restoring')
    }
  })

  if (!setupMode) {
    startPolling()
  }

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
