import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { randomBytes } from 'crypto'
import { networkInterfaces } from 'os'

export interface Config {
  port: number
  host: string
  bindAddress: string
  dataDir: string
  githubToken: string
  githubAppId: string
  githubInstallationId: string
  githubPrivateKeyPath: string
  githubOwner: string
  githubRepo: string
  githubStatusContext: string
  serverOrigin: string
  rpId: string
  challengeTtlMs: number
  rateLimitAuth: number
  rateLimitWindowMs: number
  encryptionKey: Buffer
  approveReasonRequired: boolean
  locked: boolean
}

const CONFIG_PATH = path.join(os.homedir(), '.sentinel-oracle', 'config.json')

function loadOrCreateEncryptionKey(dataDir: string): Buffer {
  const keyPath = path.join(dataDir, '.encryption_key')
  try {
    return fs.readFileSync(keyPath)
  } catch {
    const key = randomBytes(32)
    fs.mkdirSync(dataDir, { recursive: true })
    fs.writeFileSync(keyPath, key, { mode: 0o600 })
    return key
  }
}

function detectLanIp(): string {
  const nets = networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address
      }
    }
  }
  return '127.0.0.1'
}

function validateConfig(config: Partial<Config>): string[] {
  const warnings: string[] = []
  if (config.bindAddress === '127.0.0.1' || config.bindAddress === 'localhost') {
    warnings.push('bindAddress is set to loopback — phone will not be able to reach the server')
  }
  if (config.port && config.port < 1024 && process.platform !== 'win32') {
    warnings.push('port < 1024 may require root privileges on Linux')
  }
  return warnings
}

export function loadConfig(): Config {
  const dataDir = path.join(os.homedir(), '.sentinel-oracle')
  fs.mkdirSync(dataDir, { recursive: true })

  const lanIp = detectLanIp()

  const defaults: Config = {
    port: 3443,
    host: '0.0.0.0',
    bindAddress: lanIp,
    dataDir,
    githubToken: '',
    githubAppId: '',
    githubInstallationId: '',
    githubPrivateKeyPath: '',
    githubOwner: '',
    githubRepo: '',
    githubStatusContext: 'Sentinel Authorization',
    serverOrigin: `https://${lanIp}:3443`,
    rpId: lanIp,
    challengeTtlMs: 45000,
    rateLimitAuth: 5,
    rateLimitWindowMs: 60000,
    encryptionKey: loadOrCreateEncryptionKey(dataDir),
    approveReasonRequired: false,
    locked: false,
  }

  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, 'utf8')
      const user = JSON.parse(raw)
      const merged = { ...defaults, ...user, encryptionKey: defaults.encryptionKey }

      const warnings = validateConfig(merged)
      for (const w of warnings) {
        console.warn('[config] Warning:', w)
      }

      return merged
    }
  } catch (err) {
    console.error('[config] Failed to load config.json:', err)
    process.exit(1)
  }

  console.log(`[config] Detected LAN IP: ${lanIp}`)
  console.log(`[config] No config.json found — using defaults. Run with https://${lanIp}:3443`)
  return defaults
}

export function saveConfig(partial: Partial<Config>): void {
  const dir = path.dirname(CONFIG_PATH)
  fs.mkdirSync(dir, { recursive: true })
  const existing: Record<string, unknown> = {}
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      Object.assign(existing, JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')))
    }
  } catch {}
  for (const [k, v] of Object.entries(partial)) {
    if (k !== 'encryptionKey') {
      existing[k] = v
    }
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(existing, null, 2), { mode: 0o600 })
}
