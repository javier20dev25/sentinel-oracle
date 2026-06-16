import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { execSync } from 'child_process'
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
  cookieSecret: string
  hmacSeed: Buffer
  approveReasonRequired: boolean
  locked: boolean
  passwordHash: string
  enrollmentTokenTtlMs: number
  githubWebhookSecret: string
  scanEnabled: boolean
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

function loadOrCreateCookieSecret(dataDir: string): string {
  const keyPath = path.join(dataDir, '.cookie_secret')
  try {
    return fs.readFileSync(keyPath, 'utf8').trim()
  } catch {
    const secret = randomBytes(32).toString('hex')
    fs.mkdirSync(dataDir, { recursive: true })
    fs.writeFileSync(keyPath, secret, { mode: 0o600 })
    return secret
  }
}

function loadOrCreateHmacSeed(dataDir: string): Buffer {
  const keyPath = path.join(dataDir, '.hmac_seed')
  try {
    return fs.readFileSync(keyPath)
  } catch {
    const seed = randomBytes(32)
    fs.mkdirSync(dataDir, { recursive: true })
    fs.writeFileSync(keyPath, seed, { mode: 0o600 })
    return seed
  }
}

function detectTailscaleIp(): string | null {
  const nets = networkInterfaces()
  for (const name of Object.keys(nets)) {
    if (!name.toLowerCase().includes('tailscale')) continue
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        const parts = net.address.split('.')
        if (parts[0] === '100' && parseInt(parts[1]) >= 64 && parseInt(parts[1]) <= 127) {
          return net.address
        }
      }
    }
  }
  return null
}

function tailscaleBin(): string {
  if (process.platform === 'win32') {
    const winPath = 'C:\\Program Files\\Tailscale\\tailscale.exe'
    if (fs.existsSync(winPath)) return winPath
  }
  return 'tailscale'
}

function detectTailscaleFunnelUrl(config: { port: number }): { url: string; origin: string; rpId: string } | null {
  try {
    const ts = tailscaleBin()

    // Read MagicDNS name from status
    const statusOut = execSync(`"${ts}" status --json`, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
    const status = JSON.parse(statusOut)
    let dnsName: string = (status.Self?.DNSName || '').replace(/\.$/, '')
    if (!dnsName) return null
    if (dnsName.startsWith('*.')) dnsName = dnsName.slice(2)

    // Try funnel status first, then serve
    let src = 'funnel'
    let raw = execSync(`"${ts}" funnel status --json`, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
    let cfg: any = {}
    try { cfg = JSON.parse(raw) } catch {}

    if (!cfg.Web || Object.keys(cfg.Web).length === 0) {
      src = 'serve'
      raw = execSync(`"${ts}" serve status --json`, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
      try { cfg = JSON.parse(raw) } catch {}
    }

    // Handlers live under Web.<host:port>.Handlers
    const web = cfg.Web || {}
    for (const hostPort of Object.keys(web)) {
      const handlers = web[hostPort]?.Handlers || {}
      for (const handlerPath of Object.keys(handlers)) {
        const proxyTarget = handlers[handlerPath]?.Proxy || ''
        if (proxyTarget.includes(`:${config.port}`)) {
          const pathSuffix = handlerPath === '/' ? '' : handlerPath
          const origin = `https://${dnsName}`
          const url = `${origin}${pathSuffix}`
          return { url, origin, rpId: dnsName }
        }
      }
    }

    return null
  } catch {
    return null
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

  const tailscaleIp = detectTailscaleIp()
  const lanIp = tailscaleIp || detectLanIp()

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
    challengeTtlMs: 120000,
    rateLimitAuth: 5,
    rateLimitWindowMs: 60000,
    encryptionKey: loadOrCreateEncryptionKey(dataDir),
    cookieSecret: process.env.SENTINEL_COOKIE_SECRET || loadOrCreateCookieSecret(dataDir),
    hmacSeed: process.env.SENTINEL_HMAC_SEED ? Buffer.from(process.env.SENTINEL_HMAC_SEED, 'hex') : loadOrCreateHmacSeed(dataDir),
    approveReasonRequired: false,
    locked: false,
    passwordHash: '',
    enrollmentTokenTtlMs: 120000,
    githubWebhookSecret: '',
    scanEnabled: false,
  }

  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, 'utf8')
      const user = JSON.parse(raw)
      const merged = { ...defaults, ...user, encryptionKey: defaults.encryptionKey, cookieSecret: defaults.cookieSecret, hmacSeed: defaults.hmacSeed }

      // Auto-override loopback bindAddress with detected IP
      if (merged.bindAddress === '127.0.0.1' || merged.bindAddress === 'localhost') {
        merged.bindAddress = lanIp
        merged.serverOrigin = `https://${lanIp}:${merged.port}`
        merged.rpId = lanIp
        console.warn(`[config] bindAddress was set to loopback — auto-overridden to ${lanIp}`)
      }

      // Priority: 1) Funnel URL (public HTTPS), 2) Tailscale IP (tailnet-only), 3) LAN IP
      const funnel = detectTailscaleFunnelUrl(merged)
      if (funnel) {
        if (merged.bindAddress !== funnel.rpId) {
          console.warn(`[config] Tailscale Funnel active at ${funnel.url}`)
        }
        merged.bindAddress = funnel.rpId
        merged.serverOrigin = funnel.origin
        merged.rpId = funnel.rpId
      } else if (tailscaleIp && merged.bindAddress !== tailscaleIp) {
        console.warn(`[config] Tailscale detected at ${tailscaleIp} — prefering over ${merged.bindAddress}`)
        merged.bindAddress = tailscaleIp
        merged.serverOrigin = `https://${tailscaleIp}:${merged.port}`
        merged.rpId = tailscaleIp
      }

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

  const funnel = detectTailscaleFunnelUrl(defaults)
  if (funnel) {
    console.log(`[config] Tailscale Funnel active at ${funnel.url}`)
    defaults.bindAddress = funnel.rpId
    defaults.serverOrigin = funnel.origin
    defaults.rpId = funnel.rpId
  } else if (tailscaleIp) {
    console.log(`[config] Tailscale detected at ${tailscaleIp} — using Tailscale IP`)
  }

  console.log(`[config] No config.json found — using defaults. Run with https://${defaults.bindAddress}:${defaults.port}`)
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
    if (!['encryptionKey', 'cookieSecret', 'hmacSeed'].includes(k)) {
      existing[k] = v
    }
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(existing, null, 2), { mode: 0o600 })
}
