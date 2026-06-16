import { createPrivateKey, sign } from 'crypto'
import { readFileSync } from 'fs'
import https from 'https'

export interface GitHubAppConfig {
  appId: string
  installationId: string
  privateKeyPath?: string
}

interface CachedToken {
  token: string
  expiresAt: number
}

const JWT_EXPIRATION_S = 600
const TOKEN_REFRESH_MARGIN_MS = 300000

function base64urlFromBuffer(buf: Buffer): string {
  return buf.toString('base64url')
}

function base64url(str: string): string {
  return Buffer.from(str).toString('base64url')
}

function base64urlNoPad(str: string): string {
  return base64url(str).replace(/=+$/, '')
}

function httpsRequest(method: string, url: string, headers: Record<string, string>, body?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const opts: https.RequestOptions = {
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method,
      headers,
      timeout: 30000,
    }
    const req = https.request(opts, (res) => {
      let data = ''
      res.on('data', (chunk: Buffer) => { data += chunk.toString() })
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data)
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`))
        }
      })
    })
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')) })
    if (body) req.write(body)
    req.end()
  })
}

export interface InstallationTokenData {
  token: string
  expiresAt: string
  permissions: Record<string, string>
  repositorySelection: string
}

export class GitHubAppAuth {
  private appId: string
  private installationId: string
  private privateKeyPem: string
  private cachedToken: CachedToken | null = null

  constructor(config: GitHubAppConfig) {
    if (!config.appId || !config.installationId) {
      throw new Error('GitHub App requires appId and installationId')
    }
    this.appId = config.appId
    this.installationId = config.installationId

    const envKey = process.env.SENTINEL_GITHUB_PRIVATE_KEY
    const envKeyPath = process.env.SENTINEL_GITHUB_PRIVATE_KEY_PATH

    if (envKey) {
      this.privateKeyPem = Buffer.from(envKey, 'base64').toString('utf8')
    } else if (envKeyPath) {
      this.privateKeyPem = readFileSync(envKeyPath, 'utf8')
    } else if (config.privateKeyPath) {
      this.privateKeyPem = readFileSync(config.privateKeyPath, 'utf8')
    } else {
      throw new Error(
        'GitHub App private key not found. Provide via SENTINEL_GITHUB_PRIVATE_KEY env (base64) ' +
        'or SENTINEL_GITHUB_PRIVATE_KEY_PATH env or privateKeyPath in config',
      )
    }

    if (!this.privateKeyPem.includes('BEGIN')) {
      throw new Error('Private key does not appear to be a valid PEM file')
    }
  }

  generateJWT(): string {
    const now = Math.floor(Date.now() / 1000)
    const header = { alg: 'RS256', typ: 'JWT' }
    const payload = { iss: this.appId, iat: now, exp: now + JWT_EXPIRATION_S }

    const headerB64 = base64urlNoPad(JSON.stringify(header))
    const payloadB64 = base64urlNoPad(JSON.stringify(payload))
    const message = `${headerB64}.${payloadB64}`

    const key = createPrivateKey(this.privateKeyPem)
    const sig = sign('RSA-SHA256', Buffer.from(message), key)

    const sigB64 = base64urlFromBuffer(sig).replace(/=+$/, '')

    const jwt = `${message}.${sigB64}`

    const parts = jwt.split('.')
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
      throw new Error('Generated JWT is malformed')
    }

    const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    if (decodedPayload.iss !== this.appId) {
      throw new Error('JWT payload iss does not match appId')
    }
    if (decodedPayload.exp - decodedPayload.iat !== JWT_EXPIRATION_S) {
      throw new Error('JWT expiration time mismatch')
    }

    return jwt
  }

  private async requestInstallationToken(): Promise<InstallationTokenData> {
    const jwt = this.generateJWT()
    const url = `https://api.github.com/app/installations/${this.installationId}/access_tokens`

    let raw: string
    try {
      raw = await httpsRequest('POST', url, {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'sentinel-oracle',
      })
    } catch (err) {
      throw new Error(`Failed to obtain installation token: ${err}`)
    }

    const data = JSON.parse(raw)

    if (!data.token || !data.expires_at) {
      throw new Error(`Installation token response missing token or expires_at: ${raw.slice(0, 200)}`)
    }

    return {
      token: data.token,
      expiresAt: data.expires_at,
      permissions: data.permissions || {},
      repositorySelection: data.repository_selection || 'selected',
    }
  }

  async getInstallationToken(): Promise<string> {
    if (this.cachedToken && Date.now() < this.cachedToken.expiresAt - TOKEN_REFRESH_MARGIN_MS) {
      return this.cachedToken.token
    }

    const data = await this.requestInstallationToken()
    const expiresAtMs = new Date(data.expiresAt).getTime()

    if (isNaN(expiresAtMs)) {
      throw new Error(`Invalid expires_at from GitHub API: ${data.expiresAt}`)
    }

    this.cachedToken = {
      token: data.token,
      expiresAt: expiresAtMs,
    }

    return data.token
  }

  async verifyInstallation(): Promise<boolean> {
    try {
      const jwt = this.generateJWT()
      await httpsRequest('GET', 'https://api.github.com/app', {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'sentinel-oracle',
      })
      return true
    } catch {
      return false
    }
  }

  clearCache(): void {
    this.cachedToken = null
  }

  getCachedTokenData(): { token: string; expiresAt: number } | null {
    return this.cachedToken
  }
}
