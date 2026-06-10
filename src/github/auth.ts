import { createPrivateKey, sign } from 'crypto'
import { execSync } from 'child_process'
import { readFileSync, mkdtempSync, writeFileSync, unlinkSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

export interface GitHubAppConfig {
  appId: string
  installationId: string
  privateKeyPath: string
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

function execCurl(method: string, url: string, bearerToken: string, body?: object): string {
  const tmpDir = mkdtempSync(join(tmpdir(), 'gh-auth-'))
  const outFile = join(tmpDir, 'out.json')
  try {
    let cmd = `curl.exe -sS --connect-timeout 15 --max-time 30 -X ${method}`
    cmd += ` -H "Authorization: Bearer ${bearerToken}"`
    cmd += ` -H "Accept: application/vnd.github+json"`
    cmd += ` -H "User-Agent: sentinel-oracle"`
    if (body) {
      const bodyFile = join(tmpDir, 'body.json')
      writeFileSync(bodyFile, JSON.stringify(body), 'utf8')
      cmd += ` -d @${bodyFile}`
    }
    cmd += ` -o "${outFile}" -w "%{http_code}"`
    cmd += ` "${url}"`

      const code = execSync(cmd, { shell: true, timeout: 35000 } as any).toString().trim()
    const out = readFileSync(outFile, 'utf8')

    if (code.startsWith('2')) return out
    throw new Error(`GitHub API ${code}: ${out}`)
  } finally {
    try { unlinkSync(outFile) } catch {}
    try { rmSync(tmpDir, { recursive: true, force: true }) } catch {}
  }
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
    if (!config.appId || !config.installationId || !config.privateKeyPath) {
      throw new Error('GitHub App requires appId, installationId, and privateKeyPath')
    }
    this.appId = config.appId
    this.installationId = config.installationId
    this.privateKeyPem = readFileSync(config.privateKeyPath, 'utf8')

    if (!this.privateKeyPem.includes('BEGIN')) {
      throw new Error(`Private key at ${config.privateKeyPath} does not appear to be a valid PEM file`)
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
      raw = execCurl('POST', url, jwt)
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

  verifyInstallation(): boolean {
    try {
      const jwt = this.generateJWT()
      execCurl('GET', 'https://api.github.com/app', jwt)
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
