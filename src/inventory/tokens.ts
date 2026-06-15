import crypto from 'crypto'
import type { GitHubClient } from '../github/client'
import type { DatabaseStore, TokenInventory } from '../storage/database'

export interface TokenScanResult {
  tokenType: TokenInventory['tokenType']
  name: string
  source: TokenInventory['source']
  scopes: string | null
  fingerprint: string
  expiresAt: number | null
  riskScore: string
  notes: string | null
  metadata: string | null
}

export interface ScanResult {
  tokensFound: number
  tokensUpdated: number
  tokens: TokenScanResult[]
  scannedAt: number
}

export interface DriftResult {
  fingerprint: string
  name: string
  storedScopes: string[]
  currentScopes: string[]
  hasDrifted: boolean
  riskIncreased: boolean
}

const SECRET_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /ghp_[a-zA-Z0-9]{36}/g, label: 'GitHub classic PAT' },
  { regex: /github_pat_[a-zA-Z0-9]{22,}/g, label: 'GitHub fine-grained PAT' },
  { regex: /gho_[a-zA-Z0-9]{36}/g, label: 'GitHub OAuth access token' },
  { regex: /ghu_[a-zA-Z0-9]{36}/g, label: 'GitHub user-to-server token' },
  { regex: /ghs_[a-zA-Z0-9]{36}/g, label: 'GitHub server-to-server token' },
  { regex: /ghr_[a-zA-Z0-9]{36}/g, label: 'GitHub refresh token' },
  { regex: /AIza[0-9A-Za-z_-]{35}/g, label: 'Google API key' },
  { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key ID' },
  { regex: /sk-[a-zA-Z0-9]{32,}/g, label: 'OpenAI API key' },
  { regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, label: 'Private key' },
]

function fingerprintToken(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex')
}

export class TokenInventoryScanner {
  constructor(private client: GitHubClient, private db: DatabaseStore) {}

  async scanGitHubTokens(): Promise<ScanResult> {
    const result: ScanResult = { tokensFound: 0, tokensUpdated: 0, tokens: [], scannedAt: Date.now() }

    try {
      const tokenInfo = await this.client.getTokenInfo()
      const rawPrefix = tokenInfo.tokenPrefix.replace(/\.\.\.$/, '')
      const fp = fingerprintToken(rawPrefix + tokenInfo.login)

      const existing = this.db.getTokenByFingerprint(fp)
      if (existing) {
        this.db.updateTokenSeen(fp)
        this.db.updateTokenRisk(fp, tokenInfo.riskScore)
        result.tokensUpdated++
      } else {
        this.db.addToken({
          tokenType: tokenInfo.tokenType === 'github_app' ? 'github_app' : 'github_pat',
          name: tokenInfo.name || tokenInfo.login,
          source: 'github_api',
          scopes: JSON.stringify(tokenInfo.scopes),
          fingerprint: fp,
          firstSeenAt: Date.now(),
          lastSeenAt: Date.now(),
          expiresAt: null,
          lastRotation: null,
          riskScore: tokenInfo.riskScore,
          notes: tokenInfo.riskReasons.join('; '),
          metadata: JSON.stringify({ login: tokenInfo.login, avatarUrl: tokenInfo.avatarUrl }),
        })
        result.tokensFound++
      }

      result.tokens.push({
        tokenType: 'github_pat',
        name: tokenInfo.name || tokenInfo.login,
        source: 'github_api',
        scopes: JSON.stringify(tokenInfo.scopes),
        fingerprint: fp,
        expiresAt: null,
        riskScore: tokenInfo.riskScore,
        notes: null,
        metadata: null,
      })
    } catch {}

    if (this.client.authMode === 'github_app' && this.client.appAuthInstance) {
      try {
        const token = await this.client.appAuthInstance.getInstallationToken()
        const fp = fingerprintToken('gh-installation-' + token.slice(0, 16))
        const existing = this.db.getTokenByFingerprint(fp)
        if (existing) {
          this.db.updateTokenSeen(fp)
          result.tokensUpdated++
        } else {
          this.db.addToken({
            tokenType: 'github_app',
            name: 'GitHub App Installation',
            source: 'github_api',
            scopes: null,
            fingerprint: fp,
            firstSeenAt: Date.now(),
            lastSeenAt: Date.now(),
            expiresAt: null,
            lastRotation: null,
            riskScore: 'low',
            notes: 'GitHub App installation token — auto-refreshing',
            metadata: JSON.stringify({ appAuth: true }),
          })
          result.tokensFound++
        }
      } catch {}
    }

    return result
  }

  async scanRepoForSecrets(): Promise<ScanResult> {
    const result: ScanResult = { tokensFound: 0, tokensUpdated: 0, tokens: [], scannedAt: Date.now() }

    try {
      const prs = await this.client.listOpenPRs()
      const mergedPrs = prs.filter(p => p.state === 'closed')

      for (const pr of prs) {
        try {
          const files = await this.client.getPRFiles(pr.number)
          for (const file of files) {
            const patch = file.patch || ''
            for (const { regex, label } of SECRET_PATTERNS) {
              regex.lastIndex = 0
              const match = regex.exec(patch)
              if (match) {
                const fp = fingerprintToken(match[0])
                const existing = this.db.getTokenByFingerprint(fp)
                if (existing) {
                  this.db.updateTokenSeen(fp)
                  result.tokensUpdated++
                } else {
                  this.db.addToken({
                    tokenType: 'found_secret',
                    name: label,
                    source: 'repo_scan',
                    scopes: null,
                    fingerprint: fp,
                    firstSeenAt: Date.now(),
                    lastSeenAt: Date.now(),
                    expiresAt: null,
                    lastRotation: null,
                    riskScore: 'high',
                    notes: `Found in PR #${pr.number} — ${file.filename}`,
                    metadata: JSON.stringify({ prNumber: pr.number, file: file.filename }),
                  })
                  result.tokensFound++
                }

                result.tokens.push({
                  tokenType: 'found_secret',
                  name: label,
                  source: 'repo_scan',
                  scopes: null,
                  fingerprint: fp,
                  expiresAt: null,
                  riskScore: 'high',
                  notes: `Found in PR #${pr.number} — ${file.filename}`,
                  metadata: JSON.stringify({ prNumber: pr.number, file: file.filename }),
                })
              }
            }
          }
        } catch {}
      }
    } catch {}

    return result
  }

  async fullScan(): Promise<ScanResult> {
    const apiResult = await this.scanGitHubTokens()
    const repoResult = await this.scanRepoForSecrets()

    return {
      tokensFound: apiResult.tokensFound + repoResult.tokensFound,
      tokensUpdated: apiResult.tokensUpdated + repoResult.tokensUpdated,
      tokens: [...apiResult.tokens, ...repoResult.tokens],
      scannedAt: Date.now(),
    }
  }

  async detectDrift(): Promise<DriftResult[]> {
    const results: DriftResult[] = []
    const tokens = this.db.getAllTokens()

    for (const token of tokens) {
      if (token.tokenType === 'found_secret' || token.tokenType === 'generic') continue

      let currentScopes: string[] = []
      try {
        const info = await this.client.getTokenInfo()
        if (token.tokenType === 'github_app') {
          continue
        }
        currentScopes = info.scopes
      } catch {
        continue
      }

      let storedScopes: string[] = []
      if (token.scopes) {
        try {
          storedScopes = JSON.parse(token.scopes)
        } catch {
          storedScopes = []
        }
      }

      const storedSet = new Set(storedScopes)
      const currentSet = new Set(currentScopes)
      const hasDrifted =
        storedScopes.length !== currentScopes.length ||
        storedScopes.some(s => !currentSet.has(s)) ||
        currentScopes.some(s => !storedSet.has(s))

      const riskIncreased = currentScopes.some(s =>
        ['admin:org', 'repo', 'delete_repo', 'workflow', 'admin:repo_hook'].includes(s)
      ) && !storedScopes.some(s =>
        ['admin:org', 'repo', 'delete_repo', 'workflow', 'admin:repo_hook'].includes(s)
      )

      if (hasDrifted) {
        results.push({
          fingerprint: token.fingerprint,
          name: token.name,
          storedScopes,
          currentScopes,
          hasDrifted,
          riskIncreased,
        })
      }
    }

    return results
  }
}
