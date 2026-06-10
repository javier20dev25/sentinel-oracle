import { execSync } from 'child_process'
import { writeFileSync, unlinkSync, mkdtempSync, rmSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

export interface PRInfo {
  number: number
  title: string
  author: string
  sha: string
  state: string
  createdAt: string
}

export interface CheckStatus {
  context: string
  state: string
  description: string
}

export interface TokenInfo {
  login: string
  name: string
  avatarUrl: string
  tokenType: 'classic' | 'fine-grained' | 'unknown'
  scopes: string[]
  url: string
  tokenPrefix: string
  riskScore: 'low' | 'medium' | 'high'
  riskReasons: string[]
}

export class GitHubClient {
  private token: string
  private _owner: string
  private _repo: string
  private statusContext: string

  constructor(token: string, owner: string, repo: string, statusContext: string) {
    this.token = token
    this._owner = owner
    this._repo = repo
    this.statusContext = statusContext
  }

  get owner(): string { return this._owner }
  get repo(): string { return this._repo }

  private api(method: string, path: string, body?: object): string {
    return this.apiWithHeaders(method, path, body).body
  }

  private apiWithHeaders(method: string, path: string, body?: object): { body: string; headers: Record<string, string> } {
    const tmpDir = mkdtempSync(join(tmpdir(), 'gh-'))
    const outFile = join(tmpDir, 'out.json')
    const headerFile = join(tmpDir, 'headers.txt')
    let bodyFile = ''
    try {
      let cmd = `curl.exe -sS --connect-timeout 15 --max-time 30 -X ${method}`
      cmd += ` -H "Authorization: Bearer ${this.token}"`
      cmd += ` -H "Accept: application/vnd.github+json"`
      cmd += ` -H "User-Agent: sentinel-oracle"`
      if (body) {
        bodyFile = join(tmpDir, 'body.json')
        writeFileSync(bodyFile, JSON.stringify(body), 'utf8')
        cmd += ` -d @${bodyFile}`
      }
      cmd += ` -D "${headerFile}"`
      cmd += ` -o "${outFile}" -w "%{http_code}"`
      cmd += ` "https://api.github.com${path}"`

      const code = execSync(cmd, { shell: true, timeout: 35000 } as any).toString().trim()
      const out = readFileSync(outFile, 'utf8')

      const headers: Record<string, string> = {}
      try {
        const hdr = readFileSync(headerFile, 'utf8')
        for (const line of hdr.split('\n')) {
          const m = line.match(/^([^:]+):\s*(.+)\r?$/)
          if (m) headers[m[1].toLowerCase()] = m[2].trim()
        }
      } catch {}

      if (code.startsWith('2')) return { body: out, headers }
      throw new Error(`GitHub API ${code}: ${out}`)
    } finally {
      try { unlinkSync(outFile) } catch {}
      try { unlinkSync(headerFile) } catch {}
      if (bodyFile) { try { unlinkSync(bodyFile) } catch {} }
      try { rmSync(tmpDir, { recursive: true, force: true }) } catch {}
    }
  }

  listOpenPRs(): PRInfo[] {
    const out = this.api('GET', `/repos/${this.owner}/${this.repo}/pulls?state=open&sort=updated&direction=desc`)
    const data: any[] = JSON.parse(out)
    return data.map(pr => ({
      number: pr.number,
      title: pr.title,
      author: pr.user?.login || 'unknown',
      sha: pr.head.sha,
      state: pr.state,
      createdAt: pr.created_at,
    }))
  }

  getCombinedStatus(sha: string): CheckStatus[] {
    try {
      const out = this.api('GET', `/repos/${this.owner}/${this.repo}/commits/${sha}/status`)
      const data = JSON.parse(out)
      return (data.statuses || []).map((s: any) => ({
        context: s.context,
        state: s.state,
        description: s.description || '',
      }))
    } catch {
      return []
    }
  }

  getCheckRuns(sha: string): CheckStatus[] {
    try {
      const out = this.api('GET', `/repos/${this.owner}/${this.repo}/commits/${sha}/check-runs`)
      const data = JSON.parse(out)
      return (data.check_runs || []).map((r: any) => ({
        context: r.name,
        state: r.conclusion || 'pending',
        description: r.output?.title || '',
      }))
    } catch {
      return []
    }
  }

  setCommitStatus(sha: string, state: 'pending' | 'success' | 'failure', description: string): void {
    this.api('POST', `/repos/${this.owner}/${this.repo}/statuses/${sha}`,
      { state, context: this.statusContext, description },
    )
  }

  mergePR(prNumber: number, sha: string): boolean {
    try {
      const out = this.api('PUT', `/repos/${this.owner}/${this.repo}/pulls/${prNumber}/merge`,
        { sha, merge_method: 'squash' },
      )
      const data = JSON.parse(out)
      return data.merged === true
    } catch {
      return false
    }
  }

  verifyToken(): boolean {
    try {
      this.api('GET', '/user')
      return true
    } catch {
      return false
    }
  }

  getTokenInfo(): TokenInfo {
    const result = this.apiWithHeaders('GET', '/user')
    const data = JSON.parse(result.body)

    const scopesHeader = result.headers['x-oauth-scopes'] || ''
    const scopes = scopesHeader ? scopesHeader.split(',').map((s: string) => s.trim()).filter(Boolean) : []

    const tokenPrefix = this.token.length > 10 ? this.token.slice(0, 8) + '...' : 'unknown'
    const tokenType: 'classic' | 'fine-grained' | 'unknown' = scopes.length > 0 ? 'classic' : this.token.startsWith('github_pat_') ? 'fine-grained' : 'unknown'

    const riskReasons: string[] = []
    if (scopes.includes('admin:org')) riskReasons.push('Organization admin access')
    if (scopes.includes('repo')) riskReasons.push('Full repository access (all repos)')
    if (scopes.includes('delete_repo')) riskReasons.push('Can delete repositories')
    if (scopes.includes('workflow')) riskReasons.push('Can modify GitHub Actions workflows')
    if (scopes.includes('admin:repo_hook')) riskReasons.push('Can manage webhooks')
    if (scopes.includes('write:org')) riskReasons.push('Organization write access')
    if (scopes.includes('user')) riskReasons.push('Can read/write user profile data')
    if (tokenType === 'classic') riskReasons.push('Classic PAT — broad scopes, no repo-level granularity')

    const riskScore: 'low' | 'medium' | 'high' = riskReasons.length === 0 ? 'low' : riskReasons.some(r => r.includes('admin') || r.includes('Full') || r.includes('delete') || r.includes('Actions')) ? 'high' : 'medium'

    return {
      login: data.login,
      name: data.name || data.login,
      avatarUrl: data.avatar_url,
      tokenType,
      scopes,
      url: data.html_url,
      tokenPrefix,
      riskScore,
      riskReasons,
    }
  }
}
