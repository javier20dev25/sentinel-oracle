import { execSync } from 'child_process'
import { writeFileSync, unlinkSync, mkdtempSync, rmSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { GitHubAppAuth, type GitHubAppConfig } from './auth'

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
  tokenType: 'classic' | 'fine-grained' | 'github_app' | 'unknown'
  scopes: string[]
  url: string
  tokenPrefix: string
  riskScore: 'low' | 'medium' | 'high'
  riskReasons: string[]
}

export interface BranchProtection {
  enabled: boolean
  requiredStatusChecks: string[]
  requiredReviews: boolean
  dismissStaleReviews: boolean
  restrictPushes: boolean
  allowsDeletions: boolean
  allowsForcePushes: boolean
  requireLastPushApproval: boolean
  requiredStatusCheckEnforcementLevel: string
  adminEnforced: boolean
}

type AuthMode = 'pat' | 'github_app'

export class GitHubClient {
  private _owner: string
  private _repo: string
  private statusContext: string
  private mode: AuthMode
  private patToken: string
  private appAuth: GitHubAppAuth | null = null

  constructor(tokenOrConfig: string | GitHubAppConfig, owner: string, repo: string, statusContext: string) {
    this._owner = owner
    this._repo = repo
    this.statusContext = statusContext

    if (typeof tokenOrConfig === 'string') {
      this.mode = 'pat'
      this.patToken = tokenOrConfig
    } else {
      this.mode = 'github_app'
      this.patToken = ''
      this.appAuth = new GitHubAppAuth(tokenOrConfig)
    }
  }

  get owner(): string { return this._owner }
  get repo(): string { return this._repo }
  get authMode(): AuthMode { return this.mode }
  get appAuthInstance(): GitHubAppAuth | null { return this.appAuth }

  private async resolveToken(): Promise<string> {
    if (this.mode === 'pat') {
      return this.patToken
    }
    return this.appAuth!.getInstallationToken()
  }

  private async api(method: string, path: string, body?: object): Promise<string> {
    return (await this.apiWithHeaders(method, path, body)).body
  }

  private async apiWithHeaders(method: string, pathOrUrl: string, body?: object): Promise<{ body: string; headers: Record<string, string> }> {
    const token = await this.resolveToken()
    const tmpDir = mkdtempSync(join(tmpdir(), 'gh-'))
    const outFile = join(tmpDir, 'out.json')
    const headerFile = join(tmpDir, 'headers.txt')
    let bodyFile = ''
    try {
      const isFullUrl = pathOrUrl.startsWith('https://')
      const url = isFullUrl ? pathOrUrl : `https://api.github.com${pathOrUrl}`

      let cmd = `curl.exe -sS --connect-timeout 15 --max-time 30 -X ${method}`
      cmd += ` -H "Authorization: Bearer ${token}"`
      cmd += ` -H "Accept: application/vnd.github+json"`
      cmd += ` -H "User-Agent: sentinel-oracle"`
      if (body) {
        bodyFile = join(tmpDir, 'body.json')
        writeFileSync(bodyFile, JSON.stringify(body), 'utf8')
        cmd += ` -d @${bodyFile}`
      }
      cmd += ` -D "${headerFile}"`
      cmd += ` -o "${outFile}" -w "%{http_code}"`
      cmd += ` "${url}"`

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

  async listOpenPRs(): Promise<PRInfo[]> {
    const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/pulls?state=open&sort=updated&direction=desc`)
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

  async getCombinedStatus(sha: string): Promise<CheckStatus[]> {
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/commits/${sha}/status`)
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

  async getCheckRuns(sha: string): Promise<CheckStatus[]> {
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/commits/${sha}/check-runs`)
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

  async getCheckRunDetails(sha: string): Promise<any[]> {
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/commits/${sha}/check-runs`)
      const data = JSON.parse(out)
      return (data.check_runs || []).map((r: any) => ({
        name: r.name,
        conclusion: r.conclusion || 'pending',
        status: r.status,
        startedAt: r.started_at,
        completedAt: r.completed_at,
        durationMs: r.started_at && r.completed_at
          ? new Date(r.completed_at).getTime() - new Date(r.started_at).getTime()
          : null,
        detailsUrl: r.details_url,
        title: r.output?.title || '',
        summary: r.output?.summary || '',
        annotationsCount: r.output?.annotations_count || 0,
      }))
    } catch {
      return []
    }
  }

  async setCommitStatus(sha: string, state: 'pending' | 'success' | 'failure', description: string): Promise<void> {
    await this.api('POST', `/repos/${this.owner}/${this.repo}/statuses/${sha}`,
      { state, context: this.statusContext, description },
    )
  }

  async mergePR(prNumber: number, sha: string): Promise<boolean> {
    try {
      const out = await this.api('PUT', `/repos/${this.owner}/${this.repo}/pulls/${prNumber}/merge`,
        { sha, merge_method: 'squash' },
      )
      const data = JSON.parse(out)
      return data.merged === true
    } catch {
      return false
    }
  }

  async verifyToken(): Promise<boolean> {
    try {
      if (this.mode === 'github_app') {
        return this.appAuth!.verifyInstallation()
      }
      await this.api('GET', '/user')
      return true
    } catch {
      return false
    }
  }

  async getTokenInfo(): Promise<TokenInfo> {
    if (this.mode === 'github_app') {
      return {
        login: `sentinel-oracle[bot]`,
        name: `GitHub App (${this.appAuth!['appId']})`,
        avatarUrl: '',
        tokenType: 'github_app',
        scopes: [],
        url: '',
        tokenPrefix: 'gh-installation-',
        riskScore: 'low',
        riskReasons: ['GitHub App installation token — scoped to repository, auto-refreshing'],
      }
    }

    const result = await this.apiWithHeaders('GET', '/user')
    const data = JSON.parse(result.body)

    const scopesHeader = result.headers['x-oauth-scopes'] || ''
    const scopes = scopesHeader ? scopesHeader.split(',').map((s: string) => s.trim()).filter(Boolean) : []

    const tokenPrefix = this.patToken.length > 10 ? this.patToken.slice(0, 8) + '...' : 'unknown'
    const tokenType: 'classic' | 'fine-grained' | 'unknown' = scopes.length > 0 ? 'classic' : this.patToken.startsWith('github_pat_') ? 'fine-grained' : 'unknown'

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

  async getBranchProtection(branch: string = 'main'): Promise<BranchProtection> {
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/branches/${branch}/protection`)
      const data = JSON.parse(out)

      const requiredStatusChecks = data.required_status_checks?.contexts || []
      const enforcementLevel = data.required_status_checks?.enforcement_level || 'off'

      return {
        enabled: true,
        requiredStatusChecks,
        requiredReviews: !!data.required_pull_request_reviews,
        dismissStaleReviews: !!data.required_pull_request_reviews?.dismiss_stale_reviews,
        restrictPushes: !!data.restrict_pushes,
        allowsDeletions: !!data.allows_deletions,
        allowsForcePushes: !!data.allows_force_pushes,
        requireLastPushApproval: !!data.required_pull_request_reviews?.require_last_push_approval,
        requiredStatusCheckEnforcementLevel: enforcementLevel,
        adminEnforced: !!data.enforce_admins?.enabled,
      }
    } catch (err) {
      const msg = String(err)
      if (msg.includes('404') || msg.includes('Branch not protected')) {
        return {
          enabled: false,
          requiredStatusChecks: [],
          requiredReviews: false,
          dismissStaleReviews: false,
          restrictPushes: false,
          allowsDeletions: true,
          allowsForcePushes: true,
          requireLastPushApproval: false,
          requiredStatusCheckEnforcementLevel: 'off',
          adminEnforced: false,
        }
      }
      throw err
    }
  }

  async listCheckSuitesForRef(sha: string): Promise<any[]> {
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/commits/${sha}/check-suites`)
      const data = JSON.parse(out)
      return data.check_suites || []
    } catch {
      return []
    }
  }

  async getPullRequest(prNumber: number): Promise<any> {
    const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/pulls/${prNumber}`)
    return JSON.parse(out)
  }

  async compareCommits(baseSha: string, headSha: string): Promise<any> {
    const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/compare/${baseSha}...${headSha}`)
    return JSON.parse(out)
  }
}
