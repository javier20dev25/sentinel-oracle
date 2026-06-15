import https from 'https'
import { GitHubAppAuth, type GitHubAppConfig } from './auth'

export interface PRInfo {
  number: number
  title: string
  author: string
  sha: string
  state: string
  createdAt: string
}

export interface PRFile {
  filename: string
  status: string
  additions: number
  deletions: number
  patch?: string
  contents_url: string
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
    const isFullUrl = pathOrUrl.startsWith('https://')
    const url = isFullUrl ? pathOrUrl : `https://api.github.com${pathOrUrl}`

    const reqHeaders: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'sentinel-oracle',
    }

    const maxRetries = 3
    let lastErr: Error | null = null
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 8000)
        await new Promise(r => setTimeout(r, delay))
      }
      try {
        return await this._request(url, method, reqHeaders, body)
      } catch (err: any) {
        lastErr = err
        if (err.message && (err.message.includes('ENOTFOUND') || err.message.includes('ETIMEDOUT') || err.message.includes('ECONNRESET'))) {
          continue
        }
        throw err
      }
    }
    throw lastErr || new Error('Request failed after retries')
  }

  private _request(url: string, method: string, headers: Record<string, string>, body?: object): Promise<{ body: string; headers: Record<string, string> }> {
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
          const respHeaders: Record<string, string> = {}
          for (const [key, val] of Object.entries(res.headers)) {
            if (val) respHeaders[key] = Array.isArray(val) ? val.join(', ') : val
          }
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ body: data, headers: respHeaders })
          } else {
            reject(new Error(`GitHub API ${res.statusCode}: ${data}`))
          }
        })
      })
      req.on('error', reject)
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')) })
      if (body) req.write(JSON.stringify(body))
      req.end()
    })
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

  async createCheckRun(prNumber: number, sha: string, conclusion: string, summary: string, annotations?: { path: string; start_line: number; end_line: number; annotation_level: string; message: string; title?: string }[]): Promise<any> {
    try {
      const name = this.statusContext || 'Sentinel Oracle'
      const status = 'completed'
      const output: any = {
        title: `Sentinel Oracle — ${conclusion.toUpperCase()}`,
        summary,
        text: `PR #${prNumber} — ${conclusion === 'success' ? 'Authorized' : conclusion === 'failure' ? 'Blocked' : 'Action required'}`,
      }
      if (annotations && annotations.length > 0) {
        output.annotations = annotations
      }
      const out = await this.api('POST', `/repos/${this.owner}/${this.repo}/check-runs`, {
        name,
        head_sha: sha,
        status,
        conclusion,
        output,
      })
      return JSON.parse(out)
    } catch (err) {
      const msg = String(err)
      console.error('[check-run] create failed:', msg)
      return null
    }
  }

  async updateCheckRun(checkRunId: number, conclusion: string, summary: string, annotations?: { path: string; start_line: number; end_line: number; annotation_level: string; message: string; title?: string }[]): Promise<any> {
    try {
      const status = 'completed'
      const output: any = {
        title: `Sentinel Oracle — ${conclusion.toUpperCase()}`,
        summary,
      }
      if (annotations && annotations.length > 0) {
        output.annotations = annotations
      }
      const out = await this.api('PATCH', `/repos/${this.owner}/${this.repo}/check-runs/${checkRunId}`, {
        status,
        conclusion,
        output,
      })
      return JSON.parse(out)
    } catch (err) {
      const msg = String(err)
      console.error('[check-run] update failed:', msg)
      return null
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

  async getPRFiles(prNumber: number): Promise<PRFile[]> {
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/pulls/${prNumber}/files?per_page=100`)
      const data: any[] = JSON.parse(out)
      return data.map(f => ({
        filename: f.filename,
        status: f.status,
        additions: f.additions,
        deletions: f.deletions,
        patch: f.patch || '',
        contents_url: f.contents_url,
      }))
    } catch {
      return []
    }
  }

  async compareCommits(baseSha: string, headSha: string): Promise<any> {
    const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/compare/${baseSha}...${headSha}`)
    return JSON.parse(out)
  }

  async listAllPRs(state: 'closed' | 'all' = 'closed', perPage = 100): Promise<any[]> {
    const allPRs: any[] = []
    let page = 1
    while (true) {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/pulls?state=${state}&per_page=${perPage}&page=${page}&sort=created&direction=asc`)
      const batch: any[] = JSON.parse(out)
      if (batch.length === 0) break
      allPRs.push(...batch)
      page++
    }
    return allPRs
  }

  // Get workflow run durations for all commits that modified a file on main
  async getWorkflowDurationsForFile(filename: string): Promise<{ sha: string; checkName: string; durationMs: number }[]> {
    const results: { sha: string; checkName: string; durationMs: number }[] = []
    try {
      const out = await this.api('GET', `/repos/${this.owner}/${this.repo}/commits?sha=main&path=${encodeURIComponent(filename)}&per_page=50`)
      const commits: any[] = JSON.parse(out)
      for (const c of commits) {
        const sha = c.sha
        const checks = await this.getCheckRunDetails(sha)
        for (const chk of checks) {
          if (chk.durationMs != null && chk.conclusion === 'success') {
            results.push({ sha, checkName: chk.name, durationMs: chk.durationMs })
          }
        }
      }
    } catch (err) {
      console.error(`getWorkflowDurations failed for ${filename}:`, err)
    }
    return results
  }
}
