import { Octokit } from '@octokit/rest'

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

export class GitHubClient {
  private octokit: Octokit
  private _owner: string
  private _repo: string
  private statusContext: string

  constructor(token: string, owner: string, repo: string, statusContext: string) {
    this.octokit = new Octokit({ auth: token })
    this._owner = owner
    this._repo = repo
    this.statusContext = statusContext
  }

  get owner(): string { return this._owner }
  get repo(): string { return this._repo }

  async listOpenPRs(): Promise<PRInfo[]> {
    const { data } = await this.octokit.pulls.list({
      owner: this.owner,
      repo: this.repo,
      state: 'open',
      sort: 'updated',
      direction: 'desc',
    })
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
      const { data } = await this.octokit.repos.getCombinedStatusForRef({
        owner: this.owner,
        repo: this.repo,
        ref: sha,
      })
      return data.statuses.map(s => ({
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
      const { data } = await this.octokit.checks.listForRef({
        owner: this.owner,
        repo: this.repo,
        ref: sha,
      })
      return data.check_runs.map(r => ({
        context: r.name,
        state: r.conclusion || 'pending',
        description: r.output?.title || '',
      }))
    } catch {
      return []
    }
  }

  async setCommitStatus(sha: string, state: 'pending' | 'success' | 'failure', description: string): Promise<void> {
    await this.octokit.repos.createCommitStatus({
      owner: this.owner,
      repo: this.repo,
      sha,
      state,
      context: this.statusContext,
      description,
    })
  }

  async mergePR(prNumber: number, sha: string): Promise<boolean> {
    try {
      const { status } = await this.octokit.pulls.merge({
        owner: this.owner,
        repo: this.repo,
        pull_number: prNumber,
        sha,
        merge_method: 'squash',
      })
      return status === 200
    } catch {
      return false
    }
  }

  async verifyToken(): Promise<boolean> {
    try {
      await this.octokit.users.getAuthenticated()
      return true
    } catch {
      return false
    }
  }
}
