import type { DatabaseStore } from '../storage/database'
import type { GitHubClient } from '../github/client'
import type { AISkill } from './types'

export function createSkills(db: DatabaseStore, client: GitHubClient): Map<string, AISkill> {
  const skills = new Map<string, AISkill>()

  skills.set('get_scan_result', {
    name: 'get_scan_result',
    description: 'Get the latest security scan result for a PR',
    async execute(prNumber: number) {
      const result = db.getLatestScanResult(prNumber)
      if (!result) return { error: 'No scan result found' }
      return {
        riskScore: result.riskScore,
        critical: result.critical,
        high: result.high,
        medium: result.medium,
        low: result.low,
        findings: safeJsonParse(result.findingsJson, []),
      }
    },
  })

  skills.set('get_pr_files', {
    name: 'get_pr_files',
    description: 'Get the list of files changed in a PR',
    async execute(prNumber: number) {
      const files = db.getPRFiles(prNumber)
      if (!files || files.length === 0) return { error: 'No files found' }
      return files.map(f => ({
        filename: f.filename,
        status: f.status,
        additions: f.additions,
        deletions: f.deletions,
      }))
    },
  })

  skills.set('get_pr_history', {
    name: 'get_pr_history',
    description: 'Get the analysis history and scan history for a PR',
    async execute(prNumber: number) {
      const result = db.getLatestAnalysisResult(prNumber)
      const analysis = result ? { priority: result.reviewPriority, impactLevel: result.impactLevel, complexity: result.complexity, analyzedAt: result.analyzedAt } : null
      const scan = db.getLatestScanResult(prNumber)
      return {
        analysis: analysis ? {
          priority: analysis.priority,
          impactLevel: analysis.impactLevel,
          complexity: analysis.complexity,
          analyzedAt: analysis.analyzedAt,
        } : null,
        scan: scan ? {
          riskScore: scan.riskScore,
          scannedAt: scan.scannedAt,
        } : null,
      }
    },
  })

  skills.set('get_security_dna', {
    name: 'get_security_dna',
    description: 'Get the latest Security DNA snapshot for the repository',
    async execute(owner: string, repo: string) {
      const snapshots = db.getCapabilitySnapshots(owner, repo, 30)
      if (snapshots.length === 0) return { error: 'No Security DNA data available' }
      return snapshots.slice(-1)[0]
    },
  })

  skills.set('get_repository_stats', {
    name: 'get_repository_stats',
    description: 'Get repository metadata including default branch and open PR count',
    async execute() {
      const pending = db.getPendingPRs()
      const config = db.getConfig('githubOwner')
      return {
        openPRs: pending.length,
      }
    },
  })

  return skills
}

function safeJsonParse(json: string, fallback: unknown): unknown {
  try { return JSON.parse(json) } catch { return fallback }
}
