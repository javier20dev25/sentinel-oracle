import { runRules, calculateScore, type PRFile, type Finding } from './rules'

export interface ScanResult {
  riskScore: number
  critical: number
  high: number
  medium: number
  low: number
  findings: Finding[]
  scannedAt: number
}

export function scanPRFiles(files: PRFile[], prNumber?: number, owner?: string, repo?: string, sha?: string): ScanResult {
  const findings = runRules(files, prNumber, owner, repo, sha)
  const { score, critical, high, medium, low } = calculateScore(findings)
  return {
    riskScore: score,
    critical,
    high,
    medium,
    low,
    findings,
    scannedAt: Date.now(),
  }
}

export type { Finding, PRFile }
