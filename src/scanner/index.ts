import { runRules, calculateScore, type PRFile, type Finding } from './rules'
import { runIntelAnalysis, type IntelReport } from './intel/index'
import { analyzeBuildIntelligence, type BuildIntelligence } from './build-intel'

export interface ScanResult {
  riskScore: number
  critical: number
  high: number
  medium: number
  low: number
  findings: Finding[]
  scannedAt: number
  intel?: IntelReport
  buildIntel?: BuildIntelligence
}

export async function scanPRFiles(files: PRFile[], prNumber?: number, owner?: string, repo?: string, sha?: string): Promise<ScanResult> {
  const findings = runRules(files, prNumber, owner, repo, sha)
  const { score, critical, high, medium, low } = calculateScore(findings)
  const intel = await runIntelAnalysis(files)
  const buildIntel = analyzeBuildIntelligence(files)
  return {
    riskScore: score,
    critical,
    high,
    medium,
    low,
    findings,
    scannedAt: Date.now(),
    intel: Object.keys(intel).length > 0 ? intel : undefined,
    buildIntel,
  }
}

export type { Finding, PRFile }
