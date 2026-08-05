import { runRules, calculateScore, nextFindingId, resetFindingCounter, type PRFile, type Finding } from './rules'
import { runIntelAnalysis, type IntelReport } from './intel/index'
import { analyzeBuildIntelligence, type BuildIntelligence } from './build-intel'
import { determineScanVerdict, type ScanState } from './verdict'
import { signScanAttestation, type ScanAttestation } from '../crypto/attestation'

export interface ScanResult {
  riskScore: number
  critical: number
  high: number
  medium: number
  low: number
  findings: Finding[]
  state: ScanState
  stateReasons: string[]
  attestation: ScanAttestation
  scannedAt: number
  intel?: IntelReport
  buildIntel?: BuildIntelligence
}

export async function scanPRFiles(files: PRFile[], prNumber?: number, owner?: string, repo?: string, sha?: string, scanHash?: string): Promise<ScanResult> {
  const findings = runRules(files, prNumber, owner, repo, sha)
  const intel = await runIntelAnalysis(files)
  const buildIntel = analyzeBuildIntelligence(files)

  // Fold tarball-scan findings into the signed result: they change the counts,
  // risk score and verdict, so the attestation covers them.
  const tarballFindings = intel?.dependencyTarballFindings ?? []
  if (tarballFindings.length > 0) {
    resetFindingCounter()
    for (const f of tarballFindings) f.findingId = nextFindingId(f.severity)
    findings.push(...tarballFindings)
  }

  const { score, critical, high, medium, low } = calculateScore(findings)
  const { state, reasons } = determineScanVerdict(findings, intel, buildIntel)
  const scannedAt = Date.now()
  const attestation = signScanAttestation({
    prNumber: prNumber ?? 0,
    scanHash: scanHash ?? '',
    riskScore: score,
    state,
    critical,
    high,
    medium,
    low,
    scannedAt,
  })
  return {
    riskScore: score,
    critical,
    high,
    medium,
    low,
    findings,
    state,
    stateReasons: reasons,
    attestation,
    scannedAt,
    intel: Object.keys(intel).length > 0 ? intel : undefined,
    buildIntel,
  }
}

export type { Finding, PRFile }
