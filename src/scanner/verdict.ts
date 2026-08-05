import type { Finding } from './rules'
import type { IntelReport } from './intel/types'
import type { BuildIntelligence } from './build-intel'

export type ScanState = 'PASS' | 'REVIEW' | 'BLOCK'

export interface ScanVerdict {
  state: ScanState
  reasons: string[]
}

const SEVERITY_RANK: Record<Finding['severity'], number> = { low: 1, medium: 2, high: 3, critical: 4 }

/**
 * Maps a PR's evidence to a merge-gate state.
 *
 * BLOCK  — evidence strongly indicates compromise (critical findings, critical intel).
 * REVIEW — evidence is insufficient to declare the PR safe. The ChainDrop/Shai-Hulud
 *          class of attacks ships a malicious tarball behind a one-line manifest diff;
 *          a dependency change is therefore never enough to PASS — the Oracle only sees
 *          the manifest line, never the package contents.
 * PASS   — no findings and no dependency/CI/build drift.
 */
export function determineScanVerdict(findings: Finding[], intel?: IntelReport, buildIntel?: BuildIntelligence): ScanVerdict {
  const reasons: string[] = []
  let maxFindingSev: Finding['severity'] | null = null

  for (const f of findings) {
    if (!maxFindingSev || SEVERITY_RANK[f.severity] > SEVERITY_RANK[maxFindingSev]) maxFindingSev = f.severity
    if (f.severity === 'critical') reasons.push(`Critical finding: ${f.title}`)
    else if (f.severity === 'high') reasons.push(`High-severity finding: ${f.title}`)
    if (f.category === 'dependency' && f.title.toLowerCase().includes('binary')) {
      reasons.push(`Binary artifact added (${f.file}) — content not analyzable from the diff`)
    }
  }

  const deps = intel?.dependencies
  if (deps) {
    for (const d of deps.added.slice(0, 10)) {
      reasons.push(`Dependency added — manifest line only, package content not independently verified: ${d.name}@${d.version}`)
    }
    for (const d of deps.updated.slice(0, 10)) {
      reasons.push(`Dependency updated: ${d.name} ${d.fromVersion} → ${d.toVersion}`)
    }
    for (const s of deps.riskSignals) {
      reasons.push(`Dependency risk signal (${s.package}): ${s.signal}`)
    }
  }

  for (const m of intel?.securityDelta?.modules || []) {
    if (m.risk === 'critical') reasons.push(`Critical intelligence: ${m.name}`)
    else if (m.risk === 'high') reasons.push(`High-risk intelligence: ${m.name}`)
    else if (m.risk === 'medium') reasons.push(`Medium-risk intelligence: ${m.name}`)
  }

  if (intel?.trustDrift?.risk === 'critical') reasons.push('Critical trust drift detected (org access, runners, secrets)')
  else if (intel?.trustDrift?.risk === 'high') reasons.push('Trust drift detected (org access, runners, secrets)')

  if (buildIntel && buildIntel.verdict !== 'CLEAN') {
    reasons.push(`Build intelligence verdict: ${buildIntel.verdict} (trust ${buildIntel.trustScore}/100)`)
  }

  if (reasons.length === 0) return { state: 'PASS', reasons: [] }

  const hasBlock = maxFindingSev === 'critical' ||
    (intel?.securityDelta?.modules || []).some(m => m.risk === 'critical') ||
    intel?.trustDrift?.risk === 'critical'

  return { state: hasBlock ? 'BLOCK' : 'REVIEW', reasons }
}
