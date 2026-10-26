export interface AuditRecommendationInput {
  findings?: Array<{ severity?: string; category?: string }>
  state?: string
  buildIntel?: { risk?: string; verdict?: string }
  commitSha?: string
}

export interface AuditRecommendation {
  recommended: boolean
  reasons: string[]
  commitSha?: string
  command?: string
  scope: 'advisory-only'
}

/** Suggest the separate Sentinel Audit workflow when a PR needs broader evidence.
 * This output is informational and must never feed the Oracle merge decision.
 */
export function recommendAudit(input: AuditRecommendationInput): AuditRecommendation {
  const findings = input.findings || []
  const reasons = new Set<string>()
  if (findings.some((finding) => ['critical', 'high'].includes((finding.severity || '').toLowerCase()))) {
    reasons.add('The PR scan contains a high or critical finding.')
  }
  if (findings.some((finding) => ['workflow', 'dependency', 'supply_chain'].includes((finding.category || '').toLowerCase()))) {
    reasons.add('The PR changes CI/CD or dependency supply-chain surfaces.')
  }
  if (['high', 'critical'].includes((input.buildIntel?.risk || '').toLowerCase())) {
    reasons.add('Build Intelligence reports elevated build-surface risk.')
  }
  if ((input.state || '').toUpperCase() === 'REVIEW' && findings.length === 0) {
    reasons.add('The PR scan requires manual review without a specific finding to adjudicate.')
  }
  const recommended = reasons.size > 0
  const commitSha = input.commitSha && /^[a-f0-9]{40}$/i.test(input.commitSha) ? input.commitSha : undefined
  return {
    recommended,
    reasons: [...reasons],
    commitSha,
    command: recommended && commitSha ? `sentinel-audit preflight . --commit ${commitSha}` : undefined,
    scope: 'advisory-only',
  }
}
