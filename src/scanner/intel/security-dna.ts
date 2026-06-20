import type { IntelReport, CapabilitySnapshot, DNAReport, DNAChange } from './types'

export function buildCapabilitySnapshot(report: IntelReport): CapabilitySnapshot {
  const caps = report.capabilities
  const endpoints = report.endpoints
  const services = report.services
  const trustDrift = report.trustDrift
  const workflowIntel = report.workflowIntel

  let totalRiskScore = 0
  const modules = [
    report.dependencies,
    report.endpoints,
    report.services,
    report.permissions,
    report.capabilities,
    report.secrets,
    report.trustBoundaries,
    report.crypto,
    report.auth,
    report.infrastructure,
    report.trustDrift,
  ]
  for (const m of modules) {
    if (m?.risk === 'critical') totalRiskScore += 4
    else if (m?.risk === 'high') totalRiskScore += 3
    else if (m?.risk === 'medium') totalRiskScore += 2
    else if (m?.risk === 'low') totalRiskScore += 1
  }

  return {
    filesystem: caps?.filesystem?.length ?? 0,
    network: caps?.network?.length ?? 0,
    shell: caps?.shell?.length ?? 0,
    dynamicCode: caps?.dynamicCode?.length ?? 0,
    database: caps?.database?.length ?? 0,
    crypto: caps?.crypto?.length ?? 0,
    secrets: trustDrift?.newWorkflowSecrets?.length ?? 0,
    runners: trustDrift?.newRunners?.length ?? 0,
    environments: trustDrift?.newEnvironments?.length ?? 0,
    collaborators: trustDrift?.newCollaborators?.length ?? 0,
    permissionEscalations: trustDrift?.permissionEscalations?.length ?? 0,
    newDomains: endpoints?.added?.length ?? 0,
    newIntegrations: services?.added?.length ?? 0,
    workflowCount: workflowIntel?.baselines?.length ?? 0,
    totalRiskScore,
  }
}

export function buildDNAReport(
  current: CapabilitySnapshot,
  history: CapabilitySnapshot[],
): DNAReport {
  const fields: { label: string; key: keyof CapabilitySnapshot }[] = [
    { label: 'Network', key: 'network' },
    { label: 'Shell', key: 'shell' },
    { label: 'Crypto', key: 'crypto' },
    { label: 'Filesystem', key: 'filesystem' },
    { label: 'Dynamic Code', key: 'dynamicCode' },
    { label: 'Database', key: 'database' },
    { label: 'Secrets', key: 'secrets' },
    { label: 'Runners', key: 'runners' },
    { label: 'Environments', key: 'environments' },
    { label: 'Collaborators', key: 'collaborators' },
    { label: 'Permission Escalations', key: 'permissionEscalations' },
    { label: 'New Domains', key: 'newDomains' },
    { label: 'New Integrations', key: 'newIntegrations' },
  ]

  const changes: DNAChange[] = []
  const previous = history.length > 0 ? history[history.length - 1] : null

  for (const f of fields) {
    const currentVal = current[f.key]
    const previousVal = previous ? previous[f.key] : 0
    const change = currentVal - previousVal
    const changePct = previousVal > 0 ? Math.round((change / previousVal) * 100) : 0
    changes.push({
      label: f.label,
      current: currentVal,
      previous: previousVal,
      change,
      changePct,
    })
  }

  const totalModules = fields.filter(f => current[f.key] > 0).length
  const changed = changes.filter(c => c.change !== 0).length
  const summary = `${totalModules} capability areas active, ${changed} changed since last snapshot`

  return {
    current,
    history,
    changes,
    summary,
    snapshotCount: history.length + 1,
  }
}
