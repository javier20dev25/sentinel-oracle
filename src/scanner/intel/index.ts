import type { PRFile } from '../rules'
import type { IntelReport } from './types'
import { analyzeDependencies } from './dependencies'
import { analyzeEndpoints } from './endpoints'
import { analyzeServices } from './services'
import { analyzePermissions } from './permissions'
import { analyzeCapabilities } from './capabilities'
import { analyzeSecrets } from './secrets'
import { analyzeTrustBoundaries } from './trust'
import { analyzeCrypto } from './crypto'
import { analyzeAuth } from './auth'
import { analyzeInfrastructure } from './infrastructure'
import { analyzeDependencyDelta } from './deep-dependency'
import { analyzeWorkflowIntelligence } from './workflow-intelligence'
import { analyzeTrustDrift } from './trust-drift'

export type { IntelReport, IntelRisk, IntelItem } from './types'
export { analyzeWorkflowIntelligence }
export { analyzeDependencyDelta }

function buildSecurityDelta(report: IntelReport) {
  const deps = report.dependencies
  const endpoints = report.endpoints
  const services = report.services
  const permissions = report.permissions
  const capabilities = report.capabilities
  const secrets = report.secrets
  const trust = report.trustBoundaries
  const crypto = report.crypto
  const auth = report.auth
  const infra = report.infrastructure
  const trustDrift = report.trustDrift

  const totalRisk = [deps?.risk, endpoints?.risk, services?.risk, permissions?.risk,
    capabilities?.risk, secrets?.risk, trust?.risk, crypto?.risk, auth?.risk, infra?.risk, trustDrift?.risk]
    .filter((r): r is NonNullable<typeof r> => !!r)

  let totalRiskChange = 0
  for (const r of totalRisk) {
    if (r === 'critical') totalRiskChange += 4
    else if (r === 'high') totalRiskChange += 3
    else if (r === 'medium') totalRiskChange += 2
    else if (r === 'low') totalRiskChange += 1
  }

  const capList: string[] = []
  if (capabilities?.filesystem?.length) capList.push('Filesystem')
  if (capabilities?.network?.length) capList.push('Network')
  if (capabilities?.shell?.length) capList.push('Shell')
  if (capabilities?.dynamicCode?.length) capList.push('DynamicCode')
  if (capabilities?.database?.length) capList.push('Database')
  if (capabilities?.crypto?.length) capList.push('Crypto')

  return {
    totalRiskChange,
    dependsOn: deps ? deps.added.length + deps.updated.length + deps.removed.length : 0,
    permissionsOn: permissions ? 1 : 0,
    endpointsAdded: endpoints?.added.length || 0,
    endpointsSuspicious: endpoints?.suspicious.length || 0,
    capabilitiesAdded: capList,
    servicesAdded: services?.added.map(s => s.name) || [],
    authBypass: !!auth?.removedMiddleware?.length || !!auth?.changes?.some(c => c.description?.toLowerCase().includes('bypass')),
    trustViolations: trust?.flows.length || 0,
    cryptoWeakness: !!crypto?.changes?.length,
    infraDrift: !!infra?.changes?.length,
    secretExposure: !!secrets?.sources?.length,
    summary: `${totalRisk.length} modules triggered, score: ${totalRiskChange}`,
  }
}

export async function runIntelAnalysis(files: PRFile[]): Promise<IntelReport> {
  const report: IntelReport = {}

  const deps = analyzeDependencies(files)
  if (deps) report.dependencies = deps

  const endpoints = analyzeEndpoints(files)
  if (endpoints) report.endpoints = endpoints

  const services = analyzeServices(files)
  if (services) report.services = services

  const permissions = analyzePermissions(files)
  if (permissions) report.permissions = permissions

  const capabilities = analyzeCapabilities(files)
  if (capabilities) report.capabilities = capabilities

  const secrets = analyzeSecrets(files)
  if (secrets) report.secrets = secrets

  const trust = analyzeTrustBoundaries(files)
  if (trust) report.trustBoundaries = trust

  const crypto = analyzeCrypto(files)
  if (crypto) report.crypto = crypto

  const auth = analyzeAuth(files)
  if (auth) report.auth = auth

  const infra = analyzeInfrastructure(files)
  if (infra) report.infrastructure = infra

  const trustDrift = analyzeTrustDrift(files)
  if (trustDrift.risk !== 'low') report.trustDrift = trustDrift

  // Dependency Delta (EXPERIMENTAL): tarball diff — no semantic analysis yet
  if (deps && deps.updated.length > 0) {
    for (const upd of deps.updated.slice(0, 3)) { // max 3 for performance
      const delta = await analyzeDependencyDelta({
        name: upd.name,
        fromVersion: upd.fromVersion,
        toVersion: upd.toVersion,
        registry: inferRegistry(upd.name),
      })
      if (delta) {
        report.dependencyDelta = delta
        break
      }
    }
  }

  // Build SecurityDelta summary
  report.securityDelta = buildSecurityDelta(report)

  return report
}

function inferRegistry(name: string): string {
  if (/^@/.test(name)) return 'npm'
  if (name.includes('-')) return 'npm'
  return 'npm'
}
