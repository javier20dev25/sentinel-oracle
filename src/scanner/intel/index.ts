import type { PRFile } from '../rules'
import { runRules, type Finding } from '../rules'
import type { IntelReport, IntelRisk } from './types'
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
import {
  analyzeDependencyDelta,
  analyzeDependencyTarball,
  tarballToPRFiles,
  lifecycleToFindings,
  deltaToFindings,
  unverifiableVersionFinding,
} from './deep-dependency'
import { analyzeWorkflowIntelligence } from './workflow-intelligence'
import { analyzeTrustDrift } from './trust-drift'
import { TarballBudget, mergeTelemetry, type ScanTelemetry } from './tarball-budget'
import { getContentIntelStore, type ContentIntelStore } from './content-intel/store'
import { stateFromRisk } from './content-intel/state'
import type { ContentIntelEvidence } from './content-intel/record'
import { getScannerVersion } from './content-intel/scanner-version'
import { enrichContentIntel, hasCloudConnection } from './cloud-lookup'
import { contributeScanEvidence } from './cloud-contribute'
import { debug } from '../../logger'

export type { IntelReport, IntelRisk, IntelItem } from './types'
export { analyzeWorkflowIntelligence }
export { analyzeDependencyDelta, analyzeDependencyTarball }

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

  const moduleEntries: { name: string; risk: IntelRisk }[] = []
  const pushIf = (name: string, val: { risk?: IntelRisk } | undefined) => {
    if (val?.risk) moduleEntries.push({ name, risk: val.risk })
  }
  pushIf('Dependencies', deps)
  pushIf('Endpoints', endpoints)
  pushIf('Services', services)
  pushIf('Permissions', permissions)
  pushIf('Capabilities', capabilities)
  pushIf('Secrets', secrets)
  pushIf('Trust Boundaries', trust)
  pushIf('Crypto', crypto)
  pushIf('Auth', auth)
  pushIf('Infrastructure', infra)
  pushIf('Trust Drift', trustDrift)

  let totalRiskChange = 0
  for (const m of moduleEntries) {
    if (m.risk === 'critical') totalRiskChange += 4
    else if (m.risk === 'high') totalRiskChange += 3
    else if (m.risk === 'medium') totalRiskChange += 2
    else if (m.risk === 'low') totalRiskChange += 1
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
    summary: `${moduleEntries.length} modules triggered, score: ${totalRiskChange}`,
    modules: moduleEntries,
  }
}

export interface IntelAnalysisOptions {
  tarballScan?: boolean
  /** Repository context for the seen-in-repos counter (e.g. "owner/repo"). */
  repoKey?: string
  /** Inject a content-intel store (tests). Defaults to the persistent SQLite store. */
  contentIntelStore?: ContentIntelStore | null
}

export async function runIntelAnalysis(files: PRFile[], opts?: IntelAnalysisOptions): Promise<IntelReport> {
  const contentIntelStore: ContentIntelStore | null =
    opts?.contentIntelStore !== undefined ? opts.contentIntelStore : getContentIntelStore()
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

  // Tarball scan: verify ADDED dependencies by downloading and scanning the
  // actual published tarball (ChainDrop vector). Gated by SENTINEL_TARBALL_SCAN.
  // Network work is bounded by a TarballBudget (packages/bytes/time/concurrency)
  // instead of a fixed cap, so a PR that adds 120 packages degrades gracefully.
  const tarballScan = opts?.tarballScan ?? process.env.SENTINEL_TARBALL_SCAN !== '0'
  const tarballFindings: Finding[] = []
  let tarballTelemetry: ScanTelemetry | null = null

  if (deps && tarballScan) {
    const budget = new TarballBudget()
    const added = await budget.map(deps.added, add =>
      analyzeDependencyTarball({
        name: add.name,
        version: add.version,
        registry: inferRegistry(add.name),
      }, budget, { store: contentIntelStore, repoKey: opts?.repoKey }),
    )
    tarballTelemetry = budget.telemetry()
    for (const { item, value: scan } of added) {
      if (!scan) continue
      if (!report.dependencyDelta && scan.delta) report.dependencyDelta = scan.delta
      if (scan.skipped === 'not_published') {
        tarballFindings.push(unverifiableVersionFinding(item.name, item.version))
      } else if (scan.skipped !== 'budget' && scan.skipped !== 'network') {
        if (scan.fromCache) {
          if (scan.cachedFindings) tarballFindings.push(...scan.cachedFindings)
          continue
        }
        const findings: Finding[] = []
        findings.push(...lifecycleToFindings(scan.lifecycleScripts, item.name, scan.resolvedVersion ?? ''))
        if (scan.delta) findings.push(...deltaToFindings(scan.delta))
        const prFiles = tarballToPRFiles(scan, item.name)
        if (prFiles.length > 0) findings.push(...runRules(prFiles))
        tarballFindings.push(...findings)
        if (scan.contentId && scan.integrityVerified === false) {
          tarballFindings.push({
            severity: 'medium',
            category: 'supply_chain',
            title: 'Dependency tarball integrity mismatch',
            description: `${item.name}@${scan.resolvedVersion} downloaded bytes do not match the registry SRI (sha512) — possible tampering or registry integrity failure. The verdict was NOT cached.`,
            file: 'package.json',
          })
        }
        if (scan.contentId && scan.integrityVerified === true && scan.delta) {
          const evidence: ContentIntelEvidence = {
            risk: scan.delta.risk,
            filesChanged: scan.delta.filesChanged,
            newDomains: scan.delta.newDomains,
            newNetworkCalls: scan.delta.newNetworkCalls,
            newCapabilities: scan.delta.newCapabilities,
            newScripts: scan.delta.newScripts,
            newBinaries: scan.delta.newBinaries,
            lifecycleScripts: scan.lifecycleScripts,
            summary: scan.delta.summary,
            findings,
          }
          contentIntelStore?.record(scan.contentId, stateFromRisk(scan.delta.risk), evidence, {
            verified: true,
            repoKey: opts?.repoKey,
          })
          if (contentIntelStore && hasCloudConnection() && scan.contentId) {
            void enrichContentIntel(contentIntelStore, scan.contentId, {
              repoKey: opts?.repoKey,
              scannerVersion: getScannerVersion(),
            })
              .then(outcome => {
                if (outcome) debug(`[cloud] ${scan.contentId} enrichment: ${outcome}`)
              })
              .catch(() => {})
          }
          void contributeScanEvidence(scan, findings, { scannerVersion: getScannerVersion() })
            .then(outcome => {
              if (outcome) debug(`[cloud] ${scan.contentId} contribution: ${outcome}`)
            })
            .catch(() => {})
        }
      }
    }
  }

  // Dependency Delta (tarball diff for UPDATED deps). Skip when an added-dep
  // scan already produced a delta to bound network work. Each phase has its own
  // budget (a resource-scoped batch), and telemetry is merged for reporting.
  if (deps && !report.dependencyDelta && deps.updated.length > 0 && tarballScan) {
    const budget = new TarballBudget()
    const updated = await budget.map(deps.updated, upd =>
      analyzeDependencyDelta({
        name: upd.name,
        fromVersion: upd.fromVersion,
        toVersion: upd.toVersion,
        registry: inferRegistry(upd.name),
      }, budget),
    )
    tarballTelemetry = tarballTelemetry ? mergeTelemetry(tarballTelemetry, budget.telemetry()) : budget.telemetry()
    for (const { value: delta } of updated) {
      if (delta) {
        report.dependencyDelta = delta
        break
      }
    }
  }

  if (tarballFindings.length > 0) report.dependencyTarballFindings = tarballFindings
  if (tarballTelemetry) report.tarballScanTelemetry = tarballTelemetry

  // Build SecurityDelta summary
  report.securityDelta = buildSecurityDelta(report)

  return report
}

function inferRegistry(name: string): string {
  if (/^@/.test(name)) return 'npm'
  if (name.includes('-')) return 'npm'
  return 'npm'
}
