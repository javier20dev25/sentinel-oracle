export type IntelRisk = 'low' | 'medium' | 'high' | 'critical'

import type { Finding } from '../rules'

export interface IntelItem {
  label: string
  detail: string
  risk?: IntelRisk
  file?: string
  line?: number
}

export interface DependencyIntel {
  summary: string
  added: { name: string; version: string; from?: string }[]
  updated: { name: string; fromVersion: string; toVersion: string; isMajor: boolean }[]
  removed: { name: string; version: string }[]
  newToRepo: string[]
  riskSignals: { package: string; signal: string; risk: IntelRisk }[]
  risk: IntelRisk
}

export interface EndpointIntel {
  summary: string
  added: { url: string; file: string; line: number }[]
  removed: { url: string; file: string }[]
  suspicious: { url: string; reason: string; file: string; line: number }[]
  risk: IntelRisk
}

export interface ServiceIntel {
  summary: string
  added: { name: string; package: string; file: string; line: number }[]
  removed: { name: string; file: string }[]
  risk: IntelRisk
}

export interface PermissionIntel {
  summary: string
  file: string
  before: Record<string, string>
  after: Record<string, string>
  addedPermissions: string[]
  removedPermissions: string[]
  risk: IntelRisk
}

export interface CapabilityIntel {
  summary: string
  filesystem: string[]
  network: string[]
  shell: string[]
  dynamicCode: string[]
  database: string[]
  crypto: string[]
  risk: IntelRisk
}

export interface SecretSurfaceIntel {
  summary: string
  sources: { var: string; file: string; line: number }[]
  consumers: { var: string; file: string; line: number }[]
  risk: IntelRisk
}

export interface TrustBoundaryIntel {
  summary: string
  flows: { source: string; sink: string; file: string; line: number }[]
  risk: IntelRisk
}

export interface CryptoIntel {
  summary: string
  changes: { parameter: string; before: string; after: string; impact: string }[]
  risk: IntelRisk
}

export interface AuthIntel {
  summary: string
  newRoutes: { path: string; method: string; file: string; line: number }[]
  removedMiddleware: { name: string; file: string; line: number }[]
  changes: { description: string; file: string; line: number }[]
  risk: IntelRisk
}

export interface InfrastructureIntel {
  summary: string
  changes: { aspect: string; before: string; after: string; impact: string }[]
  risk: IntelRisk
}

export interface DependencyDelta {
  packageName: string
  fromVersion: string
  toVersion: string
  filesChanged: number
  newDomains: string[]
  newNetworkCalls: number
  newDependencies: string[]
  newCapabilities: string[]
  newScripts: string[]
  newBinaries: string[]
  risk: IntelRisk
  summary: string
}

export interface WorkflowCheckBaseline {
  checkName: string
  avgDurationMs: number
  medianDurationMs: number
  p95DurationMs: number
  minDurationMs: number
  maxDurationMs: number
  stdDevMs: number
  madMs: number
  sampleCount: number
  lastRunAt: number
  filename: string
}

export interface StepBaseline {
  jobName: string
  stepName: string
  stepNumber: number
  avgDurationMs: number
  medianDurationMs: number
  sampleCount: number
  lastRunAt: number
}

export interface ExecutionFingerprint {
  hash: string
  jobCount: number
  stepCounts: Record<string, number>
  jobNames: string[]
  jobStructure: { job: string; steps: string[] }[]
}

export interface CIAnomaly {
  type: 'evasion' | 'drift' | 'missing_sensor' | 'runner_change' | 'trigger_change' | 'conditional_skip' | 'continue_on_error' | 'job_missing' | 'step_missing' | 'time_anomaly' | 'test_reduction' | 'baseline_drift' | 'campaign_accumulation' | 'trust_drift' | 'fingerprint_churn' | 'step_redistribution' | 'cache_camouflage' | 'synthetic_telemetry'
  severity: IntelRisk
  detail: string
  expected?: string | number
  actual?: string | number
}

export interface MultiWindowBaseline {
  checkName: string
  windowLabel: '7d' | '30d' | 'all'
  sampleCount: number
  avgDurationMs: number
  medianDurationMs: number
  p95DurationMs: number
  minDurationMs: number
  maxDurationMs: number
  stdDevMs: number
  madMs: number
  lastRunAt: number
}

export interface TrustedBaselineInfo {
  totalRecords: number
  trustedRecords: number
  untrustedRecords: number
  usingTrustedOnly: boolean
}

export interface CampaignDelta {
  windowPrCount: number
  windowDays: number
  totalCapabilities: string[]
  newEndpoints: number
  newDomains: string[]
  newPermissions: string[]
  newExecPatterns: string[]
  risk: IntelRisk
  summary: string
}

export interface TrustDriftIntel {
  summary: string
  newCollaborators: string[]
  newGitHubApps: string[]
  newWorkflowSecrets: string[]
  newEnvironments: string[]
  newRunners: string[]
  removedBranchProtections: string[]
  permissionEscalations: string[]
  risk: IntelRisk
}

export interface WorkflowIntel {
  summary: string
  baselines: WorkflowCheckBaseline[]
  multiWindowBaselines: MultiWindowBaseline[]
  stepBaselines: StepBaseline[]
  anomalousPRs: { prNumber: number; checkpoint: string; durationMs: number; deviationPct: number; baselineAvg: number; zscore: number }[]
  anomalies: CIAnomaly[]
  fingerprint: ExecutionFingerprint | null
  integrityScore: number
  missingSensor: boolean
  sensorPresent: boolean
  trustedInfo: TrustedBaselineInfo
  campaignDelta: CampaignDelta | null
  risk: IntelRisk
}

export interface CIPolicy {
  expectedWorkflows: string[]
  minJobs: number
  expectedJobs: string[]
  expectedSteps?: Record<string, string[]>
  maxDurationIncreasePct: number
  maxDurationDecreasePct: number
  requireArtifacts: boolean
  sensitivePaths: string[]
  allowedRunners: string[]
}

export interface SecurityDelta {
  totalRiskChange: number
  dependsOn: number
  permissionsOn: number
  endpointsAdded: number
  endpointsSuspicious: number
  capabilitiesAdded: string[]
  servicesAdded: string[]
  authBypass: boolean
  trustViolations: number
  cryptoWeakness: boolean
  infraDrift: boolean
  secretExposure: boolean
  summary: string
  modules: { name: string; risk: IntelRisk }[]
}

export interface CapabilitySnapshot {
  filesystem: number
  network: number
  shell: number
  dynamicCode: number
  database: number
  crypto: number
  secrets: number
  runners: number
  environments: number
  collaborators: number
  permissionEscalations: number
  newDomains: number
  newIntegrations: number
  workflowCount: number
  totalRiskScore: number
}

export interface DNAChange {
  label: string
  current: number
  previous: number
  change: number
  changePct: number
}

export interface DNAReport {
  current: CapabilitySnapshot
  history: CapabilitySnapshot[]
  changes: DNAChange[]
  summary: string
  snapshotCount: number
}

export interface IntelReport {
  dependencies?: DependencyIntel
  endpoints?: EndpointIntel
  services?: ServiceIntel
  permissions?: PermissionIntel
  capabilities?: CapabilityIntel
  secrets?: SecretSurfaceIntel
  trustBoundaries?: TrustBoundaryIntel
  crypto?: CryptoIntel
  auth?: AuthIntel
  infrastructure?: InfrastructureIntel
  dependencyDelta?: DependencyDelta
  workflowIntel?: WorkflowIntel
  securityDelta?: SecurityDelta
  trustDrift?: TrustDriftIntel
  campaignDelta?: CampaignDelta
  /** Typed findings from scanning the tarball of an added/updated dependency. */
  dependencyTarballFindings?: Finding[]
}
