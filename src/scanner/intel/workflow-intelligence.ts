import type {
  WorkflowCheckBaseline, StepBaseline, ExecutionFingerprint, CIAnomaly, WorkflowIntel,
  IntelRisk, CIPolicy, MultiWindowBaseline, TrustedBaselineInfo, CampaignDelta,
} from './types'

interface StepRecord {
  jobName: string
  stepName: string
  stepNumber: number
  durationMs: number
  status: string
  prNumber: number
  scannedAt: number
  filename: string
}

interface JobRecord {
  checkName: string
  durationMs: number
  prNumber: number
  scannedAt: number
  filename: string
  jobsCount?: number
  stepsCount?: number
  runnerLabel?: string
  trigger?: string
  matrix?: string
  cacheHit?: boolean
  status?: string
  rerunCount?: number
  trusted?: boolean
}

function median(arr: number[]): number {
  if (arr.length === 0) return 0
  const sorted = [...arr].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

function percentile(arr: number[], p: number): number {
  if (arr.length === 0) return 0
  const sorted = [...arr].sort((a, b) => a - b)
  const idx = Math.ceil((p / 100) * sorted.length) - 1
  return sorted[Math.max(0, idx)]
}

function mad(arr: number[], med: number): number {
  if (arr.length === 0) return 0
  const deviations = arr.map(v => Math.abs(v - med))
  return median(deviations)
}

function computeFingerprint(jobStructure: { job: string; steps: string[] }[]): ExecutionFingerprint {
  const stepCounts: Record<string, number> = {}
  for (const j of jobStructure) stepCounts[j.job] = j.steps.length
  const hashInput = jobStructure.map(j => `${j.job}:${j.steps.join(',')}`).join('|')
  let hash = 0
  for (let i = 0; i < hashInput.length; i++) {
    const chr = hashInput.charCodeAt(i)
    hash = ((hash << 5) - hash) + chr
    hash |= 0
  }
  return {
    hash: Math.abs(hash).toString(36).padStart(8, '0'),
    jobCount: jobStructure.length,
    stepCounts,
    jobNames: jobStructure.map(j => j.job),
    jobStructure,
  }
}

interface PolicyCheckResult {
  anomalies: CIAnomaly[]
}

function checkPolicy(
  policy: CIPolicy | undefined,
  currentJobs: { name: string; steps: string[]; durationMs: number }[],
  baselines: WorkflowCheckBaseline[],
): PolicyCheckResult {
  const anomalies: CIAnomaly[] = []
  if (!policy) return { anomalies }
  const jobNames = currentJobs.map(j => j.name)
  for (const expected of policy.expectedJobs) {
    if (!jobNames.includes(expected)) {
      anomalies.push({ type: 'job_missing', severity: 'high', detail: `Expected job "${expected}" is missing`, expected, actual: jobNames.join(', ') })
    }
  }
  if (currentJobs.length < policy.minJobs) {
    anomalies.push({ type: 'job_missing', severity: 'high', detail: `Only ${currentJobs.length} jobs, expected at least ${policy.minJobs}`, expected: policy.minJobs, actual: currentJobs.length })
  }
  if (policy.expectedSteps) {
    for (const [job, expectedSteps] of Object.entries(policy.expectedSteps)) {
      const j = currentJobs.find(jj => jj.name === job)
      if (j) {
        const stepNames = j.steps.map(s => s.split(':')[0].trim())
        for (const es of expectedSteps) {
          if (!stepNames.some(s => s.includes(es))) {
            anomalies.push({ type: 'step_missing', severity: 'medium', detail: `Job "${job}" missing expected step "${es}"`, expected: es, actual: stepNames.join(', ') })
          }
        }
      }
    }
  }
  for (const job of currentJobs) {
    const bl = baselines.find(b => b.checkName === job.name)
    if (bl && bl.avgDurationMs > 0) {
      const pct = ((job.durationMs - bl.avgDurationMs) / bl.avgDurationMs) * 100
      if (pct > policy.maxDurationIncreasePct) {
        anomalies.push({ type: 'time_anomaly', severity: 'medium', detail: `Job "${job.name}" is ${Math.round(pct)}% over baseline`, expected: `${policy.maxDurationIncreasePct}%`, actual: `${Math.round(pct)}%` })
      }
      if (pct < -policy.maxDurationDecreasePct) {
        anomalies.push({ type: 'time_anomaly', severity: 'high', detail: `Job "${job.name}" is ${Math.round(Math.abs(pct))}% under baseline — possible evasion`, expected: `-${policy.maxDurationDecreasePct}%`, actual: `${Math.round(pct)}%` })
      }
    }
  }
  return { anomalies }
}

function computeBaselineStats(durations: number[], meta: JobRecord[]): { avg: number; med: number; p95: number; min: number; max: number; stdDev: number; madVal: number; lastRunAt: number; filename: string } | null {
  if (durations.length < 2) return null
  const avg = durations.reduce((a, b) => a + b, 0) / durations.length
  const med = median(durations)
  const p95 = percentile(durations, 95)
  const variance = durations.reduce((sum, d) => sum + (d - avg) ** 2, 0) / durations.length
  const stdDev = Math.sqrt(variance)
  const min = Math.min(...durations)
  const max = Math.max(...durations)
  const madVal = mad(durations, med)
  const lastRunAt = Math.max(...meta.map(r => r.scannedAt))
  const filename = meta[0]?.filename || ''
  return { avg, med, p95, min, max, stdDev, madVal, lastRunAt, filename }
}

export function analyzeWorkflowIntelligence(
  jobRecords: JobRecord[],
  stepRecords: StepRecord[] = [],
  options?: {
    currentPR?: { number: number; checkDurations?: Record<string, number>; jobs?: { name: string; durationMs: number; steps: { name: string; durationMs: number }[] }[]; runnerLabel?: string; trigger?: string }
    policy?: CIPolicy
    prFiles?: { filename: string; patch: string }[]
    trustedOnly?: boolean
    campaignHistory?: { prNumber: number; capabilities: string[]; endpoints: number; domains: string[]; permissions: string[]; execPatterns: string[]; scannedAt: number }[]
    previousFingerprints?: { prNumber: number; hash: string; scannedAt: number }[]
    cacheEvents?: { prNumber: number; stepName: string; cacheHit: boolean; scannedAt: number }[]
  },
): WorkflowIntel {
  // === TRUSTED FILTER ===
  // If trustedOnly, filter records to only those marked as trusted
  const trustedRecords = options?.trustedOnly ? jobRecords.filter(r => r.trusted === true) : jobRecords
  const untrustedCount = jobRecords.length - trustedRecords.length

  const byCheck = new Map<string, number[]>()
  const byCheckMeta = new Map<string, JobRecord[]>()

  for (const r of trustedRecords) {
    if (!byCheck.has(r.checkName)) {
      byCheck.set(r.checkName, [])
      byCheckMeta.set(r.checkName, [])
    }
    byCheck.get(r.checkName)!.push(r.durationMs)
    byCheckMeta.get(r.checkName)!.push(r)
  }

  const baselines: WorkflowCheckBaseline[] = []
  const multiWindowBaselines: MultiWindowBaseline[] = []
  const anomalyList: CIAnomaly[] = []
  const anomalousPRs: { prNumber: number; checkpoint: string; durationMs: number; deviationPct: number; baselineAvg: number; zscore: number }[] = []

  // === STEP 1: Multi-window baselines ===
  // Compute baselines for 7d, 30d, and all windows
  const now = Date.now()
  const DAY_MS = 86400000

  for (const [checkName, durations] of byCheck) {
    const meta = byCheckMeta.get(checkName)!
    const stats = computeBaselineStats(durations, meta)
    if (!stats) continue

    // Full historical baseline (legacy)
    baselines.push({
      checkName,
      avgDurationMs: Math.round(stats.avg),
      medianDurationMs: Math.round(stats.med),
      p95DurationMs: Math.round(stats.p95),
      minDurationMs: stats.min,
      maxDurationMs: stats.max,
      stdDevMs: Math.round(stats.stdDev),
      madMs: Math.round(stats.madVal),
      sampleCount: durations.length,
      lastRunAt: stats.lastRunAt,
      filename: stats.filename,
    })

    multiWindowBaselines.push({
      checkName,
      windowLabel: 'all',
      sampleCount: durations.length,
      avgDurationMs: Math.round(stats.avg),
      medianDurationMs: Math.round(stats.med),
      p95DurationMs: Math.round(stats.p95),
      minDurationMs: stats.min,
      maxDurationMs: stats.max,
      stdDevMs: Math.round(stats.stdDev),
      madMs: Math.round(stats.madVal),
      lastRunAt: stats.lastRunAt,
    })

    // 30-day window
    const meta30 = meta.filter(m => m.scannedAt > now - 30 * DAY_MS)
    if (meta30.length >= 3) {
      const d30 = meta30.map(m => m.durationMs)
      const s30 = computeBaselineStats(d30, meta30)
      if (s30) {
        multiWindowBaselines.push({
          checkName, windowLabel: '30d',
          sampleCount: d30.length,
          avgDurationMs: Math.round(s30.avg),
          medianDurationMs: Math.round(s30.med),
          p95DurationMs: Math.round(s30.p95),
          minDurationMs: s30.min, maxDurationMs: s30.max,
          stdDevMs: Math.round(s30.stdDev), madMs: Math.round(s30.madVal),
          lastRunAt: s30.lastRunAt,
        })
      }
    }

    // 7-day window
    const meta7 = meta.filter(m => m.scannedAt > now - 7 * DAY_MS)
    if (meta7.length >= 3) {
      const d7 = meta7.map(m => m.durationMs)
      const s7 = computeBaselineStats(d7, meta7)
      if (s7) {
        multiWindowBaselines.push({
          checkName, windowLabel: '7d',
          sampleCount: d7.length,
          avgDurationMs: Math.round(s7.avg),
          medianDurationMs: Math.round(s7.med),
          p95DurationMs: Math.round(s7.p95),
          minDurationMs: s7.min, maxDurationMs: s7.max,
          stdDevMs: Math.round(s7.stdDev), madMs: Math.round(s7.madVal),
          lastRunAt: s7.lastRunAt,
        })
      }
    }

    // Detect anomalous via MAD (robust to poisoning) — only against ALL records
    for (const r of meta) {
      if (stats.madVal > 0 && r.prNumber !== options?.currentPR?.number) {
        const z = (r.durationMs - stats.med) / (stats.madVal * 1.4826 || 1)
        if (Math.abs(z) > 3) {
          anomalousPRs.push({
            prNumber: r.prNumber, checkpoint: checkName,
            durationMs: r.durationMs,
            deviationPct: Math.round(((r.durationMs - stats.avg) / stats.avg) * 100),
            baselineAvg: Math.round(stats.avg),
            zscore: Math.round(z * 100) / 100,
          })
        }
      }
    }

    // Check for baseline drift (recent 30d vs all)
    const recentSamples = meta.filter(m => m.scannedAt > now - 30 * DAY_MS)
    if (recentSamples.length >= 3) {
      const recentAvg = recentSamples.reduce((s, m) => s + m.durationMs, 0) / recentSamples.length
      const drift = ((recentAvg - stats.avg) / stats.avg) * 100
      if (Math.abs(drift) > 15) {
        anomalyList.push({
          type: 'baseline_drift', severity: 'medium',
          detail: `Baseline for "${checkName}" drifted ${Math.round(drift)}% over last 30 days (recent avg: ${Math.round(recentAvg / 1000)}s vs historical: ${Math.round(stats.avg / 1000)}s)`,
          expected: `${Math.round(stats.avg / 1000)}s`, actual: `${Math.round(recentAvg / 1000)}s`,
        })
      }
    }
  }

  // === STEP 2: Step baselines ===
  const byStep = new Map<string, number[]>()
  const byStepMeta = new Map<string, StepRecord[]>()
  for (const r of stepRecords) {
    const key = `${r.jobName}::${r.stepName}`
    if (!byStep.has(key)) { byStep.set(key, []); byStepMeta.set(key, []) }
    byStep.get(key)!.push(r.durationMs)
    byStepMeta.get(key)!.push(r)
  }
  const stepBaselines: StepBaseline[] = []
  for (const [key, durations] of byStep) {
    if (durations.length < 2) continue
    const [jobName, stepName] = key.split('::')
    const avg = durations.reduce((a, b) => a + b, 0) / durations.length
    const med = median(durations)
    const meta = byStepMeta.get(key)!
    const lastRunAt = Math.max(...meta.map(r => r.scannedAt))
    const stepNo = meta[0].stepNumber
    stepBaselines.push({ jobName, stepName, stepNumber: stepNo, avgDurationMs: Math.round(avg), medianDurationMs: Math.round(med), sampleCount: durations.length, lastRunAt })
  }

  // === STEP 3: Current PR analysis ===
  let integrityScore = 100
  let missingSensor = false
  let sensorPresent = false

  if (options?.prFiles) {
    sensorPresent = options.prFiles.some(f =>
      f.filename.includes('sentinel-telemetry') || f.filename.includes('sentinel-ci'),
    )
    for (const file of options.prFiles) {
      if (!file.patch) continue
      const lines = file.patch.split('\n')
      for (const line of lines) {
        if (line.includes('continue-on-error:') && line.includes('true')) {
          anomalyList.push({ type: 'continue_on_error', severity: 'high', detail: `continue-on-error: true in ${file.filename}:${lines.indexOf(line)}` })
        }
        if ((line.match(/^\+\s+if:/) || line.match(/^\s+if:/)) && (line.includes('github.actor') || line.includes('github.ref') || line.includes('github.event_name') || line.includes('success()') === false)) {
          anomalyList.push({ type: 'conditional_skip', severity: 'medium', detail: `Conditional execution in ${file.filename}: "${line.trim()}"` })
        }
        if (line.match(/^\+\s*runs-on:\s*self-hosted/) || line.includes('runs-on: self-hosted')) {
          anomalyList.push({ type: 'runner_change', severity: 'high', detail: `Runner changed to self-hosted in ${file.filename}` })
        }
        if (line.match(/^\+\s*paths-ignore:/) || line.match(/^\s+paths-ignore:/)) {
          anomalyList.push({ type: 'evasion', severity: 'high', detail: `paths-ignore added in ${file.filename} — may skip CI for sensitive paths` })
        }
        if (line.match(/pull_request_target/)) {
          anomalyList.push({ type: 'trigger_change', severity: 'critical', detail: `pull_request_target used in ${file.filename} — elevated permissions risk` })
        }
      }
    }
  }

  // === STEP 4: Multi-window anomaly detection ===
  const currentPR = options?.currentPR
  const anomalyJobs = currentPR?.jobs || (currentPR?.checkDurations ?
    Object.entries(currentPR.checkDurations).map(([name, durationMs]) => ({ name, durationMs, steps: [] }))
    : undefined)

  if (anomalyJobs && currentPR) {
    for (const job of anomalyJobs) {
      // Check against all windows, take the worst deviation
      const windows = multiWindowBaselines.filter(w => w.checkName === job.name)
      let worstZ = 0
      let worstBl: MultiWindowBaseline | null = null

      for (const w of windows) {
        const madVal = w.madMs * 1.4826 || 1
        const z = (job.durationMs - w.medianDurationMs) / madVal
        if (Math.abs(z) > Math.abs(worstZ)) {
          worstZ = z
          worstBl = w
        }
      }

      if (worstBl && Math.abs(worstZ) > 3) {
        const pct = Math.round(((job.durationMs - worstBl.avgDurationMs) / worstBl.avgDurationMs) * 100)
        anomalousPRs.push({
          prNumber: currentPR.number, checkpoint: job.name,
          durationMs: job.durationMs, deviationPct: pct,
          baselineAvg: worstBl.avgDurationMs, zscore: Math.round(worstZ * 100) / 100,
        })
        anomalyList.push({
          type: 'time_anomaly', severity: 'high',
          detail: `PR #${currentPR.number}: "${job.name}" duration ${pct > 0 ? '+' : ''}${pct}% from ${worstBl.windowLabel} baseline (${Math.round(worstBl.medianDurationMs / 1000)}s, actual ${Math.round(job.durationMs / 1000)}s)`,
          expected: `${Math.round(worstBl.medianDurationMs / 1000)}s`, actual: `${Math.round(job.durationMs / 1000)}s`,
        })
      }

      // === Step redistribution detection ===
      if (job.steps.length >= 2) {
        const totalStepMs = job.steps.reduce((s, st) => s + st.durationMs, 0)
        if (totalStepMs > 0) {
          for (const step of job.steps) {
            const sb = stepBaselines.find(s => s.jobName === job.name && s.stepName === step.name)
            if (sb && sb.avgDurationMs > 0) {
              const stepPct = ((step.durationMs - sb.avgDurationMs) / sb.avgDurationMs) * 100
              // Detect if one step grew a lot while others shrank (redistribution)
              if (Math.abs(stepPct) > 20) {
                const otherStepsTotal = job.steps.filter(s => s.name !== step.name).reduce((s, st) => s + st.durationMs, 0)
                const otherStepsBaseline = job.steps.filter(s => s.name !== step.name)
                  .map(s => stepBaselines.find(sb => sb.jobName === job.name && sb.stepName === s.name))
                  .filter(Boolean) as StepBaseline[]
                const otherBaselineTotal = otherStepsBaseline.reduce((s, b) => s + b.avgDurationMs, 0)
                const otherPct = otherBaselineTotal > 0 ? ((otherStepsTotal - otherBaselineTotal) / otherBaselineTotal) * 100 : 0

                if (stepPct > 20 && otherPct < -20) {
                  anomalyList.push({
                    type: 'step_redistribution', severity: 'medium',
                    detail: `Step "${step.name}" in "${job.name}" is ${Math.round(stepPct)}% over baseline while other steps are ${Math.round(otherPct)}% under — possible activity masking`,
                    expected: `${Math.round(sb.avgDurationMs / 1000)}s`, actual: `${Math.round(step.durationMs / 1000)}s`,
                  })
                }
              }
            }
          }
        }
      }

      // === Cache camouflage detection ===
      if (options?.cacheEvents) {
        const cacheHits = options.cacheEvents.filter(c =>
          c.prNumber === currentPR.number && c.cacheHit,
        )
        if (cacheHits.length > 0 && job.durationMs < baselines.find(b => b.checkName === job.name)?.avgDurationMs! * 0.7) {
          anomalyList.push({
            type: 'cache_camouflage', severity: 'medium',
            detail: `Job "${job.name}" is ${Math.round((1 - job.durationMs / (baselines.find(b => b.checkName === job.name)?.avgDurationMs || 1)) * 100)}% faster with ${cacheHits.length} cache hits — possible activity masking`,
          })
        }
      }
    }
  }

  // === STEP 5: Missing telemetry ===
  if (options?.prFiles && !sensorPresent) {
    if (options.prFiles.some(f => f.filename.startsWith('.github/workflows/'))) {
      missingSensor = true
      anomalyList.push({ type: 'missing_sensor', severity: 'high', detail: 'No sentinel-telemetry workflow found — CI cannot be monitored' })
    }
  }

  // === STEP 6: Policy ===
  if (options?.policy && currentPR?.jobs) {
    anomalyList.push(...checkPolicy(
      options.policy,
      currentPR.jobs.map(j => ({ name: j.name, steps: j.steps.map(s => s.name), durationMs: j.durationMs })),
      baselines,
    ).anomalies)
  }

  // === STEP 7: Campaign detection (weighted) ===
  let campaignDelta: CampaignDelta | null = null
  if (options?.campaignHistory && options.campaignHistory.length > 0) {
    const totalCaps = new Set<string>()
    const allDomains = new Set<string>()
    const allPerms = new Set<string>()
    const allExec = new Set<string>()
    let totalEndpoints = 0

    for (const pr of options.campaignHistory) {
      for (const c of pr.capabilities) totalCaps.add(c)
      for (const d of pr.domains) allDomains.add(d)
      for (const p of pr.permissions) allPerms.add(p)
      for (const e of pr.execPatterns) allExec.add(e)
      totalEndpoints += pr.endpoints
    }

    // Weighted scoring
    // exec patterns = 10 each
    // permission escalations (id-token:write, admin, write-all, contents:write) = 8 each
    // operational changes (self-hosted runner) = 8 each
    // secret-like permissions (uppercase, >3 chars) = 6 each
    // generic capabilities = 2 each (capped at 20)
    // new domains = 1 each (capped at 10)
    // new endpoints = 1 each (capped at 10)
    let weightedScore = 0

    for (const exec of allExec) {
      weightedScore += 10
    }

    const ESCALATION_PERMS = new Set(['id-token:write', 'contents:write', 'write-all', 'admin', 'pull-requests:write', 'issues:write', 'actions:write', 'checks:write', 'statuses:write'])
    for (const perm of allPerms) {
      if (ESCALATION_PERMS.has(perm.toLowerCase())) {
        weightedScore += 8
      } else if (/^[A-Z][A-Z0-9_]{2,}$/.test(perm)) {
        weightedScore += 6
      }
    }

    for (const domain of allDomains) {
      if (domain.includes('self-hosted')) {
        weightedScore += 8
      } else {
        weightedScore += 1
      }
    }

    weightedScore += Math.min(totalCaps.size * 2, 20)
    weightedScore += Math.min(totalEndpoints, 10)
    weightedScore += Math.max(0, allDomains.size - 1) * 0

    let campaignRisk: IntelRisk = 'low'
    if (weightedScore >= 15) campaignRisk = 'critical'
    else if (weightedScore >= 8) campaignRisk = 'high'
    else if (weightedScore >= 4) campaignRisk = 'medium'

    if (campaignRisk !== 'low') {
      campaignDelta = {
        windowPrCount: options.campaignHistory.length,
        windowDays: 30,
        totalCapabilities: [...totalCaps],
        newEndpoints: totalEndpoints,
        newDomains: [...allDomains],
        newPermissions: [...allPerms],
        newExecPatterns: [...allExec],
        risk: campaignRisk,
        summary: `${weightedScore} weighted campaign score across ${options.campaignHistory.length} recent PRs`,
      }
      anomalyList.push({
        type: 'campaign_accumulation', severity: campaignRisk,
        detail: `Campaign detected: ${totalCaps.size} capabilities, ${allDomains.size} domains, ${allPerms.size} permissions (weighted score: ${weightedScore}) across ${options.campaignHistory.length} PRs`,
        expected: 'low accumulation', actual: `${weightedScore}`,
      })
    }
  }

  // === STEP 8: Fingerprint churn ===
  if (options?.previousFingerprints && options.previousFingerprints.length >= 5) {
    const uniqueHashes = new Set(options.previousFingerprints.map(f => f.hash))
    if (uniqueHashes.size >= options.previousFingerprints.length * 0.5) {
      anomalyList.push({
        type: 'fingerprint_churn', severity: 'medium',
        detail: `High fingerprint churn: ${uniqueHashes.size} unique fingerprints in ${options.previousFingerprints.length} PRs — possible structure evasion`,
        expected: `${Math.round(options.previousFingerprints.length * 0.3)} unique`,
        actual: `${uniqueHashes.size} unique`,
      })
    }
  }

  // === STEP 9: Synthetic telemetry detection ===
  if (options?.currentPR?.jobs) {
    for (const job of options.currentPR.jobs) {
      for (const step of job.steps) {
        const sb = stepBaselines.find(s => s.jobName === job.name && s.stepName === step.name)
        if (sb && sb.sampleCount <= 3 && step.durationMs < 60000) {
          // A step with very few historical samples and fast execution might be synthetic
          anomalyList.push({
            type: 'synthetic_telemetry', severity: 'medium',
            detail: `Step "${step.name}" in "${job.name}" has only ${sb.sampleCount} historical samples — possible fabricated telemetry`,
            expected: '>5 samples', actual: `${sb.sampleCount} samples`,
          })
        }
      }
    }
  }

  // === STEP 10: Compute integrity score ===
  const severityWeights: Record<string, number> = { critical: 25, high: 15, medium: 5, low: 1 }
  for (const a of anomalyList) {
    integrityScore -= severityWeights[a.severity] || 5
  }
  for (const anom of anomalousPRs) {
    const zMag = Math.abs(anom.zscore)
    if (zMag > 10) integrityScore -= 40
    else if (zMag > 5) integrityScore -= 20
    else integrityScore -= 10
  }
  if (missingSensor) integrityScore -= 10
  integrityScore = Math.max(0, Math.min(100, integrityScore))

  let risk: IntelRisk = 'low'
  if (integrityScore < 40) risk = 'critical'
  else if (integrityScore < 60) risk = 'high'
  else if (integrityScore < 80) risk = 'medium'

  // === STEP 11: Summary ===
  const summary = baselines.length > 0
    ? `CI Integrity: ${integrityScore}% — ${baselines.length} workflows tracked, ${multiWindowBaselines.length} windows${anomalyList.length > 0 ? `, ${anomalyList.length} anomalies` : ''}${anomalousPRs.length > 0 ? `, ${anomalousPRs.length} anomalous runs` : ''}`
    : 'Insufficient workflow history for baselines'

  let fingerprint: ExecutionFingerprint | null = null
  if (currentPR?.jobs && currentPR.jobs.length > 0) {
    fingerprint = computeFingerprint(
      currentPR.jobs.map(j => ({ job: j.name, steps: j.steps.map(s => s.name) })),
    )
  }

  const trustedInfo: TrustedBaselineInfo = {
    totalRecords: jobRecords.length,
    trustedRecords: trustedRecords.length,
    untrustedRecords: untrustedCount,
    usingTrustedOnly: options?.trustedOnly || false,
  }

  return {
    summary, baselines, multiWindowBaselines, stepBaselines,
    anomalousPRs, anomalies: anomalyList, fingerprint,
    integrityScore, missingSensor, sensorPresent,
    trustedInfo, campaignDelta, risk,
  }
}
