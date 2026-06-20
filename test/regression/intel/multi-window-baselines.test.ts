import { describe, it, expect } from 'vitest'
import { analyzeWorkflowIntelligence } from '../../../src/scanner/intel/workflow-intelligence'

describe('Multi-window baselines', () => {
  it('produces baselines for 7d, 30d, and all windows', () => {
    const now = Date.now()
    const day = 86400000
    const records = Array.from({ length: 20 }, (_, i) => ({
      checkName: 'build', durationMs: 200000 + i * 5000,
      prNumber: i + 1, scannedAt: now - (30 - i) * day, filename: 'ci.yml',
    }))
    const result = analyzeWorkflowIntelligence(records)

    const windows = result.multiWindowBaselines
    const buildWindows = windows.filter(w => w.checkName === 'build')
    expect(buildWindows.length).toBeGreaterThanOrEqual(2) // all + at least one window
    const allWindow = buildWindows.find(w => w.windowLabel === 'all')
    expect(allWindow).toBeDefined()
    expect(allWindow!.sampleCount).toBe(20)

    const w7 = buildWindows.find(w => w.windowLabel === '7d')
    if (w7) {
      expect(w7.sampleCount).toBeGreaterThanOrEqual(3)
      console.log(`[Multi-window] 7d: ${w7.sampleCount} samples, avg=${w7.avgDurationMs}ms, mad=${w7.madMs}ms`)
    }
    const w30 = buildWindows.find(w => w.windowLabel === '30d')
    if (w30) {
      expect(w30.sampleCount).toBeGreaterThanOrEqual(3)
      console.log(`[Multi-window] 30d: ${w30.sampleCount} samples, avg=${w30.avgDurationMs}ms, mad=${w30.madMs}ms`)
    }
  })
})

describe('Trusted baselines', () => {
  it('filters untrusted records when trustedOnly is set', () => {
    const clean = [
      { checkName: 'build', durationMs: 240000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml', trusted: true },
      { checkName: 'build', durationMs: 250000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml', trusted: true },
      { checkName: 'build', durationMs: 260000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml', trusted: true },
    ]
    const poisoned = [
      { checkName: 'build', durationMs: 300000, prNumber: 10, scannedAt: 4000, filename: 'ci.yml', trusted: false },
      { checkName: 'build', durationMs: 350000, prNumber: 11, scannedAt: 5000, filename: 'ci.yml', trusted: false },
      { checkName: 'build', durationMs: 400000, prNumber: 12, scannedAt: 6000, filename: 'ci.yml', trusted: false },
    ]

    const allRecords = [...clean, ...poisoned]

    // Without trustedOnly: baseline includes ALL records
    const dirtyResult = analyzeWorkflowIntelligence(allRecords, [], {
      currentPR: { number: 99, checkDurations: { build: 255000 } },
    })
    expect(dirtyResult.trustedInfo.totalRecords).toBe(6)
    expect(dirtyResult.trustedInfo.trustedRecords).toBe(6)
    expect(dirtyResult.trustedInfo.untrustedRecords).toBe(0)
    expect(dirtyResult.trustedInfo.usingTrustedOnly).toBe(false)
    const dirtyBl = dirtyResult.baselines.find(b => b.checkName === 'build')
    expect(dirtyBl).toBeDefined()
    expect(dirtyBl!.avgDurationMs).toBeGreaterThan(260000)

    // With trustedOnly: only clean records used
    const cleanResult = analyzeWorkflowIntelligence(allRecords, [], {
      currentPR: { number: 99, checkDurations: { build: 255000 } },
      trustedOnly: true,
    })
    expect(cleanResult.trustedInfo.totalRecords).toBe(6)
    expect(cleanResult.trustedInfo.trustedRecords).toBe(3)
    expect(cleanResult.trustedInfo.untrustedRecords).toBe(3)
    expect(cleanResult.trustedInfo.usingTrustedOnly).toBe(true)
    const cleanBl = cleanResult.baselines.find(b => b.checkName === 'build')
    expect(cleanBl).toBeDefined()
    expect(cleanBl!.avgDurationMs).toBe(250000)
  })
})

describe('Campaign detection', () => {
  it('detects capability accumulation across PRs', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      campaignHistory: [
        { prNumber: 1, capabilities: ['filesystem'], endpoints: 1, domains: ['example.com'], permissions: [], execPatterns: [], scannedAt: 1000 },
        { prNumber: 2, capabilities: ['network'], endpoints: 0, domains: ['evil-c2.com'], permissions: ['write-all'], execPatterns: [], scannedAt: 2000 },
        { prNumber: 3, capabilities: ['shell'], endpoints: 2, domains: [], permissions: [], execPatterns: ['eval'], scannedAt: 3000 },
        { prNumber: 4, capabilities: ['dynamicCode'], endpoints: 0, domains: ['data-exfil.com'], permissions: [], execPatterns: ['exec'], scannedAt: 4000 },
        { prNumber: 5, capabilities: ['database'], endpoints: 1, domains: [], permissions: ['admin'], execPatterns: [], scannedAt: 5000 },
      ],
    })

    expect(result.campaignDelta).toBeDefined()
    if (result.campaignDelta) {
      expect(result.campaignDelta.totalCapabilities.length).toBeGreaterThanOrEqual(3)
      expect(result.campaignDelta.risk).toBe('critical')
      expect(result.anomalies.some(a => a.type === 'campaign_accumulation')).toBe(true)
      console.log(`[Campaign] Risk: ${result.campaignDelta.risk}, Total caps: ${result.campaignDelta.totalCapabilities.length}, Domains: ${result.campaignDelta.newDomains}`)
    }
  })

  it('does not alert for low accumulation', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      campaignHistory: [
        { prNumber: 1, capabilities: ['filesystem'], endpoints: 1, domains: [], permissions: [], execPatterns: [], scannedAt: 1000 },
      ],
    })
    expect(result.campaignDelta).toBeNull()
    expect(result.anomalies.some(a => a.type === 'campaign_accumulation')).toBe(false)
  })
})

describe('Step redistribution detection', () => {
  it('detects when one step grows while others shrink', () => {
    const records = Array.from({ length: 10 }, (_, i) => ({
      checkName: 'ci', durationMs: 290000 + i * 20000, prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    }))
    const stepRecords = Array.from({ length: 10 }, (_, i) => ({
      jobName: 'ci', stepName: 'build', stepNumber: 0, durationMs: 180000 + i * 10000, status: 'success', prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    })).concat(
      Array.from({ length: 10 }, (_, i) => ({
        jobName: 'ci', stepName: 'run-tests', stepNumber: 1, durationMs: 90000 + i * 5000, status: 'success', prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
      }))
    )

    // Attack: build step +50%, test step -83% — redistribution
    const result = analyzeWorkflowIntelligence(records, stepRecords, {
      currentPR: {
        number: 99,
        jobs: [
          { name: 'ci', durationMs: 300000, steps: [{ name: 'build', durationMs: 285000 }, { name: 'run-tests', durationMs: 15000 }] },
        ],
      },
    })

    const redistribution = result.anomalies.some(a => a.type === 'step_redistribution')
    expect(redistribution).toBe(true)
    console.log('[Step redistribution] Detected:', redistribution)
  })
})

describe('Fingerprint churn detection', () => {
  it('detects high fingerprint churn', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      previousFingerprints: Array.from({ length: 10 }, (_, i) => ({
        prNumber: i + 1, hash: `hash${i}`, scannedAt: i * 1000,
      })),
    })
    const churn = result.anomalies.some(a => a.type === 'fingerprint_churn')
    expect(churn).toBe(true)
    console.log('[Fingerprint churn] Detected:', churn)
  })

  it('does not alert for stable fingerprints', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      previousFingerprints: Array.from({ length: 10 }, (_, i) => ({
        prNumber: i + 1, hash: 'samehash', scannedAt: i * 1000,
      })),
    })
    const churn = result.anomalies.some(a => a.type === 'fingerprint_churn')
    expect(churn).toBe(false)
  })
})

describe('Synthetic telemetry detection', () => {
  it('detects steps with suspiciously few historical samples', () => {
    const stepRecords = Array.from({ length: 2 }, (_, i) => ({
      jobName: 'audit', stepName: 'run', stepNumber: 0, durationMs: 30000 + i * 5000, status: 'success', prNumber: 100 + i, scannedAt: i * 100000, filename: 'ci.yml',
    }))
    const result = analyzeWorkflowIntelligence([], stepRecords, {
      currentPR: {
        number: 999,
        jobs: [
          { name: 'audit', durationMs: 35000, steps: [{ name: 'run', durationMs: 35000 }] },
        ],
      },
    })
    const synthetic = result.anomalies.some(a => a.type === 'synthetic_telemetry')
    expect(synthetic).toBe(true)
    console.log('[Synthetic telemetry] Detected:', synthetic)
  })
})
