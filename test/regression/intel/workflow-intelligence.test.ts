import { describe, it, expect } from 'vitest'
import { analyzeWorkflowIntelligence } from '../../../src/scanner/intel/workflow-intelligence'

describe('analyzeWorkflowIntelligence', () => {
  it('returns empty report for no records', () => {
    const result = analyzeWorkflowIntelligence([])
    expect(result.baselines).toHaveLength(0)
    expect(result.anomalousPRs).toHaveLength(0)
    expect(result.risk).toBe('low')
  })

  it('calculates baselines from records', () => {
    const records = [
      { checkName: 'test', durationMs: 100000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
      { checkName: 'test', durationMs: 110000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
      { checkName: 'test', durationMs: 90000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
    ]
    const result = analyzeWorkflowIntelligence(records)
    expect(result.baselines).toHaveLength(1)
    expect(result.baselines[0].avgDurationMs).toBe(100000)
    expect(result.baselines[0].sampleCount).toBe(3)
  })

  it('detects anomalous current PR', () => {
    const records = [
      { checkName: 'build', durationMs: 100000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 110000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 90000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
    ]
    const result = analyzeWorkflowIntelligence(records, [], {
      currentPR: { number: 4, checkDurations: { build: 600000 } },
    })
    expect(result.anomalousPRs.length).toBeGreaterThanOrEqual(1)
    expect(result.risk).toBe('high')
  })

  it('computes integrity score', () => {
    const records = Array.from({ length: 10 }, (_, i) => ({
      checkName: 'build', durationMs: 100000 + (i % 3) * 5000, prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    }))
    const result = analyzeWorkflowIntelligence(records, [], {
      currentPR: { number: 99, checkDurations: { build: 600000 } },
    })
    expect(typeof result.integrityScore).toBe('number')
    expect(result.integrityScore).toBeLessThan(100)
  })

  it('detects evasion signals from PR files', () => {
    const records = [
      { checkName: 'build', durationMs: 100000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 110000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
    ]
    const prFiles = [
      { filename: '.github/workflows/ci.yml', patch: '+continue-on-error: true' },
      { filename: '.github/workflows/deploy.yml', patch: '+runs-on: self-hosted' },
    ]
    const result = analyzeWorkflowIntelligence(records, [], { prFiles })
    expect(result.anomalies.length).toBeGreaterThanOrEqual(2)
    expect(result.anomalies.some(a => a.type === 'continue_on_error')).toBe(true)
    expect(result.anomalies.some(a => a.type === 'runner_change')).toBe(true)
  })

  it('reports missing sensor', () => {
    const prFiles = [
      { filename: '.github/workflows/ci.yml', patch: '+name: CI' },
      { filename: 'src/index.ts', patch: '+console.log("hello")' },
    ]
    const result = analyzeWorkflowIntelligence([], [], { prFiles })
    expect(result.missingSensor).toBe(true)
    expect(result.anomalies.some(a => a.type === 'missing_sensor')).toBe(true)
  })

  it('returns fingerprint when jobs provided', () => {
    const records = [
      { checkName: 'build', durationMs: 100000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
    ]
    const result = analyzeWorkflowIntelligence(records, [], {
      currentPR: {
        number: 2,
        jobs: [
          { name: 'build', durationMs: 105000, steps: [{ name: 'checkout', durationMs: 5000 }, { name: 'test', durationMs: 100000 }] },
        ],
      },
    })
    expect(result.fingerprint).toBeTruthy()
    expect(result.fingerprint!.jobCount).toBe(1)
    expect(result.fingerprint!.stepCounts.build).toBe(2)
  })

  it('honors policy for expected jobs', () => {
    const records = [
      { checkName: 'build', durationMs: 100000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
    ]
    const result = analyzeWorkflowIntelligence(records, [], {
      currentPR: {
        number: 2,
        jobs: [{ name: 'build', durationMs: 105000, steps: [] }],
      },
      policy: {
        expectedWorkflows: [],
        minJobs: 3,
        expectedJobs: ['build', 'test', 'security'],
        maxDurationIncreasePct: 50,
        maxDurationDecreasePct: 30,
        requireArtifacts: false,
        sensitivePaths: [],
        allowedRunners: [],
      },
    })
    expect(result.anomalies.some(a => a.type === 'job_missing')).toBe(true)
  })
})
