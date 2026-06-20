import { describe, it, expect } from 'vitest'
import { analyzeWorkflowIntelligence } from '../../src/scanner/intel/workflow-intelligence'
import { runIntelAnalysis } from '../../src/scanner/intel/index'
import type { PRFile } from '../../src/scanner/rules'

/**
 * RED TEAM: Simulated attack PRs
 * 
 * These test cases simulate real-world CI evasion techniques.
 * Each attack targets a different evasion vector.
 */

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

// Shared baseline for all tests
const baselineRecords = [
  { checkName: 'build', durationMs: 240000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 250000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 260000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 245000, prNumber: 4, scannedAt: 4000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 255000, prNumber: 5, scannedAt: 5000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 180000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 190000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 185000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 175000, prNumber: 4, scannedAt: 4000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 188000, prNumber: 5, scannedAt: 5000, filename: 'ci.yml' },
  { checkName: 'security', durationMs: 120000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
  { checkName: 'security', durationMs: 130000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
  { checkName: 'security', durationMs: 125000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
]

// === ATTACK 1: Skip security job ===
describe('Red Team Attack #1: Job removal', () => {
  it('detects missing security job', () => {
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: {
        number: 99,
        jobs: [
          { name: 'build', durationMs: 250000, steps: [{ name: 'checkout', durationMs: 10000 }, { name: 'compile', durationMs: 240000 }] },
          { name: 'test', durationMs: 188000, steps: [{ name: 'unit', durationMs: 180000 }, { name: 'lint', durationMs: 8000 }] },
          // security job MISSING
        ],
      },
      policy: {
        expectedWorkflows: ['CI'],
        minJobs: 3,
        expectedJobs: ['build', 'test', 'security'],
        maxDurationIncreasePct: 50,
        maxDurationDecreasePct: 30,
        requireArtifacts: false,
        sensitivePaths: [],
        allowedRunners: ['ubuntu-latest'],
      },
    })
    expect(result.anomalies.some(a => a.type === 'job_missing' && a.detail.includes('security'))).toBe(true)
    expect(result.integrityScore).toBeLessThan(90)
  })
})

// === ATTACK 2: Artificially fast build (magic evasion) ===
describe('Red Team Attack #2: Duration manipulation', () => {
  it('detects abnormally fast build', () => {
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: {
        number: 100,
        checkDurations: { build: 10000, test: 188000, security: 125000 },
      },
    })
    expect(result.anomalousPRs.some(a => a.checkpoint === 'build' && a.deviationPct < -80)).toBe(true)
  })
})

// === ATTACK 3: continue-on-error to hide failures ===
describe('Red Team Attack #3: continue-on-error', () => {
  it('detects continue-on-error in workflow', () => {
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: `+
jobs:
  security:
    continue-on-error: true
    steps:
      - run: npm audit` },
      ],
    })
    expect(result.anomalies.some(a => a.type === 'continue_on_error')).toBe(true)
    expect(result.integrityScore).toBeLessThan(95)
  })
})

// === ATTACK 4: Self-hosted runner (bypass controlled env) ===
describe('Red Team Attack #4: Runner change', () => {
  it('detects runner change to self-hosted', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      prFiles: [
        { filename: '.github/workflows/deploy.yml', patch: `+
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: echo "deploying"` },
      ],
    })
    expect(result.anomalies.some(a => a.type === 'runner_change')).toBe(true)
    expect(result.anomalies.some(a => a.severity === 'high')).toBe(true)
  })
})

// === ATTACK 5: Conditional skip via if: ===
describe('Red Team Attack #5: Conditional skip', () => {
  it('detects conditional if: skip', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: `+
jobs:
  security:
    if: github.actor == 'bot'
    steps:
      - run: npm audit` },
      ],
    })
    expect(result.anomalies.some(a => a.type === 'conditional_skip')).toBe(true)
  })
})

// === ATTACK 6: Baseline poisoning (slow drift) ===
describe('Red Team Attack #6: Baseline poisoning', () => {
  it('detects baseline drift over time', () => {
    const now = Date.now()
    const day = 86400000
    const poisonedRecords = baselineRecords.concat(
      // Recent records drifting upward
      { checkName: 'build', durationMs: 300000, prNumber: 10, scannedAt: now - 20 * day, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 320000, prNumber: 11, scannedAt: now - 15 * day, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 340000, prNumber: 12, scannedAt: now - 10 * day, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 360000, prNumber: 13, scannedAt: now - 5 * day, filename: 'ci.yml' },
      { checkName: 'build', durationMs: 380000, prNumber: 14, scannedAt: now - 2 * day, filename: 'ci.yml' },
    )
    const result = analyzeWorkflowIntelligence(poisonedRecords, [], {
      currentPR: { number: 99, checkDurations: { build: 600000 } },
    })
    // Should detect baseline drift anomaly
    expect(result.anomalies.some(a => a.type === 'baseline_drift')).toBe(true)
    // MAD-based detection should still flag the attack PR
    expect(result.anomalies.some(a => a.type === 'time_anomaly')).toBe(true)
  })
})

// === ATTACK 7: Combined attack (multiple evasion vectors) ===
describe('Red Team Attack #7: Multi-vector evasion', () => {
  it('detects combined evasion attempts and computes low integrity score', () => {
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: {
        number: 101,
        jobs: [
          { name: 'build', durationMs: 15000, steps: [{ name: 'checkout', durationMs: 5000 }, { name: 'compile', durationMs: 10000 }] },
          // test and security jobs MISSING
        ],
      },
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: `+
jobs:
  build:
    continue-on-error: true
    runs-on: self-hosted
    if: github.actor != 'admin'
    steps:
      - run: echo "fake build"` },
      ],
      policy: {
        expectedWorkflows: ['CI'],
        minJobs: 3,
        expectedJobs: ['build', 'test', 'security'],
        maxDurationIncreasePct: 50,
        maxDurationDecreasePct: 30,
        requireArtifacts: false,
        sensitivePaths: [],
        allowedRunners: ['ubuntu-latest'],
      },
    })
    expect(result.anomalies.length).toBeGreaterThanOrEqual(4)
    expect(result.integrityScore).toBeLessThan(50)
    expect(result.risk === 'critical' || result.risk === 'high').toBe(true)
  })
})

// === ATTACK 8: Dependency Deep Scan evasion ===
describe('Red Team Attack #8: Hijacked dependency', () => {
  it('detects suspicious package updates via Security Delta', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'package.json', patch: '+"axios": "^1.8.0"', additions: 1 }),
      makeFile({ filename: '.npmrc', patch: '+registry=https://malicious-registry.com/' }),
    ]
    const report = await runIntelAnalysis(files)
    expect(report.dependencies).toBeDefined()
    expect(report.securityDelta).toBeDefined()
    expect(report.securityDelta!.totalRiskChange).toBeGreaterThan(0)
  })
})

// === ATTACK 9: Trigger manipulation ===
describe('Red Team Attack #9: Trigger change', () => {
  it('detects pull_request_target usage', () => {
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: `+
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest` },
      ],
    })
    expect(result.anomalies.some(a => a.type === 'trigger_change')).toBe(true)
    expect(result.anomalies.some(a => a.severity === 'critical')).toBe(true)
  })
})

// === ATTACK 10: paths-ignore bypass ===
describe('Red Team Attack #10: Path exclusion', () => {
  it('detects suspicious paths-ignore addition', () => {
    const result = analyzeWorkflowIntelligence([], [], {
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: `+
on:
  pull_request:
    paths-ignore:
      - 'src/security/**'
      - 'package.json'` },
      ],
    })
    expect(result.anomalies.some(a => a.type === 'evasion')).toBe(true)
  })
})

// === BLUE TEAM Summary Generator ===
describe('Blue Team: CI Integrity Summary', () => {
  it('generates actionable integrity report from all attacks', () => {
    // Simulate running all attack vectors and aggregating
    const allAnomalies: string[] = []
    const results: { attack: string; score: number; findings: number }[] = []

    // Attack 1
    const r1 = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: { number: 99, jobs: [{ name: 'build', durationMs: 250000, steps: [] }, { name: 'test', durationMs: 188000, steps: [] }] },
      policy: { expectedWorkflows: [], minJobs: 3, expectedJobs: ['build', 'test', 'security'], maxDurationIncreasePct: 50, maxDurationDecreasePct: 30, requireArtifacts: false, sensitivePaths: [], allowedRunners: [] },
    })
    results.push({ attack: 'Job removal', score: r1.integrityScore, findings: r1.anomalies.length })
    allAnomalies.push(...r1.anomalies.map(a => `[${a.severity}] ${a.detail}`))

    // Attack 2
    const r2 = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: { number: 100, checkDurations: { build: 10000 } },
    })
    results.push({ attack: 'Duration manipulation', score: r2.integrityScore, findings: r2.anomalies.length })
    allAnomalies.push(...r2.anomalies.map(a => `[${a.severity}] ${a.detail}`))

    // Attack 3
    const r3 = analyzeWorkflowIntelligence(baselineRecords, [], {
      prFiles: [{ filename: '.github/workflows/ci.yml', patch: '+continue-on-error: true' }],
    })
    results.push({ attack: 'continue-on-error', score: r3.integrityScore, findings: r3.anomalies.length })
    allAnomalies.push(...r3.anomalies.map(a => `[${a.severity}] ${a.detail}`))

    // Verify the aggregated report has meaningful data
    expect(results.length).toBe(3)
    expect(allAnomalies.length).toBeGreaterThanOrEqual(3)
    // All attacks should have reduced integrity scores
    expect(results.every(r => r.score < 100)).toBe(true)
  })
})
