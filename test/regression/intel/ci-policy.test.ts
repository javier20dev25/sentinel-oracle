import { describe, it, expect } from 'vitest'
import { parsePolicy, detectPolicyInFiles } from '../../../src/scanner/intel/ci-policy'

describe('parsePolicy', () => {
  it('returns default policy for empty input', () => {
    const p = parsePolicy(null)
    expect(p.minJobs).toBe(1)
    expect(p.expectedJobs).toEqual([])
    expect(p.maxDurationDecreasePct).toBe(30)
  })

  it('parses sentinel policy from raw object', () => {
    const raw = {
      sentinel: {
        min_jobs: 3,
        expected_jobs: ['build', 'test', 'security'],
        max_duration_increase_pct: 60,
        allowed_runners: ['ubuntu-latest'],
      },
    }
    const p = parsePolicy(raw)
    expect(p.minJobs).toBe(3)
    expect(p.expectedJobs).toHaveLength(3)
    expect(p.maxDurationIncreasePct).toBe(60)
  })
})

describe('detectPolicyInFiles', () => {
  it('returns undefined for no policy file', () => {
    const files = [{ filename: 'src/index.ts', patch: '+const x = 1' }]
    const result = detectPolicyInFiles(files)
    expect(result.policy).toBeUndefined()
  })

  it('detects sentinel.policy.yml in PR files', () => {
    const files = [
      { filename: 'sentinel.policy.yml', patch: `+sentinel:
+  min_jobs: 3
+  expected_jobs:
+    - build` },
      { filename: 'src/index.ts', patch: '+const x = 1' },
    ]
    const result = detectPolicyInFiles(files)
    expect(result.policy).toBeDefined()
    expect(result.sourceFile).toBe('sentinel.policy.yml')
  })
})
