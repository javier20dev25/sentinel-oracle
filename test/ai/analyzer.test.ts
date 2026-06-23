import { describe, it, expect } from 'vitest'
import { analyzePR, computeScanHash } from '../../src/ai/analyzer'
import type { PRFile } from '../../src/github/client'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return {
    sha: 'abc123',
    status: 'modified',
    additions: 10,
    deletions: 0,
    patch: '',
    contents_url: '',
    raw_url: '',
    blob_url: '',
    ...overrides,
  }
}

const mockDb = {
  getLatestScanResult: () => null,
  getPRFiles: () => [],
} as any

describe('analyzePR', () => {
  it('returns a basic analysis for an empty PR', async () => {
    const result = await analyzePR(1, 'Test PR', 'author', 'body', 'main', 'feature', [], 'sha1', mockDb)
    expect(result.prNumber).toBe(1)
    expect(result.executiveSummary.length).toBeGreaterThan(0)
    expect(result.scanHash).toBeTruthy()
    expect(result.priority.reviewPriority).toBe('low')
  })

  it('detects security-relevant files', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'src/auth/login.ts', additions: 20 }),
      makeFile({ filename: 'src/utils/helper.ts', additions: 5 }),
    ]
    const result = await analyzePR(2, 'Auth update', 'dev', '', 'main', 'feat', files, 'sha2', mockDb)
    expect(result.priority.reviewPriority).toBe('critical')
    expect(result.reviewHotspots.length).toBeGreaterThan(0)
    expect(result.reviewHotspots[0].file).toContain('auth')
  })

  it('detects config changes', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'config.yml', additions: 3 }),
      makeFile({ filename: 'src/index.ts', additions: 1 }),
    ]
    const result = await analyzePR(3, 'Config update', 'dev', '', 'main', 'feat', files, 'sha3', mockDb)
    expect(result.priority.reviewPriority).toBe('high')
  })

  it('detects dependency changes', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'package.json', additions: 2, deletions: 1 }),
    ]
    const result = await analyzePR(4, 'Update deps', 'bot', '', 'main', 'feat', files, 'sha4', mockDb)
    expect(result.dependencies.length).toBeGreaterThan(0)
    expect(result.dependencies[0].name).toBe('package.json')
  })

  it('computes consistent scan hashes', () => {
    const files = [
      { filename: 'a.ts', patch: '+foo', status: 'modified', additions: 1, deletions: 0 },
      { filename: 'b.ts', patch: '+bar', status: 'modified', additions: 1, deletions: 0 },
    ]
    const hash1 = computeScanHash(files, 'sha1')
    const hash2 = computeScanHash(files, 'sha1')
    expect(hash1).toBe(hash2)
  })

  it('computes different hashes for different content', () => {
    const files1 = [{ filename: 'a.ts', patch: '+foo', status: 'modified', additions: 1, deletions: 0 }]
    const files2 = [{ filename: 'a.ts', patch: '+bar', status: 'modified', additions: 1, deletions: 0 }]
    const hash1 = computeScanHash(files1, 'sha1')
    const hash2 = computeScanHash(files2, 'sha1')
    expect(hash1).not.toBe(hash2)
  })
})
