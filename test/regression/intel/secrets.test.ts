import { describe, it, expect } from 'vitest'
import { analyzeSecrets } from '../../../src/scanner/intel/secrets'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeSecrets', () => {
  it('returns undefined for files without env access', () => {
    const result = analyzeSecrets([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects access to sensitive env vars', () => {
    const result = analyzeSecrets([makeFile({
      filename: 'src/config.ts',
      patch: '+const key = process.env.API_SECRET',
    })])
    expect(result).toBeDefined()
    // process.env.X can match multiple regex patterns (process.env.X and env.X)
    expect(result!.sources.some(s => s.var === 'API_SECRET')).toBe(true)
  })

  it('detects multiple sensitive vars', () => {
    const result = analyzeSecrets([makeFile({
      filename: 'src/config.ts',
      patch: '+const token = process.env.GITHUB_TOKEN\n+const key = process.env.API_KEY',
    })])
    expect(result).toBeDefined()
    expect(result!.sources.some(s => s.var === 'GITHUB_TOKEN')).toBe(true)
    expect(result!.sources.some(s => s.var === 'API_KEY')).toBe(true)
  })

  it('tracks all env var usage as consumers', () => {
    const result = analyzeSecrets([makeFile({
      filename: 'src/config.ts',
      patch: '+const dbUrl = process.env.DATABASE_URL',
    })])
    expect(result).toBeDefined()
    expect(result!.consumers.some(c => c.var === 'DATABASE_URL')).toBe(true)
  })
})
