import { describe, it, expect } from 'vitest'
import { analyzeAuth } from '../../../src/scanner/intel/auth'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeAuth', () => {
  it('returns undefined for files without auth changes', () => {
    const result = analyzeAuth([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects new routes', () => {
    const result = analyzeAuth([makeFile({
      filename: 'src/routes.ts',
      patch: '+router.get("/api/users", handler)',
    })])
    expect(result).toBeDefined()
    expect(result!.newRoutes.length).toBeGreaterThanOrEqual(1)
    expect(result!.newRoutes[0].path).toBe('/api/users')
    expect(result!.newRoutes[0].method).toBe('GET')
  })

  it('detects auth bypass patterns', () => {
    const result = analyzeAuth([makeFile({
      filename: 'src/routes.ts',
      patch: '+router.get("/admin", skipAuth, adminHandler)',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.length).toBeGreaterThanOrEqual(1)
    expect(result!.changes[0].description).toContain('skipAuth')
    expect(result!.risk).toBe('critical')
  })

  it('detects new POST route', () => {
    const result = analyzeAuth([makeFile({
      filename: 'src/api.ts',
      patch: '+app.post("/api/data", handler)',
    })])
    expect(result).toBeDefined()
    expect(result!.newRoutes.length).toBeGreaterThanOrEqual(1)
    expect(result!.newRoutes[0].method).toBe('POST')
  })
})
