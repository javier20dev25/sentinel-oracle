import { describe, it, expect } from 'vitest'
import { analyzeTrustBoundaries } from '../../../src/scanner/intel/trust'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeTrustBoundaries', () => {
  it('returns undefined for clean code', () => {
    const result = analyzeTrustBoundaries([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects user input flowing to database query', () => {
    const result = analyzeTrustBoundaries([makeFile({
      filename: 'src/api.ts',
      patch: '+const id = req.body.id\n+db.query("SELECT * FROM users")',
    })])
    expect(result).toBeDefined()
    expect(result!.flows.length).toBeGreaterThanOrEqual(1)
    expect(result!.flows[0].source).toContain('req')
  })

  it('detects user input flowing to dangerous sink (exec)', () => {
    const result = analyzeTrustBoundaries([makeFile({
      filename: 'src/rce.ts',
      patch: '+app.get("/run", (req, res) => {\n+  const cmd = req.query.cmd\n+  exec(cmd)\n+})',
    })])
    expect(result).toBeDefined()
    expect(result!.risk).toBe('critical')
  })

  it('sets critical risk for exec sinks', () => {
    const result = analyzeTrustBoundaries([makeFile({
      filename: 'src/exec.ts',
      patch: '+const input = req.body.cmd\n+exec(input)',
    })])
    expect(result!.risk).toBe('critical')
  })
})
