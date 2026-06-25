import { describe, it, expect, vi } from 'vitest'
import { analyzePR, computeScanHash, explainPR, explainScanFindings } from '../../src/ai/analyzer'
import type { PRFile } from '../../src/github/client'

let mockOllamaGenerateResponse = ''

vi.mock('../../src/ai/ollama', () => ({
  ollamaGenerate: vi.fn(async () => mockOllamaGenerateResponse),
  ollamaGenerateJSON: vi.fn(async () => null),
}))

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

describe('explainPR', () => {
  it('returns fallback explanation when model is auto or sentinel-ai-engine', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'src/main.ts', additions: 10, deletions: 2, status: 'modified' })
    ]
    const result = await explainPR(1, 'Test Title', 'author', files, 'auto')
    expect(result.summary).toContain('Se modificó src/main.ts (+10 -2)')
    expect(result.argumentation).toContain('Este PR modifica 1 archivo(s)')
  })

  it('uses ollama model when specified and parses sections correctly', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'src/main.ts', additions: 10, deletions: 2, status: 'modified' })
    ]
    mockOllamaGenerateResponse = `
## RESUMEN
• Added helper functions
• Cleaned up code

## ARGUMENTACIÓN
This PR does a bunch of cleanups to improve codebase health. We refactored main.ts.
`
    const result = await explainPR(1, 'Test Title', 'author', files, 'ollama:qwen')
    expect(result.summary).toEqual(['Added helper functions', 'Cleaned up code'])
    expect(result.argumentation).toContain('This PR does a bunch of cleanups')
  })

  it('falls back to file list summary if LLM response is invalid or missing sections', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'src/main.ts', additions: 10, deletions: 2, status: 'modified' })
    ]
    mockOllamaGenerateResponse = 'This is just a random plain text explanation with no headers.'
    const result = await explainPR(1, 'Test Title', 'author', files, 'ollama:qwen')
    expect(result.summary).toContain('Se modificó src/main.ts (+10 -2)')
    expect(result.argumentation).toBe('This is just a random plain text explanation with no headers.')
  })
})

describe('explainScanFindings', () => {
  it('returns fallback summary and argumentation when model is auto', async () => {
    const findings = [
      { severity: 'high', title: 'SQL Injection', file: 'db.ts', message: 'Raw query check' }
    ]
    const result = await explainScanFindings(1, 'Test Title', findings, 'auto')
    expect(result.summary[0]).toContain('HIGH: SQL Injection')
    expect(result.argumentation).toContain('El escaneo de seguridad detectó 1 hallazgo')
  })

  it('returns message for empty findings', async () => {
    const result = await explainScanFindings(1, 'Test Title', [], 'ollama:qwen')
    expect(result.summary[0]).toContain('No se detectaron hallazgos')
    expect(result.argumentation).toContain('El escaneo de seguridad no encontró patrones')
  })

  it('uses ollama model when specified and parses sections', async () => {
    const findings = [
      { severity: 'high', title: 'SQL Injection', file: 'db.ts', message: 'Raw query check' }
    ]
    mockOllamaGenerateResponse = `
## RESUMEN
• Critical SQL vulnerability found
• Immediate fix required

## ARGUMENTACIÓN
The SQL injection vulnerability in db.ts is highly critical because it allows unauthorized access to the database.
`
    const result = await explainScanFindings(1, 'Test Title', findings, 'ollama:qwen')
    expect(result.summary).toEqual(['Critical SQL vulnerability found', 'Immediate fix required'])
    expect(result.argumentation).toContain('The SQL injection vulnerability in db.ts')
  })
})
