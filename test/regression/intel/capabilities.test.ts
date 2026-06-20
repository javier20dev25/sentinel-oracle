import { describe, it, expect } from 'vitest'
import { analyzeCapabilities } from '../../../src/scanner/intel/capabilities'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeCapabilities', () => {
  it('returns undefined for files without capabilities', () => {
    const result = analyzeCapabilities([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects filesystem access', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/fs.ts',
      patch: '+const data = fs.readFileSync("/etc/passwd")',
    })])
    expect(result).toBeDefined()
    expect(result!.filesystem).toContain('src/fs.ts')
    expect(result!.risk).toBe('medium')
  })

  it('detects network calls', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/net.ts',
      patch: '+const res = await fetch("https://example.com")',
    })])
    expect(result).toBeDefined()
    expect(result!.network).toContain('src/net.ts')
  })

  it('detects shell execution as critical', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/exec.ts',
      patch: '+const out = execSync("rm -rf /")',
    })])
    expect(result).toBeDefined()
    expect(result!.shell).toContain('src/exec.ts')
    expect(result!.risk).toBe('critical')
  })

  it('detects dynamic code execution', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/eval.ts',
      patch: '+eval(userInput)',
    })])
    expect(result).toBeDefined()
    expect(result!.dynamicCode).toContain('src/eval.ts')
  })

  it('detects database access', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/db.ts',
      patch: '+const rows = db.query("SELECT * FROM users")',
    })])
    expect(result).toBeDefined()
    expect(result!.database).toContain('src/db.ts')
  })

  it('detects crypto usage', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/crypto.ts',
      patch: '+const hash = crypto.createHash("sha256")',
    })])
    expect(result).toBeDefined()
    expect(result!.crypto).toContain('src/crypto.ts')
  })

  it('sets high risk when both filesystem and network are present', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/both.ts',
      patch: '+fs.readFileSync("/data")\n+fetch("https://c2.example.com")',
    })])
    expect(result!.risk).toBe('high')
  })

  it('sets critical risk when shell is present with other capabilities', () => {
    const result = analyzeCapabilities([makeFile({
      filename: 'src/all.ts',
      patch: '+exec("whoami")\n+fetch("https://c2.example.com")',
    })])
    expect(result!.risk).toBe('critical')
  })
})
