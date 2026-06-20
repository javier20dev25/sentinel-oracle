import { describe, it, expect } from 'vitest'
import { analyzeCrypto } from '../../../src/scanner/intel/crypto'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeCrypto', () => {
  it('returns undefined for files without crypto changes', () => {
    const result = analyzeCrypto([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects bcrypt rounds change', () => {
    const result = analyzeCrypto([makeFile({
      filename: 'src/auth.ts',
      patch: '-const saltRounds = 10\n+const saltRounds = 8',
    })])
    expect(result).toBeDefined()
    expect(result!.changes).toHaveLength(1)
    expect(result!.changes[0].parameter).toBe('rounds')
    expect(result!.changes[0].before).toBe('10')
    expect(result!.changes[0].after).toBe('8')
    expect(result!.changes[0].impact).toContain('Reduced')
  })

  it('detects algorithm change to weak', () => {
    const result = analyzeCrypto([makeFile({
      filename: 'src/jwt.ts',
      patch: '-const algorithm = "RS256"\n+const algorithm = "HS256"',
    })])
    expect(result).toBeDefined()
    expect(result!.changes[0].parameter).toBe('algorithm')
  })

  it('detects token expiry change', () => {
    const result = analyzeCrypto([makeFile({
      filename: 'src/jwt.ts',
      patch: '-const expiresIn = 3600\n+const expiresIn = 86400',
    })])
    expect(result).toBeDefined()
    expect(result!.changes[0].parameter).toBe('expiry')
  })

  it('flags weak algorithms as critical', () => {
    const result = analyzeCrypto([makeFile({
      filename: 'src/hash.ts',
      patch: '-const algorithm = "sha256"\n+const algorithm = "md5"',
    })])
    expect(result!.risk).toBe('critical')
  })
})
