import { describe, it, expect } from 'vitest'
import { analyzeEndpoints } from '../../../src/scanner/intel/endpoints'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeEndpoints', () => {
  it('returns undefined for files without URLs', () => {
    const result = analyzeEndpoints([makeFile({ filename: 'index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects new HTTP endpoints', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/api.ts',
      patch: '+const res = await fetch("https://api.example.com/data")',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].url).toContain('api.example.com')
  })

  it('marks IP addresses as suspicious', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/config.ts',
      patch: '+const url = "http://192.168.1.1:8080/api"',
    })])
    expect(result).toBeDefined()
    expect(result!.suspicious).toHaveLength(1)
    expect(result!.suspicious[0].reason).toContain('IP address')
    expect(result!.risk).toBe('high')
  })

  it('does not flag known domains', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/api.ts',
      patch: '+await fetch("https://api.github.com/repos")',
    })])
    expect(result).toBeDefined()
    expect(result!.suspicious).toHaveLength(0)
    expect(result!.risk).toBe('low')
  })

  it('flags suspicious TLDs', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/download.ts',
      patch: '+const url = "https://malicious.ru/payload"',
    })])
    expect(result).toBeDefined()
    expect(result!.suspicious).toHaveLength(1)
    expect(result!.suspicious[0].reason).toContain('Suspicious TLD')
  })
})

describe('isIpAddress / extractUrl internal', () => {
  it('flags raw IP addresses as suspicious', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/config.ts',
      patch: '+const API = "http://192.168.1.1/api"',
    })])
    expect(result).toBeDefined()
    expect(result!.suspicious.length).toBeGreaterThanOrEqual(1)
  })

  it('flags internal 10.x addresses', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/config.ts',
      patch: '+const DB = "http://10.0.0.5:5432"',
    })])
    expect(result).toBeDefined()
    expect(result!.suspicious.length).toBeGreaterThanOrEqual(1)
  })

  it('does not flag known cloud domains', () => {
    const result = analyzeEndpoints([makeFile({
      filename: 'src/api.ts',
      patch: '+fetch("https://api.github.com/repos")',
    })])
    expect(result).toBeDefined()
    expect(result!.suspicious || []).toHaveLength(0)
  })
})
