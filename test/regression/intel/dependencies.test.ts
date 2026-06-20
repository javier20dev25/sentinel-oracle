import { describe, it, expect } from 'vitest'
import { analyzeDependencies } from '../../../src/scanner/intel/dependencies'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeDependencies', () => {
  it('returns undefined for non-manifest files', () => {
    const result = analyzeDependencies([makeFile({ filename: 'src/index.ts', patch: '+console.log("hi")' })])
    expect(result).toBeUndefined()
  })

  it('detects added npm packages', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'package.json',
      patch: '+"express": "^5.0.0"',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('express')
    // version is stripped of ^/~ prefix
    expect(result!.added[0].version).toBe('5.0.0')
  })

  it('detects removed npm packages', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'package.json',
      patch: '-"lodash": "^4.17.21"',
    })])
    expect(result).toBeDefined()
    expect(result!.removed).toHaveLength(1)
    expect(result!.removed[0].name).toBe('lodash')
  })

  it('detects updated packages (add+remove same name)', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'package.json',
      patch: '-\"axios\": \"^1.6.0\"\n+\"axios\": \"^1.12.0\"',
    })])
    expect(result).toBeDefined()
    expect(result!.updated).toHaveLength(1)
    expect(result!.updated[0].name).toBe('axios')
    expect(result!.updated[0].fromVersion).toBe('1.6.0')
    expect(result!.updated[0].toVersion).toBe('1.12.0')
  })

  it('flags major version bump as risk signal', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'package.json',
      patch: '-\"express\": \"^4.0.0\"\n+\"express\": \"^5.0.0\"',
    })])
    expect(result).toBeDefined()
    expect(result!.updated).toHaveLength(1)
    expect(result!.updated[0].isMajor).toBe(true)
    expect(result!.riskSignals).toHaveLength(1)
    expect(result!.riskSignals[0].risk).toBe('high')
  })

  it('detects added Python packages', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'requirements.txt',
      patch: '+flask>=2.3.0',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('flask')
    expect(result!.added[0].version).toBe('2.3.0')
  })

  it('detects added Go modules', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'go.mod',
      patch: '+github.com/gin-gonic/gin v1.9.1',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('github.com/gin-gonic/gin')
  })

  it('detects added Cargo dependencies', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'Cargo.toml',
      patch: '+serde = "1.0.0"',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('serde')
  })

  it('flags pre-release versions', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'package.json',
      patch: '+"unstable-pkg": "^0.1.0-alpha.1"',
    })])
    expect(result).toBeDefined()
    expect(result!.riskSignals).toHaveLength(1)
    expect(result!.riskSignals[0].signal).toContain('Pre-release')
  })

  it('sets risk to high for major version bumps', () => {
    const result = analyzeDependencies([makeFile({
      filename: 'package.json',
      patch: '-\"react\": \"^17.0.0\"\n+\"react\": \"^18.0.0"',
    })])
    expect(result!.risk).toBe('high')
  })
})
