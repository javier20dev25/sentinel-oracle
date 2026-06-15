import { describe, it, expect } from 'vitest'
import { scanPRFiles } from '../src/scanner/index'
import type { PRFile } from '../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return {
    status: 'modified',
    additions: 10,
    deletions: 0,
    patch: '',
    contents_url: '',
    ...overrides,
  }
}

describe('scanPRFiles', () => {
  it('returns empty findings for a clean PR', () => {
    const result = scanPRFiles([
      makeFile({ filename: 'src/index.ts', patch: '+console.log("hello")' }),
    ])
    expect(result.findings).toHaveLength(0)
    expect(result.riskScore).toBe(0)
  })

  it('detects pull_request_target in workflow files', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.github/workflows/ci.yml',
        patch: `+
on:
  pull_request_target:
    types: [opened]`,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'pull_request_target trigger detected')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('critical')
  })

  it('does not flag pull_request_target in non-workflow files', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'docs/notes.md',
        patch: '+pull_request_target is dangerous',
      }),
    ])
    expect(result.findings.filter(f => f.title === 'pull_request_target trigger detected')).toHaveLength(0)
  })

  it('detects write-all permissions in workflows', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.github/workflows/deploy.yml',
        patch: `+permissions: write-all`,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Excessive CI permissions')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('high')
  })

  it('detects hardcoded GitHub PATs', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'src/config.ts',
        patch: '+const token = "ghp_abcdef123456789012345678901234567890"',
      }),
    ])
    const finding = result.findings.find(f => f.category === 'secret')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('high')
  })

  it('detects hardcoded AWS keys', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.env',
        patch: '+AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE',
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Hardcoded secret detected')
    expect(finding).toBeTruthy()
  })

  it('detects private keys', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'key.pem',
        patch: '+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA',
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Hardcoded secret detected')
    expect(finding).toBeTruthy()
  })

  it('detects actions pinned to mutable tags', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.github/workflows/ci.yml',
        patch: `+      - uses: actions/checkout@v3`,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Action pinned to mutable tag')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('medium')
  })

  it('does not flag actions pinned to SHA', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.github/workflows/ci.yml',
        patch: '+      - uses: actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Action pinned to mutable tag')
    expect(finding).toBeUndefined()
  })

  it('detects secrets exposed in CI env', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.github/workflows/deploy.yml',
        patch: `+        env:
+          API_KEY: \${{ secrets.API_KEY }}`,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Secret exposed in CI environment')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('high')
  })

  it('detects .env file additions', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.env',
        patch: '+DATABASE_URL=postgres://localhost',
        additions: 1,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Environment file committed')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('medium')
  })

  it('detects binary file additions', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'dist/app.exe',
        additions: 0,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Binary file added')
    expect(finding).toBeTruthy()
  })

  it('detects large files', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'data/big.json',
        additions: 600,
      }),
    ])
    const finding = result.findings.find(f => f.title === 'Large file added')
    expect(finding).toBeTruthy()
    expect(finding!.severity).toBe('low')
  })

  it('calculates risk score correctly', () => {
    const result = scanPRFiles([
      makeFile({
        filename: '.github/workflows/ci.yml',
        patch: `+
on:
  pull_request_target:
permissions: write-all`,
      }),
    ])
    expect(result.critical).toBe(1)
    expect(result.high).toBe(1)
    expect(result.riskScore).toBe(30)
  })

  it('handles multiple files', () => {
    const result = scanPRFiles([
      makeFile({ filename: 'src/ok.ts', patch: '+const x = 1' }),
      makeFile({
        filename: '.github/workflows/deploy.yml',
        patch: `+      - uses: actions/checkout@v3`,
      }),
    ])
    expect(result.findings.length).toBeGreaterThanOrEqual(1)
  })

  it('includes code snippet and line number for findings', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'src/config.ts',
        patch: '+const token = "ghp_abcdef123456789012345678901234567890"',
      }),
    ])
    const finding = result.findings.find(f => f.category === 'secret')
    expect(finding).toBeTruthy()
    expect(finding!.code).toBeTruthy()
    expect(finding!.code).toContain('ghp_')
    expect(finding!.line).toBeGreaterThan(0)
  })

  it('includes PR URL when prNumber/owner/repo/sha are provided', () => {
    const result = scanPRFiles(
      [
        makeFile({
          filename: 'src/config.ts',
          patch: '+const token = "ghp_abcdef123456789012345678901234567890"',
        }),
      ],
      42,
      'my-owner',
      'my-repo',
      'abc123def456'
    )
    const finding = result.findings.find(f => f.category === 'secret')
    expect(finding).toBeTruthy()
    expect(finding!.prUrl).toBe(
      'https://github.com/my-owner/my-repo/blob/abc123def456/src/config.ts#L1'
    )
  })

  it('truncates secret code snippet to 80 chars', () => {
    const result = scanPRFiles([
      makeFile({
        filename: 'src/config.ts',
        patch: '+const token = "ghp_abcdef123456789012345678901234567890" + " and some extra padding to push this line well beyond eighty characters for the code field"',
      }),
    ])
    const finding = result.findings.find(f => f.category === 'secret')
    expect(finding).toBeTruthy()
    expect(finding!.code!.length).toBeLessThanOrEqual(80)
  })

  it('handles empty patch gracefully', () => {
    const result = scanPRFiles([
      { filename: 'src/index.ts', status: 'modified', additions: 5, deletions: 0, contents_url: '' },
    ])
    expect(result.findings).toHaveLength(0)
  })
})
