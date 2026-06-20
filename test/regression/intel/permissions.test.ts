import { describe, it, expect } from 'vitest'
import { analyzePermissions } from '../../../src/scanner/intel/permissions'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzePermissions', () => {
  it('returns undefined for non-workflow files', () => {
    const result = analyzePermissions([makeFile({ filename: 'src/index.ts', patch: '+permissions: write-all' })])
    expect(result).toBeUndefined()
  })

  it('detects permissions changes in workflows', () => {
    // permissions: must be on an added/removed line, not a context line
    const result = analyzePermissions([makeFile({
      filename: '.github/workflows/ci.yml',
      patch: `+permissions:
+  contents: write
+  issues: read`,
    })])
    expect(result).toBeDefined()
    expect(result!.file).toContain('ci.yml')
  })

  it('flags added write permissions as high risk', () => {
    const result = analyzePermissions([makeFile({
      filename: '.github/workflows/ci.yml',
      patch: `@@ ... @@
+permissions:
+  contents: write
`,
    })])
    expect(result).toBeDefined()
    expect(result!.addedPermissions).toContain('contents')
    expect(result!.risk).toBe('high')
  })
})

describe('parsePermissionsBlock internal', () => {
  it('detects contents write permission', () => {
    const result = analyzePermissions([makeFile({
      filename: '.github/workflows/ci.yml',
      patch: `+permissions:
+  contents: write`,
    })])
    expect(result).toBeDefined()
    expect(result!.risk).toBe('high')
  })

  it('detects id-token write', () => {
    const result = analyzePermissions([makeFile({
      filename: '.github/workflows/deploy.yml',
      patch: `+permissions:
+  id-token: write`,
    })])
    expect(result).toBeDefined()
    expect(result!.risk).toBe('high')
  })

  it('assigns medium risk for readonly permissions', () => {
    const result = analyzePermissions([makeFile({
      filename: '.github/workflows/ci.yml',
      patch: `+permissions:
+  contents: read`,
    })])
    expect(result).toBeDefined()
    expect(result!.risk).toBe('medium')
  })

  it('returns undefined for non-workflow files', () => {
    const result = analyzePermissions([makeFile({
      filename: 'src/app.ts',
      patch: '+console.log("hello")',
    })])
    expect(result).toBeUndefined()
  })
})
