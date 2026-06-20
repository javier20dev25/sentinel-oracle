import { describe, it, expect } from 'vitest'
import { runIntelAnalysis } from '../../../src/scanner/intel/index'
import { scanPRFiles } from '../../../src/scanner/index'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('runIntelAnalysis', () => {
  it('returns empty report for clean files', async () => {
    const result = await runIntelAnalysis([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(Object.keys(result).filter(k => k !== 'securityDelta')).toHaveLength(0)
  })

  it('runs all analyzers on mixed file set', async () => {
    const result = await runIntelAnalysis([
      makeFile({ filename: 'package.json', patch: '+"express": "^4.0.0"' }),
      makeFile({ filename: 'src/api.ts', patch: '+fetch("https://unknown.xyz/data")' }),
      makeFile({ filename: 'Dockerfile', patch: '+FROM node:latest' }),
    ])
    expect(result.dependencies).toBeDefined()
    expect(result.endpoints).toBeDefined()
    expect(result.infrastructure).toBeDefined()
  })

  it('detects dependency + endpoint + infra in same report', async () => {
    const result = await runIntelAnalysis([
      makeFile({ filename: 'go.mod', patch: '+github.com/gin-gonic/gin v1.9.1' }),
      makeFile({ filename: 'src/main.go', patch: '+resp, err := http.Get("https://c2.ru/beacon")' }),
      makeFile({ filename: 'Dockerfile', patch: '+USER root' }),
    ])
    expect(result.dependencies).toBeDefined()
    expect(result.endpoints).toBeDefined()
    expect(result.infrastructure).toBeDefined()
    expect(result.dependencies!.added).toHaveLength(1)
    expect(result.endpoints!.suspicious.length).toBeGreaterThanOrEqual(1)
    expect(result.infrastructure!.changes.some(c => c.aspect.includes('Root user'))).toBe(true)
  })
})

describe('scanPRFiles intel integration', () => {
  it('attaches intel to scan result', async () => {
    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"axios": "^1.12.0"' }),
    ])
    expect(result.intel).toBeDefined()
    expect(result.intel!.dependencies).toBeDefined()
  })

  it('does not attach intel when no modules fire', async () => {
    const result = await scanPRFiles([
      makeFile({ filename: 'src/index.ts', patch: '+const x = 1' }),
    ])
    expect(result.intel).toBeUndefined()
  })
})

describe('buildSecurityDelta internal', () => {
  it('produces security delta from intel report', async () => {
    const result = await runIntelAnalysis([makeFile({
      filename: 'src/api.ts',
      status: 'added',
      additions: 30,
      patch: `+app.get("/new-endpoint")
+fetch("https://evil.example.com")
+exec("curl")`,
    })])
    expect(result.securityDelta).toBeDefined()
    expect(result.securityDelta!.totalRiskChange).toBeGreaterThanOrEqual(3)
  })

  it('produces low delta for clean files', async () => {
    const result = await runIntelAnalysis([makeFile({
      filename: 'src/hello.ts',
      status: 'added',
      additions: 5,
      patch: `+const x = 1
+console.log(x)`,
    })])
    expect(result.securityDelta).toBeDefined()
    expect(result.securityDelta!.totalRiskChange).toBeLessThanOrEqual(2)
  })
})

describe('inferRegistry internal', () => {
  it('infers npm for hyphenated names', async () => {
    const result = await runIntelAnalysis([makeFile({
      filename: 'package.json',
      status: 'modified',
      additions: 3,
      patch: `+
+"@scope/pkg": "^1.0.0"
+"simple-dep": "^2.0.0"
-"old-dep": "^0.5.0"`,
    })])
    expect(result.dependencies).toBeDefined()
  })
})
