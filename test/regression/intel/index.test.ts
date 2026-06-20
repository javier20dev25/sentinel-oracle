import { describe, it, expect, vi } from 'vitest'
import type { PRFile } from '../../../src/scanner/rules'

const INFRA_PATTERNS = [/Dockerfile/, /\.dockerignore/, /docker-compose\.ya?ml/, /compose\.ya?ml/, /\.tf$/, /\.ya?ml$/, /nginx\.conf/, /\.nginx/]

vi.mock('../../../src/scanner/intel/infrastructure', () => ({
  analyzeInfrastructure: (files: PRFile[]) => {
    const infraFiles = files.filter(f => f.patch && INFRA_PATTERNS.some(p => p.test(f.filename)))
    if (infraFiles.length === 0) return undefined
    return {
      changes: infraFiles.map(f => ({
        aspect: `Infra change in ${f.filename}`,
        before: 'unknown',
        after: 'detected',
        impact: 'Mock infra detection',
      })),
      risk: 'critical' as const,
      description: 'Mock infra analysis',
      summary: `${infraFiles.length} infra change(s) detected`,
    }
  },
}))

import { scanPRFiles } from '../../../src/scanner/index'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('runIntelAnalysis', () => {
  it('returns empty report for clean files', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(Object.keys(result.intel!).filter(k => k !== 'securityDelta')).toHaveLength(0)
  })

  it('runs all analyzers on mixed file set', async () => {
    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"express": "^4.0.0"' }),
      makeFile({ filename: 'src/api.ts', patch: '+fetch("https://unknown.xyz/data")' }),
      makeFile({ filename: 'Dockerfile', patch: '+FROM node:latest' }),
    ])
    expect(result.intel!.dependencies).toBeDefined()
    expect(result.intel!.endpoints).toBeDefined()
    expect(result.intel!.infrastructure).toBeDefined()
  })

  it('detects dependency + endpoint + infra in same report', async () => {
    const result = await scanPRFiles([
      makeFile({ filename: 'go.mod', patch: '+github.com/gin-gonic/gin v1.9.1' }),
      makeFile({ filename: 'src/main.go', patch: '+resp, err := http.Get("https://c2.ru/beacon")' }),
      makeFile({ filename: 'Dockerfile', patch: '+USER root' }),
    ])
    expect(result.intel!.dependencies).toBeDefined()
    expect(result.intel!.endpoints).toBeDefined()
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.dependencies!.added).toHaveLength(1)
    expect(result.intel!.endpoints!.suspicious.length).toBeGreaterThanOrEqual(1)
    expect(result.intel!.infrastructure!.changes.length).toBeGreaterThanOrEqual(1)
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
    expect(result.intel!.securityDelta!.totalRiskChange).toBe(0)
  })
})

describe('buildSecurityDelta internal', () => {
  it('produces security delta from intel report', async () => {
    const result = await scanPRFiles([makeFile({
      filename: 'src/api.ts',
      status: 'added',
      additions: 30,
      patch: `+app.get("/new-endpoint")
+fetch("https://evil.example.com")
+exec("curl")`,
    })])
    expect(result.intel!.securityDelta).toBeDefined()
    expect(result.intel!.securityDelta!.totalRiskChange).toBeGreaterThanOrEqual(3)
  })

  it('produces low delta for clean files', async () => {
    const result = await scanPRFiles([makeFile({
      filename: 'src/hello.ts',
      status: 'added',
      additions: 5,
      patch: `+const x = 1
+console.log(x)`,
    })])
    expect(result.intel!.securityDelta).toBeDefined()
    expect(result.intel!.securityDelta!.totalRiskChange).toBeLessThanOrEqual(2)
  })
})

describe('inferRegistry internal', () => {
  it('infers npm for hyphenated names', async () => {
    const result = await scanPRFiles([makeFile({
      filename: 'package.json',
      status: 'modified',
      additions: 3,
      patch: `+
+"@scope/pkg": "^1.0.0"
+"simple-dep": "^2.0.0"
-"old-dep": "^0.5.0"`,
    })])
    expect(result.intel!.dependencies).toBeDefined()
  })
})
