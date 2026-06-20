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

describe('analyzeInfrastructure via scanPRFiles', () => {
  it('returns no infra changes for non-infra files', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result.intel!.infrastructure).toBeUndefined()
  })

  it('detects root user in Dockerfile', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'Dockerfile', patch: '+\nUSER root\n' })])
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.infrastructure!.risk).toBe('critical')
  })

  it('detects port exposure', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'Dockerfile', patch: '+\nEXPOSE 8080\n' })])
    expect(result.intel!.infrastructure).toBeDefined()
  })

  it('detects latest tag usage', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'Dockerfile', patch: '+FROM node:latest' })])
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.infrastructure!.risk).toBe('critical')
  })

  it('detects hardcoded secrets in Terraform', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'main.tf', patch: '+resource "aws_db_instance" "db" {\n+  password = "supersecret123"\n+}' })])
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.infrastructure!.risk).toBe('critical')
  })

  it('detects privileged containers in K8s', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'deployment.yaml', patch: '+      privileged: true' })])
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.infrastructure!.risk).toBe('critical')
  })

  it('detects public S3 bucket in Terraform', async () => {
    const result = await scanPRFiles([makeFile({ filename: 's3.tf', patch: '+  acl = "public-read"' })])
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.infrastructure!.risk).toBe('critical')
  })

  it('detects .git exposure in nginx', async () => {
    const result = await scanPRFiles([makeFile({ filename: 'nginx.conf', patch: '+  location ~ /\.git { deny all; }' })])
    expect(result.intel!.infrastructure).toBeDefined()
    expect(result.intel!.infrastructure!.risk).toBe('critical')
  })
})
