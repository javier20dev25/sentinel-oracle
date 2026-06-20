import { describe, it, expect } from 'vitest'
import { analyzeInfrastructure } from '../../../src/scanner/intel/infrastructure'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeInfrastructure', () => {
  it('returns undefined for non-infra files', () => {
    const result = analyzeInfrastructure([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects root user in Dockerfile', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 'Dockerfile',
      patch: '+\nUSER root\n',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Root user'))).toBe(true)
    expect(result!.risk).toBe('critical')
  })

  it('detects port exposure', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 'Dockerfile',
      patch: '+\nEXPOSE 8080\n',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Exposed port'))).toBe(true)
  })

  it('detects latest tag usage', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 'Dockerfile',
      patch: '+FROM node:latest',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Latest tag'))).toBe(true)
    expect(result!.risk).toBe('medium')
  })

  it('detects hardcoded secrets in Terraform', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 'main.tf',
      patch: '+resource "aws_db_instance" "db" {\n+  password = "supersecret123"\n+}',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Hardcoded secret'))).toBe(true)
    expect(result!.risk).toBe('critical')
  })

  it('detects privileged containers in K8s', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 'deployment.yaml',
      patch: '+      privileged: true',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Privileged container'))).toBe(true)
    expect(result!.risk).toBe('critical')
  })

  it('detects public S3 bucket in Terraform', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 's3.tf',
      patch: '+  acl = "public-read"',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Public S3'))).toBe(true)
    expect(result!.risk).toBe('critical')
  })

  it('detects .git exposure in nginx', () => {
    const result = analyzeInfrastructure([makeFile({
      filename: 'nginx.conf',
      patch: '+  location ~ /\.git { deny all; }',
    })])
    expect(result).toBeDefined()
    expect(result!.changes.some(c => c.aspect.includes('Exposed'))).toBe(true)
    expect(result!.risk).toBe('critical')
  })
})
