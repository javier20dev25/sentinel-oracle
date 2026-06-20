import { describe, it, expect } from 'vitest'
import { analyzeServices } from '../../../src/scanner/intel/services'
import type { PRFile } from '../../../src/scanner/rules'

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('analyzeServices', () => {
  it('returns undefined for files without SDK imports', () => {
    const result = analyzeServices([makeFile({ filename: 'src/index.ts', patch: '+const x = 1' })])
    expect(result).toBeUndefined()
  })

  it('detects Stripe SDK', () => {
    const result = analyzeServices([makeFile({
      filename: 'src/payment.ts',
      patch: '+import Stripe from "stripe"',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('Stripe')
  })

  it('detects OpenAI SDK', () => {
    const result = analyzeServices([makeFile({
      filename: 'src/ai.ts',
      patch: '+import OpenAI from "openai"',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('OpenAI')
  })

  it('detects AWS SDK', () => {
    const result = analyzeServices([makeFile({
      filename: 'src/storage.ts',
      patch: '+import { S3Client } from "@aws-sdk/client-s3"',
    })])
    expect(result).toBeDefined()
    expect(result!.added).toHaveLength(1)
    expect(result!.added[0].name).toBe('AWS S3')
  })

  it('sets medium risk for cloud SDKs', () => {
    const result = analyzeServices([makeFile({
      filename: 'src/ai.ts',
      patch: '+import OpenAI from "openai"',
    })])
    expect(result!.risk).toBe('medium')
  })

  it('deduplicates repeated SDK imports', () => {
    const result = analyzeServices([makeFile({
      filename: 'src/payment.ts',
      patch: '+import Stripe from "stripe"\n+const s = require("stripe")',
    })])
    expect(result!.added).toHaveLength(1)
  })
})
