import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { InMemoryContentIntelStore } from '../../../src/scanner/intel/content-intel/store'
import { signRecord, type ContentIntelEvidence } from '../../../src/scanner/intel/content-intel/record'
import { enrichContentIntel } from '../../../src/scanner/intel/cloud-lookup'
import type { IntelRisk } from '../../../src/scanner/intel/types'

vi.mock('../../../src/scanner/intel/content-intel/scanner-version', () => ({
  getScannerVersion: () => {
    throw new Error('boom')
  },
}))

const BASE = 'https://cloud.example'
const TOKEN = 'token-123'
const KEY = Buffer.alloc(32, 7)
const ID = 'sha512:' + 'c'.repeat(128)

function evidence(risk: IntelRisk = 'low'): ContentIntelEvidence {
  return {
    risk,
    filesChanged: 0,
    newDomains: [],
    newNetworkCalls: 0,
    newCapabilities: [],
    newScripts: [],
    newBinaries: [],
    lifecycleScripts: [],
    summary: 'test evidence',
    findings: [],
  }
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_CLOUD_URL', '')
  vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', '')
  vi.stubGlobal('fetch', vi.fn(async () => {
    return new Response(JSON.stringify({ contentId: ID, found: true, usable: true, verdict: 'MALICIOUS' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }))
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('enrichContentIntel resilience', () => {
  it('never throws even when an internal dependency (scannerVersion) throws', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.put(signRecord({
      contentId: ID,
      state: 'KNOWN_SAFE',
      stateSince: 1,
      firstSeen: 1,
      lastSeen: 1,
      seenInRepoCount: 0,
      seenRepoKeys: [],
      scannerVersion: 'test',
      verified: true,
      evidence: evidence('low'),
      signer: '',
    }, KEY, 'test'))
    const outcome = await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN, scannerVersion: 'v1' })
    expect(outcome).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })
})
