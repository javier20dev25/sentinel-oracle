import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { InMemoryContentIntelStore } from '../../../src/scanner/intel/content-intel/store'
import { signRecord, type ContentIntelEvidence } from '../../../src/scanner/intel/content-intel/record'
import { enrichContentIntel } from '../../../src/scanner/intel/cloud-lookup'
import type { IntelRisk } from '../../../src/scanner/intel/types'

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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

function stubCloud(body: unknown): ReturnType<typeof vi.fn> {
  const mock = vi.fn(async () => jsonResponse(200, body))
  vi.stubGlobal('fetch', mock)
  return mock
}

function hit(verdict: 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS'): Record<string, unknown> {
  return { contentId: ID, found: true, usable: true, verdict }
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_CLOUD_URL', '')
  vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', '')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('enrichContentIntel', () => {
  it('returns null when the store is null or the contentId is empty', async () => {
    expect(await enrichContentIntel(null, ID, { baseUrl: BASE, token: TOKEN })).toBeNull()
    const store = new InMemoryContentIntelStore(KEY)
    expect(await enrichContentIntel(store, '', { baseUrl: BASE, token: TOKEN })).toBeNull()
  })

  it('is a noop when there is no local record and never records one', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    stubCloud(hit('MALICIOUS'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('noop')
    expect(store.lookup(ID)).toBeNull()
  })

  it('upgrades a KNOWN_SAFE record to MALICIOUS from the cloud', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'), { repoKey: 'a/b' })
    stubCloud(hit('MALICIOUS'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN, repoKey: 'a/b' })).toBe('upgrade')
    expect(store.lookup(ID)?.state).toBe('MALICIOUS')
  })

  it('marks an UNKNOWN record SUSPICIOUS from the cloud', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.put(signRecord({
      contentId: ID,
      state: 'UNKNOWN',
      stateSince: 1,
      firstSeen: 1,
      lastSeen: 1,
      seenInRepoCount: 0,
      seenRepoKeys: [],
      scannerVersion: 'test',
      verified: false,
      evidence: evidence(),
      signer: '',
    }, KEY, 'test'))
    stubCloud(hit('SUSPICIOUS'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('enriched')
    expect(store.lookup(ID)?.state).toBe('SUSPICIOUS')
  })

  it('never downgrades a MALICIOUS record from a KNOWN_SAFE cloud hit', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'MALICIOUS', evidence('critical'), { repoKey: 'a/b' })
    stubCloud(hit('KNOWN_SAFE'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('noop')
    expect(store.lookup(ID)?.state).toBe('MALICIOUS')
  })

  it('never downgrades a SUSPICIOUS record from a KNOWN_SAFE cloud hit', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'SUSPICIOUS', evidence('medium'), { repoKey: 'a/b' })
    stubCloud(hit('KNOWN_SAFE'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('noop')
    expect(store.lookup(ID)?.state).toBe('SUSPICIOUS')
  })

  it('never applies a KNOWN_SAFE cloud hit to a KNOWN_SAFE local record', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'), { repoKey: 'a/b' })
    stubCloud(hit('KNOWN_SAFE'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('noop')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('leaves the store untouched on unusable, miss and error', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'), { repoKey: 'a/b' })

    stubCloud({ contentId: ID, found: true, usable: false, reason: 'scanner too old' })
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')

    stubCloud({ contentId: ID, found: false })
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('noop')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')

    stubCloud({ contentId: ID, found: true, usable: true, verdict: 'BENIGN' })
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('returns unavailable when the cloud is not configured and never throws', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'))
    expect(await enrichContentIntel(store, ID)).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('returns unavailable when the lookup fails at the network layer and never throws', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'))
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('ECONNREFUSED')
    }))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })
})
