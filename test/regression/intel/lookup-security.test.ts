import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs'
import path from 'path'
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

function hit(verdict: 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS', extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { contentId: ID, found: true, usable: true, verdict, ...extra }
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_CLOUD_URL', '')
  vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', '')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('enrichment fail-closed rules (adversarial)', () => {
  it('gherkin: "login exitoso" — a valid credential upgrades KNOWN_SAFE -> MALICIOUS', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'), { repoKey: 'a/b' })
    stubCloud(hit('MALICIOUS'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN, repoKey: 'a/b' })).toBe('upgrade')
    expect(store.lookup(ID)?.state).toBe('MALICIOUS')
  })

  it('gherkin: "token inválido" — a 401 is an error, never a miss, and the store stays untouched', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'))
    stubCloud({ found: false })
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(401, { found: false })))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('gherkin: "Cloud offline" — a network failure is an error and the store stays untouched', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'))
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('ECONNREFUSED')
    }))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('gherkin: "hit de caché" — an existing cached verdict is kept when the cloud agrees (noop)', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'MALICIOUS', evidence('critical'), { repoKey: 'a/b' })
    stubCloud(hit('MALICIOUS'))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('noop')
    expect(store.lookup(ID)?.state).toBe('MALICIOUS')
  })

  it('gherkin: "revalidación por revocación" — an unusable/revoked cloud record never touches the store', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'))
    stubCloud({ contentId: ID, found: true, usable: false, reason: 'revoked' })
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('a broken signature is an error and the store stays untouched', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'))
    stubCloud(hit('MALICIOUS', { signature: 'zz-not-hex' }))
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
    expect(store.lookup(ID)?.state).toBe('KNOWN_SAFE')
  })

  it('a missing signature is accepted and may upgrade the record (documents current behavior)', async () => {
    const store = new InMemoryContentIntelStore(KEY)
    store.record(ID, 'KNOWN_SAFE', evidence('low'), { repoKey: 'a/b' })
    stubCloud({ contentId: ID, found: true, usable: true, verdict: 'MALICIOUS' })
    expect(await enrichContentIntel(store, ID, { baseUrl: BASE, token: TOKEN })).toBe('upgrade')
    expect(store.lookup(ID)?.state).toBe('MALICIOUS')
  })

  it('SCANNING and UNKNOWN records can be upgraded by SUSPICIOUS/MALICIOUS cloud hits', async () => {
    for (const state of ['SCANNING', 'UNKNOWN'] as const) {
      const store = new InMemoryContentIntelStore(KEY)
      store.put(signRecord({
        contentId: ID,
        state,
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
    }
  })
})

describe('enrichment hook wiring (static guards)', () => {
  const hookSrc = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'src', 'scanner', 'intel', 'index.ts'), 'utf8')

  it('the cloud enrichment hook is fire-and-forget: void + .catch, never awaited', () => {
    const start = hookSrc.indexOf('if (contentIntelStore && hasCloudConnection')
    const end = hookSrc.indexOf('.catch(() => {})', start) + '.catch(() => {})'.length
    expect(start).toBeGreaterThan(-1)
    const hookBlock = hookSrc.slice(start, end)
    expect(hookBlock).toContain('hasCloudConnection()')
    expect(hookBlock).toContain('void enrichContentIntel(')
    expect(hookBlock).toContain('.then(outcome =>')
    expect(hookBlock).toContain('.catch(() => {})')
    expect(hookBlock).not.toMatch(/await\s+enrichContentIntel/)
  })

  it('the hook reads the cloud connection from env only — config.cloudApiUrl/cloudApiToken are never consumed', () => {
    const start = hookSrc.indexOf('if (contentIntelStore && hasCloudConnection')
    const end = hookSrc.indexOf('.catch(() => {})', start) + '.catch(() => {})'.length
    const hookBlock = hookSrc.slice(start, end)
    expect(hookBlock).not.toMatch(/baseUrl/)
    expect(hookBlock).not.toMatch(/token:/)
    expect(hookBlock).not.toMatch(/cloudApiUrl|cloudApiToken/)
  })

  it('no other call site awaits enrichContentIntel or lookupCloud in a blocking path', () => {
    expect(hookSrc).not.toMatch(/await\s+enrichContentIntel/)
  })
})
