import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs'
import path from 'path'
import type { Finding } from '../../../src/scanner/rules'
import type { TarballScanResult } from '../../../src/scanner/intel/deep-dependency'
import { contributeEvidence, contributeScanEvidence, CONTRIBUTE_ENDPOINT, buildContributePayload, MAX_429_RETRIES } from '../../../src/scanner/intel/cloud-contribute'

const BASE = 'https://cloud.example'
const TOKEN = 'sntl_test_pat_123'

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })
}

function stubFetch(impl: (url: string, init?: RequestInit) => Promise<Response> | Response): ReturnType<typeof vi.fn> {
  const mock = vi.fn(impl)
  vi.stubGlobal('fetch', mock)
  return mock
}

const okBody = {
  applied: true,
  contentId: 'sha512:' + 'b'.repeat(128),
  state: 'MALICIOUS',
  previousState: 'UNKNOWN',
  reason: null,
  scannerVersion: '1.0.2',
  verified: false,
}

const OPTS = {
  manifest: JSON.stringify({ name: 'evildep', version: '1.0.0' }),
  state: 'MALICIOUS' as const,
  risk: 'critical' as const,
  alerts: [{ type: 'supply_chain', severity: 'CRITICAL' as const, riskLevel: 9, message: 'x', category: 'supply_chain' }],
  deltas: [],
  baseUrl: BASE,
  token: TOKEN,
  maxRetries: 1,
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_CLOUD_URL', '')
  vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', '')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('contributeEvidence HTTP contract', () => {
  it('does not call fetch when the cloud is not configured', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(200, okBody))
    const outcome = await contributeEvidence({ ...OPTS, baseUrl: undefined, token: undefined })
    expect(outcome).toMatchObject({ kind: 'error' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('posts to /api/intelligence/contribute with Bearer PAT and the built payload', async () => {
    const fetchMock = stubFetch(async (url, init) => {
      expect(url).toBe(`${BASE}${CONTRIBUTE_ENDPOINT}`)
      expect(init?.method).toBe('POST')
      const headers = new Headers(init?.headers)
      expect(headers.get('authorization')).toBe(`Bearer ${TOKEN}`)
      expect(headers.get('content-type')).toContain('application/json')
      expect(JSON.parse(String(init?.body))).toEqual(buildContributePayload(OPTS))
      return jsonResponse(200, okBody)
    })
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'accepted', applied: true, verified: false, reason: null })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('200 with applied=false + reason surfaces the reconciliation result', async () => {
    stubFetch(async () => jsonResponse(200, { ...okBody, applied: false, reason: 'downgrade-rejected' }))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'accepted', applied: false, reason: 'downgrade-rejected' })
  })

  it('rejects a 200 whose verified field is true (pinned contract says false)', async () => {
    stubFetch(async () => jsonResponse(200, { ...okBody, verified: true }))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'error' })
  })

  it('rejects a 200 that omits applied', async () => {
    const { applied, ...rest } = okBody
    stubFetch(async () => jsonResponse(200, rest))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'error' })
  })

  it('surfaces a 401 as a clear token problem without retrying', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(401, {}))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'rejected', status: 401 })
    expect((outcome as { message: string }).message.toLowerCase()).toContain('token')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('surfaces a 403 as a clear capability problem without retrying', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(403, {}))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'rejected', status: 403 })
    expect((outcome as { message: string }).message.toLowerCase()).toContain('capability')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('surfaces 400 and 413 without retrying', async () => {
    const f400 = stubFetch(async () => jsonResponse(400, {}))
    expect(await contributeEvidence(OPTS)).toMatchObject({ kind: 'rejected', status: 400 })
    expect(f400).toHaveBeenCalledTimes(1)
    const f413 = stubFetch(async () => jsonResponse(413, {}))
    expect(await contributeEvidence(OPTS)).toMatchObject({ kind: 'rejected', status: 413 })
    expect(f413).toHaveBeenCalledTimes(1)
  })

  it('backs off on 429 honoring Retry-After and retries up to the budget', async () => {
    let calls = 0
    stubFetch(async () => {
      calls++
      if (calls < 3) return jsonResponse(429, {}, { 'retry-after': '0' })
      return jsonResponse(200, okBody)
    })
    const outcome = await contributeEvidence({ ...OPTS, maxRetries: 2 })
    expect(outcome).toMatchObject({ kind: 'accepted' })
    expect(calls).toBe(3)
  })

  it('gives up after the 429 retry budget and reports the quota', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(429, {}, { 'retry-after': '0' }))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'rejected', status: 429 })
    expect(fetchMock).toHaveBeenCalledTimes(1 + (OPTS.maxRetries ?? MAX_429_RETRIES))
  })

  it('treats a 503 disabled body as a fail-safe disable (no retry)', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(503, { error: 'Content-intel is disabled on this server.' }))
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toEqual({ kind: 'disabled' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('collapses other 5xx and network failures into a non-throwing error', async () => {
    stubFetch(async () => jsonResponse(500, {}))
    expect(await contributeEvidence(OPTS)).toMatchObject({ kind: 'error' })
    stubFetch(async () => {
      throw new TypeError('ECONNREFUSED')
    })
    const outcome = await contributeEvidence(OPTS)
    expect(outcome).toMatchObject({ kind: 'error' })
    expect((outcome as { message?: string }).message).toBe('ECONNREFUSED')
  })

  it('collapses a malformed 200 body into an error', async () => {
    stubFetch(async () => new Response('not-json', { status: 200 }))
    expect(await contributeEvidence(OPTS)).toMatchObject({ kind: 'error' })
  })
})

describe('contributeScanEvidence wiring', () => {
  const scan: TarballScanResult = {
    resolvedVersion: '1.0.0',
    contentId: 'sha512:' + 'a'.repeat(128),
    integrityVerified: true,
    delta: {
      packageName: 'evildep',
      fromVersion: '',
      toVersion: '1.0.0',
      filesChanged: 3,
      newDomains: ['evil.example'],
      newNetworkCalls: 1,
      newDependencies: [],
      newCapabilities: ['Shell'],
      newScripts: [],
      newBinaries: [],
      risk: 'critical',
      summary: 's',
    },
    files: new Map([['package.json', JSON.stringify({ name: 'evildep', version: '1.0.0' })]]),
    lifecycleScripts: [],
  }
  const findings: Finding[] = []

  it('returns null (nothing to contribute) when the scan has no manifest', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(200, okBody))
    const noManifest: TarballScanResult = { ...scan, files: new Map([['index.js', 'x']]) }
    expect(await contributeScanEvidence(noManifest, findings, { baseUrl: BASE, token: TOKEN })).toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('returns a status string for logging and never throws', async () => {
    stubFetch(async () => jsonResponse(200, okBody))
    expect(await contributeScanEvidence(scan, findings, { baseUrl: BASE, token: TOKEN })).toBe('submitted')
  })

  it('reports rejection statuses for logging', async () => {
    stubFetch(async () => jsonResponse(403, {}))
    expect(await contributeScanEvidence(scan, findings, { baseUrl: BASE, token: TOKEN })).toBe('rejected:403')
  })

  it('reports disabled and unavailable states for logging', async () => {
    stubFetch(async () => jsonResponse(503, { error: 'Content-intel is disabled on this server.' }))
    expect(await contributeScanEvidence(scan, findings, { baseUrl: BASE, token: TOKEN })).toBe('disabled')
    vi.unstubAllGlobals()
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('ENOTFOUND') }))
    expect(await contributeScanEvidence(scan, findings, { baseUrl: BASE, token: TOKEN })).toBe('unavailable')
  })
})

describe('contribution hook wiring (static guards)', () => {
  const hookSrc = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'src', 'scanner', 'intel', 'index.ts'), 'utf8')

  it('the contribution hook is fire-and-forget: void + .catch, never awaited', () => {
    const start = hookSrc.indexOf('void contributeScanEvidence(')
    const end = hookSrc.indexOf('.catch(() => {})', start) + '.catch(() => {})'.length
    expect(start).toBeGreaterThan(-1)
    const hookBlock = hookSrc.slice(start, end)
    expect(hookBlock).toContain('void contributeScanEvidence(')
    expect(hookBlock).toContain('.then(outcome =>')
    expect(hookBlock).toContain('.catch(() => {})')
    expect(hookBlock).not.toMatch(/await\s+contributeScanEvidence/)
  })

  it('the contribution hook does not consume config.cloudApiUrl/cloudApiToken directly', () => {
    const start = hookSrc.indexOf('void contributeScanEvidence(')
    const end = hookSrc.indexOf('.catch(() => {})', start) + '.catch(() => {})'.length
    const hookBlock = hookSrc.slice(start, end)
    expect(hookBlock).not.toMatch(/baseUrl/)
    expect(hookBlock).not.toMatch(/token:/)
    expect(hookBlock).not.toMatch(/cloudApiUrl|cloudApiToken/)
  })

  it('no call site awaits contributeScanEvidence in a blocking path', () => {
    expect(hookSrc).not.toMatch(/await\s+contributeScanEvidence/)
  })
})
