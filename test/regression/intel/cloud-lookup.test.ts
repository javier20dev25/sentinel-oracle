import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { lookupCloud, hasCloudConnection, configureCloudLookup } from '../../../src/scanner/intel/cloud-lookup'

const BASE = 'https://cloud.example'
const TOKEN = 'token-123'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

function stubFetch(impl: (url: string, init?: RequestInit) => Promise<Response> | Response): ReturnType<typeof vi.fn> {
  const mock = vi.fn(impl)
  vi.stubGlobal('fetch', mock)
  return mock
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_CLOUD_URL', '')
  vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', '')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  configureCloudLookup()
})

describe('hasCloudConnection', () => {
  it('is false unless both a URL and a token are configured', () => {
    expect(hasCloudConnection()).toBe(false)
    expect(hasCloudConnection({ baseUrl: BASE })).toBe(false)
    expect(hasCloudConnection({ token: TOKEN })).toBe(false)
    expect(hasCloudConnection({ baseUrl: BASE, token: TOKEN })).toBe(true)
  })
})

describe('configureCloudLookup', () => {
  it('makes config-file cloud settings effective (no env required)', () => {
    configureCloudLookup(BASE, TOKEN)
    expect(hasCloudConnection()).toBe(true)
  })

  it('lets explicit non-empty opts override configured settings', () => {
    configureCloudLookup(BASE, TOKEN)
    expect(hasCloudConnection()).toBe(true)
    expect(hasCloudConnection({ baseUrl: 'https://other', token: 'other-tok' })).toBe(true)
    const fetchMock = stubFetch(async () => jsonResponse(200, {
      contentId: 'sha512:abc', found: true, usable: true, verdict: 'KNOWN_SAFE', signature: 'a'.repeat(64),
    }))
    void lookupCloud('sha512:abc', { baseUrl: 'https://other', token: 'other-tok', scannerVersion: 'v1' }).then((o) => {
      expect(o.kind).toBe('hit')
      expect(fetchMock.mock.calls[0][0]).toBe('https://other/api/intelligence/query')
    })
  })

  it('clears the connection when given empty values', () => {
    configureCloudLookup(BASE, TOKEN)
    expect(hasCloudConnection()).toBe(true)
    configureCloudLookup('', '')
    expect(hasCloudConnection()).toBe(false)
  })

  it('uses configured settings for the actual lookup request', async () => {
    configureCloudLookup(BASE, TOKEN)
    const fetchMock = stubFetch(async (url, init) => {
      const headers = new Headers(init?.headers)
      expect(url).toBe(`${BASE}/api/intelligence/query`)
      expect(headers.get('authorization')).toBe(`Bearer ${TOKEN}`)
      return jsonResponse(200, {
        contentId: 'sha512:abc',
        found: true,
        usable: true,
        verdict: 'KNOWN_SAFE',
        signature: 'a'.repeat(64),
      })
    })
    const outcome = await lookupCloud('sha512:abc', { scannerVersion: 'v1' })
    expect(outcome.kind).toBe('hit')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('lookupCloud', () => {
  it('returns an error without calling fetch when the cloud is not configured', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(200, {}))
    const outcome = await lookupCloud('sha512:abc')
    expect(outcome).toEqual({ kind: 'error' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('posts the query and returns a MALICIOUS hit with confidence and a valid signature', async () => {
    const fetchMock = stubFetch(async (url, init) => {
      expect(url).toBe(`${BASE}/api/intelligence/query`)
      expect(init?.method).toBe('POST')
      const headers = new Headers(init?.headers)
      expect(headers.get('authorization')).toBe(`Bearer ${TOKEN}`)
      expect(headers.get('content-type')).toContain('application/json')
      expect(JSON.parse(String(init?.body))).toEqual({ contentId: 'sha512:abc', scannerVersion: 'v1' })
      return jsonResponse(200, {
        contentId: 'sha512:abc',
        found: true,
        usable: true,
        verdict: 'MALICIOUS',
        confidence: 0.99,
        signature: 'a'.repeat(64),
      })
    })
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN, scannerVersion: 'v1' })
    expect(outcome).toEqual({
      kind: 'hit',
      verdict: 'MALICIOUS',
      confidence: 0.99,
      signature: 'a'.repeat(64),
      usable: true,
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('returns a miss when found is false', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: false, usable: false }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome).toEqual({ kind: 'miss' })
  })

  it('returns unusable with the reason when usable is false', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: true, usable: false, reason: 'scanner too old' }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome).toEqual({ kind: 'unusable', reason: 'scanner too old' })
  })

  it('treats 401 as an error, not a miss', async () => {
    stubFetch(async () => jsonResponse(401, { found: false }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome).toEqual({ kind: 'error' })
  })

  it('treats 403 as an error, not a miss', async () => {
    stubFetch(async () => jsonResponse(403, { found: false }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('treats a 5xx as an error', async () => {
    stubFetch(async () => jsonResponse(503, {}))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('collapses a network throw into an error without throwing', async () => {
    stubFetch(async () => {
      throw new TypeError('fetch failed')
    })
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
    expect((outcome as { message?: string }).message).toBe('fetch failed')
  })

  it('rejects a non-hex signature as an error (broken signature => do not trust)', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: true, usable: true, verdict: 'MALICIOUS', signature: 'zz-not-hex' }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('rejects a signature of the wrong length as an error', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: true, usable: true, verdict: 'MALICIOUS', signature: 'a'.repeat(63) }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('accepts a well-formed 64-hex signature on a hit', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: true, usable: true, verdict: 'SUSPICIOUS', signature: 'b'.repeat(64) }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome).toMatchObject({ kind: 'hit', verdict: 'SUSPICIOUS', signature: 'b'.repeat(64) })
  })

  it('rejects an unknown verdict as an error (fail-closed)', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: true, usable: true, verdict: 'BENIGN' }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('rejects a hit that omits contentId as an error', async () => {
    stubFetch(async () => jsonResponse(200, { found: true, usable: true, verdict: 'MALICIOUS' }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('rejects a hit that omits usable as an error', async () => {
    stubFetch(async () => jsonResponse(200, { contentId: 'sha512:abc', found: true, verdict: 'MALICIOUS' }))
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN })
    expect(outcome.kind).toBe('error')
  })

  it('aborts the request when the timeout elapses and returns an error', async () => {
    let capturedSignal: AbortSignal | undefined
    stubFetch(async (_url, init) => {
      capturedSignal = init?.signal
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted.', 'AbortError'))
        })
      })
    })
    const started = Date.now()
    const outcome = await lookupCloud('sha512:abc', { baseUrl: BASE, token: TOKEN, timeoutMs: 25 })
    expect(Date.now() - started).toBeLessThan(2000)
    expect(outcome.kind).toBe('error')
    expect(capturedSignal?.aborted).toBe(true)
  })
})
