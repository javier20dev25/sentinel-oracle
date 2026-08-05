import { describe, it, expect } from 'vitest'
import { determineScanVerdict } from '../../src/scanner/verdict'
import type { Finding } from '../../src/scanner/rules'
import type { IntelReport } from '../../src/scanner/intel/types'
import type { BuildIntelligence } from '../../src/scanner/build-intel'

function finding(overrides: Partial<Finding>): Finding {
  return {
    severity: 'low',
    category: 'code',
    title: 'test',
    description: 'test',
    ...overrides,
  } as Finding
}

describe('determineScanVerdict', () => {
  it('PASSes a clean PR with no findings and no dependency changes', () => {
    const v = determineScanVerdict([], undefined, undefined)
    expect(v.state).toBe('PASS')
    expect(v.reasons).toHaveLength(0)
  })

  it('REVIEWs a dependency added to a manifest (ChainDrop vector — manifest-line evidence only)', () => {
    const intel: IntelReport = {
      dependencies: {
        added: [{ name: 'keyv', version: '^6.0.0' }],
        updated: [],
        removed: [],
        newToRepo: [],
        riskSignals: [],
        risk: 'medium',
        summary: '1 added',
      },
    }
    const v = determineScanVerdict([], intel, undefined)
    expect(v.state).toBe('REVIEW')
    expect(v.reasons.some(r => r.includes('keyv@^6.0.0'))).toBe(true)
    expect(v.reasons.some(r => r.includes('not independently verified'))).toBe(true)
  })

  it('REVIEWs a dependency update', () => {
    const intel: IntelReport = {
      dependencies: {
        added: [],
        updated: [{ name: 'axios', fromVersion: '1.6.0', toVersion: '1.12.0', isMajor: false }],
        removed: [],
        newToRepo: [],
        riskSignals: [],
        risk: 'medium',
        summary: '1 updated',
      },
    }
    const v = determineScanVerdict([], intel, undefined)
    expect(v.state).toBe('REVIEW')
  })

  it('REVIEWs high-severity findings', () => {
    const v = determineScanVerdict([finding({ severity: 'high', title: 'Dynamic Function constructor' })])
    expect(v.state).toBe('REVIEW')
    expect(v.reasons.some(r => r.includes('Dynamic Function constructor'))).toBe(true)
  })

  it('BLOCKs critical findings', () => {
    const v = determineScanVerdict([finding({ severity: 'critical', title: 'Unsafe eval() detected' })])
    expect(v.state).toBe('BLOCK')
    expect(v.reasons.some(r => r.includes('Unsafe eval() detected'))).toBe(true)
  })

  it('BLOCKs critical intel even without critical findings', () => {
    const intel: IntelReport = {
      securityDelta: { modules: [{ name: 'Trust Drift', risk: 'critical' }], totalRiskChange: 4 } as any,
    }
    const v = determineScanVerdict([], intel, undefined)
    expect(v.state).toBe('BLOCK')
  })

  it('REVIEWs medium/high intel risk', () => {
    const intel: IntelReport = {
      securityDelta: { modules: [{ name: 'Dependencies', risk: 'medium' }], totalRiskChange: 2 } as any,
    }
    const v = determineScanVerdict([], intel, undefined)
    expect(v.state).toBe('REVIEW')
  })

  it('REVIEWs non-CLEAN build intelligence', () => {
    const buildIntel = { verdict: 'REVIEW', trustScore: 60 } as unknown as BuildIntelligence
    const v = determineScanVerdict([], undefined, buildIntel)
    expect(v.state).toBe('REVIEW')
  })

  it('BLOCK beats REVIEW when both critical finding and dependency change exist', () => {
    const intel: IntelReport = {
      dependencies: {
        added: [{ name: 'keyv', version: '6.0.0' }],
        updated: [],
        removed: [],
        newToRepo: [],
        riskSignals: [],
        risk: 'medium',
        summary: '1 added',
      },
    }
    const v = determineScanVerdict([finding({ severity: 'critical', title: 'Unsafe eval() detected' })], intel)
    expect(v.state).toBe('BLOCK')
    expect(v.reasons.length).toBeGreaterThan(1)
  })
})
