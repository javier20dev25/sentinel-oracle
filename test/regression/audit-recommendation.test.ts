import { describe, expect, it } from 'vitest'
import { recommendAudit } from '../../src/audit/recommendation'

describe('Sentinel Audit PR recommendation', () => {
  it('recommends a separate audit for high severity findings without altering scan state', () => {
    const recommendation = recommendAudit({
      findings: [{ severity: 'high', category: 'code' }],
      state: 'REVIEW',
      commitSha: 'a'.repeat(40),
    })
    expect(recommendation.recommended).toBe(true)
    expect(recommendation.command).toContain('--commit ' + 'a'.repeat(40))
    expect(recommendation.scope).toBe('advisory-only')
  })

  it('recommends deeper evidence for medium CI/CD or dependency signals', () => {
    expect(recommendAudit({ findings: [{ severity: 'medium', category: 'workflow' }] }).recommended).toBe(true)
    expect(recommendAudit({ findings: [{ severity: 'low', category: 'dependency' }] }).recommended).toBe(true)
  })

  it('does not recommend audit for a routine low risk result', () => {
    expect(recommendAudit({ findings: [{ severity: 'low', category: 'code' }], state: 'PASS' })).toMatchObject({ recommended: false, reasons: [], scope: 'advisory-only' })
  })

  it('does not output an unpinned command when the commit is not a full SHA', () => {
    expect(recommendAudit({ findings: [{ severity: 'critical', category: 'secret' }], commitSha: 'main' }).command).toBeUndefined()
  })
})
