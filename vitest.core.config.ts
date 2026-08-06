import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/scanner.test.ts',
      'test/regression/signing.test.ts',
      'test/regression/encryption.test.ts',
      'test/regression/verdict.test.ts',
      'test/regression/attestation.test.ts',
      'test/regression/intel/tarball-scan.test.ts',
      'test/regression/intel/content-intel.test.ts',
      'test/integration/**',
      'test/red-team/**',
      'test/evasion/**',
    ],
    testTimeout: 60000,
    env: { SENTINEL_TARBALL_SCAN: '0' },
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 2,
  },
})
