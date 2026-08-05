import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/intel/capabilities.test.ts',
      'test/regression/intel/ci-policy.test.ts',
      'test/regression/intel/crypto.test.ts',
      'test/regression/intel/deep-dependency.test.ts',
      'test/regression/intel/dependencies.test.ts',
      'test/regression/intel/dna-validation.test.ts',
    ],
    testTimeout: 60000,
    env: { SENTINEL_TARBALL_SCAN: '0' },
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 2,
  },
})
