import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/intel/cloud-lookup.test.ts',
      'test/regression/intel/cloud-contribute.test.ts',
      'test/regression/intel/contribute-builder.test.ts',
      'test/regression/intel/enrich.test.ts',
      'test/regression/intel/enrich-throws.test.ts',
      'test/regression/intel/lookup-security.test.ts',
      'test/regression/cloud-config.test.ts',
    ],
    testTimeout: 30000,
    env: { SENTINEL_TARBALL_SCAN: '0' },
    hookTimeout: 30000,
    pool: 'forks',
    maxWorkers: 2,
  },
})
