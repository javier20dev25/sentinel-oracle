import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/intel/endpoints.test.ts',
      'test/regression/intel/permissions.test.ts',
      'test/regression/intel/services.test.ts',
      'test/regression/intel/trust.test.ts',
      'test/regression/intel/trust-drift.test.ts',
      'test/regression/intel/workflow-intelligence.test.ts',
    ],
    testTimeout: 60000,
    env: { SENTINEL_TARBALL_SCAN: '0' },
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 2,
  },
})
