import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/intel/auth.test.ts',
      'test/regression/intel/multi-window-baselines.test.ts',
      'test/regression/intel/secrets.test.ts',
    ],
    testTimeout: 60000,
    env: { SENTINEL_TARBALL_SCAN: '0' },
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 1,
  },
})
