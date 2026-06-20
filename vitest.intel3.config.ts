import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/intel/auth.test.ts',
      'test/regression/intel/index.test.ts',
      'test/regression/intel/infrastructure.test.ts',
      'test/regression/intel/multi-window-baselines.test.ts',
      'test/regression/intel/secrets.test.ts',
    ],
    testTimeout: 60000,
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 2,
  },
})
