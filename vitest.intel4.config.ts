import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/regression/intel/index.test.ts'],
    testTimeout: 60000,
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 1,
  },
})
