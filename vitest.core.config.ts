import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      'test/regression/scanner.test.ts',
      'test/regression/signing.test.ts',
      'test/regression/encryption.test.ts',
      'test/integration/**',
      'test/red-team/**',
      'test/evasion/**',
    ],
    testTimeout: 60000,
    hookTimeout: 60000,
    pool: 'forks',
    maxWorkers: 2,
  },
})
