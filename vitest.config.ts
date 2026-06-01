import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
    exclude: ['node_modules', 'dist'],
    testTimeout: 15000,
    coverage: {
      provider: 'v8',
      include: ['src/core/lite/**', 'src/oracle/**', 'src/cli/intelligence/**'],
      reporter: ['text', 'lcov'],
    },
  },
});
