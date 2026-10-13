import { defineConfig } from 'vitest/config';

// Plain Vitest config: the extension's unit tests exercise pure,
// dependency-injected modules (lib/*), so no WXT-specific plugin is needed —
// which also keeps the test runner decoupled from the build toolchain's
// Vite version. Browser-entrypoint wiring is covered by the e2e suite.
export default defineConfig({
  test: {
    environment: 'happy-dom',
    include: ['tests/**/*.test.ts'],
    testTimeout: 15000,
  },
});
