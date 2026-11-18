import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';

// The Go server (a copy of deploy/dev/config.yaml) serves /api and /auth.
const backend = process.env.OLYMPOS_BACKEND ?? 'http://127.0.0.1:18080';

const version = (JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string }).version;

export default defineConfig({
  plugins: [react()],
  define: { __APP_VERSION__: JSON.stringify(version) },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: backend },
      '/auth': { target: backend },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // The server's CSP only allows same-origin fonts/scripts: never inline assets.
    assetsInlineLimit: 0,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // page tests render the whole SPA against the mock API (with its artificial delays)
    testTimeout: 20_000,
  },
});
