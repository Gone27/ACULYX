import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';

export default defineConfig({
  plugins: [
    crx({ manifest }),
  ],
  build: {
    // Keep readable output for debugging during development
    minify: false,
    sourcemap: true,
    target: 'es2022',
    rollupOptions: {
      // crxjs handles entry points from manifest; these are extras
      output: {
        // Ensure chunks are named predictably
        chunkFileNames: 'chunks/[name]-[hash].js',
      },
    },
  },
  // Vitest config lives here to avoid a separate vitest.config.ts
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/rules/**/*.test.ts'],
    exclude: ['tests/e2e/**'],
    coverage: {
      provider: 'v8',
      include: ['src/rules/**'],
    },
  },
});
