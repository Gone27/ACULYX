import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';

import path from 'path';

function contentScriptBundlePlugin() {
  return {
    name: 'aculyx-content-script-bundle',
    generateBundle(_options: unknown, bundle: Record<string, any>) {
      for (const [fileName, chunk] of Object.entries(bundle)) {
        if (fileName.startsWith('content/') && chunk.type === 'chunk') {
          let code = chunk.code;
          // Strip export statements so executeScript never fails with SyntaxError: Unexpected token 'export'
          code = code.replace(/export\s*\{[^}]*\};?/g, '');
          chunk.code = `(() => {\n${code}\n})();\n`;
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [
    crx({ manifest }),
    contentScriptBundlePlugin(),
  ],
  build: {
    // Keep readable output for debugging during development
    minify: false,
    sourcemap: process.env.VITE_SOURCEMAP === 'true',
    target: 'es2022',
    rollupOptions: {
      input: {
        panel: path.resolve(__dirname, 'src/devtools/panel.html'),
        'dom-collector': path.resolve(__dirname, 'src/content/dom-collector.ts'),
        'main-world-hooks': path.resolve(__dirname, 'src/content/main-world-hooks.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'dom-collector' || chunkInfo.name === 'main-world-hooks') {
            return 'content/[name].js';
          }
          return 'chunks/[name]-[hash].js';
        },
        chunkFileNames: 'chunks/[name]-[hash].js',
      },
    },
  },
  // Vitest config lives here to avoid a separate vitest.config.ts
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/e2e/**'],
    coverage: {
      provider: 'v8',
      include: ['src/rules/**'],
    },
  },
});
