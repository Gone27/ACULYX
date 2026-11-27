import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json' with { type: 'json' };

import fs from 'fs';
import path from 'path';

function copyNoticePlugin() {
  return {
    name: 'aculyx-copy-notice',
    writeBundle() {
      const srcNotice = path.resolve(import.meta.dirname, 'NOTICE');
      const destNotice = path.resolve(import.meta.dirname, 'dist', 'NOTICE');
      if (fs.existsSync(srcNotice)) {
        fs.copyFileSync(srcNotice, destNotice);
      }
    },
  };
}

function contentScriptBundlePlugin() {
  return {
    name: 'aculyx-content-script-bundle',
    generateBundle(_options: unknown, bundle: Record<string, any>) {
      for (const [fileName, chunk] of Object.entries(bundle)) {
        if (fileName.startsWith('content/') && chunk.type === 'chunk') {
          let code = chunk.code;
          // Strip export statements so executeScript never fails with SyntaxError: Unexpected token 'export'
          code = code.replace(/^\s*export\s+[^;]+;?/gm, '');
          code = code.replace(/export\s*\{[^}]*\};?/g, '');

          // Verify that no module import or export remains before wrapping
          if (/^\s*import\s+/m.test(code)) {
            throw new Error(`Content script "${fileName}" contains an ES module import statement. Injected content scripts must be standalone classic scripts.`);
          }
          if (/^\s*export\s+/m.test(code)) {
            throw new Error(`Content script "${fileName}" contains an ES module export statement. Injected content scripts must be standalone classic scripts.`);
          }

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
    copyNoticePlugin(),
  ],
  build: {
    // Keep readable output for debugging during development
    minify: false,
    sourcemap: process.env.VITE_SOURCEMAP === 'true',
    target: 'es2022',
    rollupOptions: {
      input: {
        popup: path.resolve(import.meta.dirname, 'src/popup/popup.html'),
        panel: path.resolve(import.meta.dirname, 'src/devtools/panel.html'),
        'dom-collector': path.resolve(import.meta.dirname, 'src/content/dom-collector.ts'),
        'main-world-hooks': path.resolve(import.meta.dirname, 'src/content/main-world-hooks.ts'),
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
