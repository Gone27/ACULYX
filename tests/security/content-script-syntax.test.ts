import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {
  S3_ALLOWED_SINKS,
  S3_ALLOWED_SOURCE_CATEGORIES,
  S3_ALLOWED_EVENT_TYPES,
} from '../../src/shared/messaging';
import {
  ALLOWED_SINKS,
  ALLOWED_SOURCE_CATEGORIES,
  ALLOWED_EVENT_TYPES,
} from '../../src/content/dom-collector';

const PROJECT_ROOT = path.resolve(__dirname, '../..');

describe('P0 Content Script Standalone Packaging & Classic Syntax', () => {
  it('keeps dom-collector S3 allowed sets strictly synchronized with messaging definitions', () => {
    expect(Array.from(ALLOWED_SINKS).sort()).toEqual(Array.from(S3_ALLOWED_SINKS).sort());
    expect(Array.from(ALLOWED_SOURCE_CATEGORIES).sort()).toEqual(Array.from(S3_ALLOWED_SOURCE_CATEGORIES).sort());
    expect(Array.from(ALLOWED_EVENT_TYPES).sort()).toEqual(Array.from(S3_ALLOWED_EVENT_TYPES).sort());
  });

  const artifactPaths = [
    { target: 'Chrome dist', file: path.join(PROJECT_ROOT, 'dist/content/dom-collector.js') },
    { target: 'Chrome dist main-world', file: path.join(PROJECT_ROOT, 'dist/content/main-world-hooks.js') },
    { target: 'Firefox dist', file: path.join(PROJECT_ROOT, 'dist-firefox/content/dom-collector.js') },
    { target: 'Firefox dist main-world', file: path.join(PROJECT_ROOT, 'dist-firefox/content/main-world-hooks.js') },
    { target: 'Hunter dist', file: path.join(PROJECT_ROOT, 'dist-hunter/content/dom-collector.js') },
    { target: 'Hunter dist main-world', file: path.join(PROJECT_ROOT, 'dist-hunter/content/main-world-hooks.js') },
  ];

  for (const { target, file } of artifactPaths) {
    it(`guarantees ${target} (${path.basename(file)}) contains zero module import/export statements`, () => {
      if (!fs.existsSync(file)) {
        throw new Error(`Artifact ${file} does not exist. Run build before running this test.`);
      }
      const code = fs.readFileSync(file, 'utf8');

      // Must not contain ES module import statement
      const importMatch = code.match(/^\s*import\s+.*$/m);
      expect(
        importMatch,
        `Found ES module import in ${target} (${file}): "${importMatch?.[0]}". Injected content scripts must be standalone classic scripts.`
      ).toBeNull();

      // Must not contain ES module export statement
      const exportMatch = code.match(/^\s*export\s+.*$/m);
      expect(
        exportMatch,
        `Found ES module export in ${target} (${file}): "${exportMatch?.[0]}". Injected content scripts must be standalone classic scripts.`
      ).toBeNull();
    });

    it(`executes ${target} (${path.basename(file)}) cleanly as a classic script without SyntaxError`, () => {
      if (!fs.existsSync(file)) {
        throw new Error(`Artifact ${file} does not exist.`);
      }
      const code = fs.readFileSync(file, 'utf8');

      // Create a mock browser DOM/Window sandbox
      const sandbox: Record<string, unknown> = {
        console: { log: () => {}, warn: () => {}, error: () => {}, debug: () => {}, info: () => {} },
        document: {
          querySelectorAll: () => [],
          addEventListener: () => {},
          removeEventListener: () => {},
          createElement: () => ({ setAttribute: () => {}, appendChild: () => {} }),
          head: { appendChild: () => {} },
          documentElement: {},
        },
        window: {
          addEventListener: () => {},
          removeEventListener: () => {},
        },
        chrome: {
          runtime: {
            sendMessage: () => Promise.resolve(),
            onMessage: { addListener: () => {} },
          },
        },
        location: { href: 'https://example.com/test', origin: 'https://example.com' },
        Set,
        Map,
        Array,
        Object,
        String,
        Number,
        Boolean,
        RegExp,
        Date,
        Math,
      };
      (sandbox.window as Record<string, unknown>).window = sandbox.window;
      (sandbox.window as Record<string, unknown>).document = sandbox.document;

      // Running as a classic script should NOT throw SyntaxError (e.g. Cannot use import statement outside a module)
      expect(() => {
        vm.runInNewContext(code, sandbox, { filename: path.basename(file) });
      }).not.toThrow();
    });
  }
});
