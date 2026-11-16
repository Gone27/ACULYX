import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as zlib from 'zlib';
import {
  parseZipEntries,
  extractZipEntry,
  verifyZipArchive,
  verifyAllArchives,
} from '../../scripts/verify-release-zip.mjs';
import {
  collectFiles,
  writeZipArchive,
  packTarget,
  isExcludedFile,
} from '../../scripts/pack-release.mjs';

function createMockZipBuffer(files: { name: string; content: string | Buffer; method?: number }[]): Buffer {
  const localHeaders: Buffer[] = [];
  const centralHeaders: Buffer[] = [];
  let offset = 0;

  for (const file of files) {
    const isDeflate = file.method === 8;
    const rawContent = Buffer.isBuffer(file.content) ? file.content : Buffer.from(file.content, 'utf8');
    const compressedData = isDeflate ? zlib.deflateRawSync(rawContent) : rawContent;
    const compressionMethod = isDeflate ? 8 : 0;
    const nameBuf = Buffer.from(file.name, 'utf8');

    // Local header: 30 bytes + nameLen + data
    const localHeader = Buffer.alloc(30 + nameBuf.length + compressedData.length);
    localHeader.writeUInt32LE(0x04034b50, 0); // local signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0, 6); // flags
    localHeader.writeUInt16LE(compressionMethod, 8); // method
    localHeader.writeUInt16LE(0, 10); // time
    localHeader.writeUInt16LE(0, 12); // date
    localHeader.writeUInt32LE(0, 14); // crc32 (mock 0 for simple test)
    localHeader.writeUInt32LE(compressedData.length, 18); // comp size
    localHeader.writeUInt32LE(rawContent.length, 22); // uncomp size
    localHeader.writeUInt16LE(nameBuf.length, 26); // name length
    localHeader.writeUInt16LE(0, 28); // extra length
    nameBuf.copy(localHeader, 30);
    compressedData.copy(localHeader, 30 + nameBuf.length);
    localHeaders.push(localHeader);

    // Central directory header: 46 bytes + nameLen
    const centralHeader = Buffer.alloc(46 + nameBuf.length);
    centralHeader.writeUInt32LE(0x02014b50, 0); // central signature PK\x01\x02
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0, 8); // flags
    centralHeader.writeUInt16LE(compressionMethod, 10); // method
    centralHeader.writeUInt16LE(0, 12); // time
    centralHeader.writeUInt16LE(0, 14); // date
    centralHeader.writeUInt32LE(0, 16); // crc32
    centralHeader.writeUInt32LE(compressedData.length, 20); // comp size
    centralHeader.writeUInt32LE(rawContent.length, 24); // uncomp size
    centralHeader.writeUInt16LE(nameBuf.length, 28); // name length
    centralHeader.writeUInt16LE(0, 30); // extra length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk number start
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE(0, 38); // external attrs
    centralHeader.writeUInt32LE(offset, 42); // relative offset of local header
    nameBuf.copy(centralHeader, 46);
    centralHeaders.push(centralHeader);

    offset += localHeader.length;
  }

  const centralOffset = offset;
  const centralDir = Buffer.concat(centralHeaders);

  // End of central directory record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // start disk
  eocd.writeUInt16LE(files.length, 8); // entries on disk
  eocd.writeUInt16LE(files.length, 10); // total entries
  eocd.writeUInt32LE(centralDir.length, 12); // size of central dir
  eocd.writeUInt32LE(centralOffset, 16); // offset of central dir
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localHeaders, centralDir, eocd]);
}

describe('Release ZIP Packaging & Verifier', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-pack-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('parseZipEntries & extractZipEntry', () => {
    it('correctly parses entries and decompresses deflated entries', () => {
      const mockZip = createMockZipBuffer([
        { name: 'manifest.json', content: '{"name":"aculyx"}', method: 8 },
        { name: 'popup.html', content: '<html><body>test</body></html>', method: 0 },
      ]);

      const entries = parseZipEntries(mockZip);
      expect(entries.map((e: { name: string }) => e.name)).toEqual(['manifest.json', 'popup.html']);

      const firstEntry = entries[0];
      const secondEntry = entries[1];
      if (!firstEntry || !secondEntry) {
        throw new Error('Expected entries to exist');
      }

      const manifestBuf = extractZipEntry(mockZip, firstEntry);
      expect(manifestBuf.toString('utf8')).toBe('{"name":"aculyx"}');

      const popupBuf = extractZipEntry(mockZip, secondEntry);
      expect(popupBuf.toString('utf8')).toBe('<html><body>test</body></html>');
    });
  });

  describe('verifyZipArchive target checks', () => {
    it('rejects zip files containing backslashes in entry names', () => {
      const mockZip = createMockZipBuffer([
        { name: 'src\\index.ts', content: 'console.log("hello")', method: 0 },
      ]);
      const zipPath = path.join(tmpDir, 'test-backslash.zip');
      fs.writeFileSync(zipPath, mockZip);

      const result = verifyZipArchive(zipPath, 'source');
      expect(result.success).toBe(false);
      expect(result.errors.some((err: string) => err.includes('backslash'))).toBe(true);
    });

    it('rejects zip files containing duplicate entries', () => {
      const mockZip = createMockZipBuffer([
        { name: 'manifest.json', content: '{}', method: 0 },
        { name: 'manifest.json', content: '{}', method: 0 },
      ]);
      const zipPath = path.join(tmpDir, 'test-dup.zip');
      fs.writeFileSync(zipPath, mockZip);

      const result = verifyZipArchive(zipPath, 'chrome');
      expect(result.success).toBe(false);
      expect(result.errors.some((err: string) => err.includes('Duplicate'))).toBe(true);
    });

    describe('target: source', () => {
      it('rejects source zip if forbidden directories (dist, node_modules, .git, .agents) are present', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{"version":"2.0.3"}', method: 0 },
          { name: 'manifest.json', content: '{"manifest_version":3}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: 'dist/index.js', content: 'bundled', method: 0 },
          { name: '.agents/log.txt', content: 'secret', method: 0 },
          { name: 'node_modules/dep/index.js', content: 'dep', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-source-forbidden.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'source');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('dist/'))).toBe(true);
        expect(result.errors.some((err: string) => err.includes('.agents/'))).toBe(true);
        expect(result.errors.some((err: string) => err.includes('node_modules/'))).toBe(true);
      });

      it('rejects source zip if essential source files are missing', () => {
        const mockZip = createMockZipBuffer([
          { name: 'src/index.ts', content: 'export {}', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-source-missing.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'source');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('package.json'))).toBe(true);
      });

      it('accepts valid clean source archive', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{"version":"2.0.3"}', method: 0 },
          { name: 'manifest.json', content: '{"manifest_version":3}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: 'README.md', content: '# ACULYX', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-source-valid.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'source', { smokeExtract: true });
        expect(result.success).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('target: chrome', () => {
      it('rejects chrome zip if manifest.json is wrapped in a subfolder', () => {
        const mockZip = createMockZipBuffer([
          { name: 'dist/manifest.json', content: '{"manifest_version":3}', method: 0 },
          { name: 'dist/popup.html', content: '<html></html>', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-chrome-wrapped.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'chrome');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('Root manifest.json is missing'))).toBe(true);
      });

      it('rejects chrome zip if browser_specific_settings.gecko is present', () => {
        const mockZip = createMockZipBuffer([
          {
            name: 'manifest.json',
            content: JSON.stringify({
              manifest_version: 3,
              name: 'ACULYX',
              browser_specific_settings: { gecko: { id: 'aculyx@test' } },
            }),
            method: 0,
          },
        ]);
        const zipPath = path.join(tmpDir, 'test-chrome-gecko.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'chrome');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('Firefox-specific browser_specific_settings'))).toBe(true);
      });

      it('rejects chrome zip if source or test files are bundled', () => {
        const mockZip = createMockZipBuffer([
          { name: 'manifest.json', content: '{"manifest_version":3}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-chrome-src.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'chrome');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('Source or test'))).toBe(true);
      });

      it('accepts valid flat Chrome store archive and extracts in smoke test', () => {
        const validManifest = {
          manifest_version: 3,
          name: 'ACULYX',
          version: '2.0.3',
          action: { default_popup: 'popup.html' },
          content_security_policy: {
            extension_pages: "script-src 'self'; object-src 'none'; connect-src 'none'",
          },
        };
        const mockZip = createMockZipBuffer([
          { name: 'manifest.json', content: JSON.stringify(validManifest), method: 8 },
          { name: 'popup.html', content: '<html><body>Popup</body></html>', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-chrome-valid.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'chrome', { smokeExtract: true });
        expect(result.success).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('target: firefox', () => {
      it('rejects firefox zip if browser_specific_settings.gecko is missing', () => {
        const mockZip = createMockZipBuffer([
          {
            name: 'manifest.json',
            content: JSON.stringify({
              manifest_version: 3,
              name: 'ACULYX',
            }),
            method: 0,
          },
        ]);
        const zipPath = path.join(tmpDir, 'test-firefox-no-gecko.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'firefox');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('gecko'))).toBe(true);
      });

      it('rejects firefox zip if prohibited Chrome permissions like sidePanel remain', () => {
        const mockZip = createMockZipBuffer([
          {
            name: 'manifest.json',
            content: JSON.stringify({
              manifest_version: 3,
              name: 'ACULYX',
              browser_specific_settings: { gecko: { id: 'aculyx@dhyanpatel.com' } },
              permissions: ['storage', 'sidePanel'],
            }),
            method: 0,
          },
        ]);
        const zipPath = path.join(tmpDir, 'test-firefox-sidepanel.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'firefox');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('sidePanel'))).toBe(true);
      });

      it('accepts valid flat Firefox AMO archive', () => {
        const validFirefoxManifest = {
          manifest_version: 3,
          name: 'ACULYX',
          version: '2.0.3',
          browser_specific_settings: {
            gecko: {
              id: 'aculyx@dhyanpatel.com',
              strict_min_version: '140.0',
            },
          },
          permissions: ['storage', 'tabs'],
          action: { default_popup: 'popup.html' },
        };
        const mockZip = createMockZipBuffer([
          { name: 'manifest.json', content: JSON.stringify(validFirefoxManifest), method: 8 },
          { name: 'popup.html', content: '<html><body>Firefox Popup</body></html>', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-firefox-valid.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'firefox', { smokeExtract: true });
        expect(result.success).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('target: full', () => {
      it('rejects full zip if forbidden node_modules or .git are present', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{}', method: 0 },
          { name: 'manifest.json', content: '{}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: 'dist/manifest.json', content: '{}', method: 0 },
          { name: 'node_modules/lib/index.js', content: 'dep', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-full-forbidden.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'full');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('node_modules/'))).toBe(true);
      });

      it('rejects full zip if built dist directory is missing', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{}', method: 0 },
          { name: 'manifest.json', content: '{}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-full-no-dist.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'full');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('dist/manifest.json'))).toBe(true);
      });

      it('accepts valid full project archive containing source and built distributions', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{}', method: 0 },
          { name: 'manifest.json', content: '{}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: 'dist/manifest.json', content: '{"name":"aculyx"}', method: 8 },
          { name: 'dist-firefox/manifest.json', content: '{"name":"aculyx"}', method: 8 },
        ]);
        const zipPath = path.join(tmpDir, 'test-full-valid.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'full', { smokeExtract: true });
        expect(result.success).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('universal sensitive & ignored file rejection', () => {
      it('rejects archives containing .env or .env.local', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{}', method: 0 },
          { name: 'manifest.json', content: '{}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: '.env', content: 'SECRET=true', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-env.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'source');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('.env'))).toBe(true);
      });

      it('rejects archives containing .local or ORIGINAL_REQUEST.md files', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{}', method: 0 },
          { name: 'manifest.json', content: '{}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: 'secrets.local', content: 'secret', method: 0 },
          { name: 'ORIGINAL_REQUEST.md', content: '# Prompt', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-local-ignored.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'source');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('secrets.local'))).toBe(true);
        expect(result.errors.some((err: string) => err.includes('ORIGINAL_REQUEST.md'))).toBe(true);
      });

      it('rejects archives containing OS metadata files like .DS_Store or Thumbs.db', () => {
        const mockZip = createMockZipBuffer([
          { name: 'package.json', content: '{}', method: 0 },
          { name: 'manifest.json', content: '{}', method: 0 },
          { name: 'src/index.ts', content: 'export {}', method: 0 },
          { name: '.DS_Store', content: 'junk', method: 0 },
        ]);
        const zipPath = path.join(tmpDir, 'test-ds-store.zip');
        fs.writeFileSync(zipPath, mockZip);

        const result = verifyZipArchive(zipPath, 'source');
        expect(result.success).toBe(false);
        expect(result.errors.some((err: string) => err.includes('.DS_Store'))).toBe(true);
      });
    });

    describe('verifyAllArchives aggregate verification', () => {
      it('fails closed when any of the four required release archives is missing', () => {
        const aggDir = path.join(tmpDir, 'aggregate-missing');
        fs.mkdirSync(aggDir);

        // Only create source and chrome, leave full and firefox missing
        fs.writeFileSync(
          path.join(aggDir, 'ACULYX-source.zip'),
          createMockZipBuffer([
            { name: 'package.json', content: '{}', method: 0 },
            { name: 'manifest.json', content: '{}', method: 0 },
            { name: 'src/index.ts', content: 'export {}', method: 0 },
          ])
        );

        const res = verifyAllArchives(aggDir);
        expect(res.success).toBe(false);
        expect(res.errors.some((err: string) => err.includes('ACULYX-full.zip'))).toBe(true);
        expect(res.errors.some((err: string) => err.includes('ACULYX-firefox.zip'))).toBe(true);
      });

      it('succeeds when all four required archives exist and meet specifications', () => {
        const aggDir = path.join(tmpDir, 'aggregate-valid');
        fs.mkdirSync(aggDir);

        const validManifest = {
          manifest_version: 3,
          name: 'ACULYX',
          version: '2.0.5',
          content_security_policy: {
            extension_pages: "script-src 'self'; object-src 'none'; connect-src 'self'",
          },
        };

        const validFirefoxManifest = {
          manifest_version: 3,
          name: 'ACULYX',
          version: '2.0.5',
          browser_specific_settings: { gecko: { id: 'aculyx@dhyanpatel.com' } },
        };

        fs.writeFileSync(
          path.join(aggDir, 'ACULYX-source.zip'),
          createMockZipBuffer([
            { name: 'package.json', content: '{}', method: 0 },
            { name: 'manifest.json', content: '{}', method: 0 },
            { name: 'src/index.ts', content: 'export {}', method: 0 },
          ])
        );
        fs.writeFileSync(
          path.join(aggDir, 'ACULYX-full.zip'),
          createMockZipBuffer([
            { name: 'package.json', content: '{}', method: 0 },
            { name: 'manifest.json', content: '{}', method: 0 },
            { name: 'src/index.ts', content: 'export {}', method: 0 },
            { name: 'dist/manifest.json', content: '{}', method: 0 },
          ])
        );
        fs.writeFileSync(
          path.join(aggDir, 'ACULYX-chrome.zip'),
          createMockZipBuffer([
            { name: 'manifest.json', content: JSON.stringify(validManifest), method: 8 },
            { name: 'popup.html', content: '<html></html>', method: 0 },
          ])
        );
        fs.writeFileSync(
          path.join(aggDir, 'ACULYX-firefox.zip'),
          createMockZipBuffer([
            { name: 'manifest.json', content: JSON.stringify(validFirefoxManifest), method: 8 },
            { name: 'popup.html', content: '<html></html>', method: 0 },
          ])
        );

        const res = verifyAllArchives(aggDir, { smokeExtract: true });
        expect(res.success).toBe(true);
        expect(res.errors).toHaveLength(0);
      });
    });

    describe('pack-release exclusions and workspace fixture integration', () => {
      it('isExcludedFile correctly identifies sensitive files, local configs, and temporary dirs', () => {
        expect(isExcludedFile('.env', 'source')).toBe(true);
        expect(isExcludedFile('.env.production', 'source')).toBe(true);
        expect(isExcludedFile('auth.local', 'source')).toBe(true);
        expect(isExcludedFile('ORIGINAL_REQUEST.md', 'source')).toBe(true);
        expect(isExcludedFile('.DS_Store', 'source')).toBe(true);
        expect(isExcludedFile('Thumbs.db', 'source')).toBe(true);
        expect(isExcludedFile('node_modules/express/index.js', 'source')).toBe(true);
        expect(isExcludedFile('.git/HEAD', 'source')).toBe(true);
        expect(isExcludedFile('dist/bundle.js', 'source')).toBe(true);
        expect(isExcludedFile('dist/bundle.js', 'full')).toBe(false);
        expect(isExcludedFile('src/index.ts', 'source')).toBe(false);
        expect(isExcludedFile('src/index.ts', 'full')).toBe(false);
      });

      it('collectFiles scans a workspace fixture and strips all ignored and sensitive files', () => {
        const fixtureDir = path.join(tmpDir, 'fixture-workspace');
        fs.mkdirSync(path.join(fixtureDir, 'src'), { recursive: true });
        fs.mkdirSync(path.join(fixtureDir, 'node_modules', 'dep'), { recursive: true });

        fs.writeFileSync(path.join(fixtureDir, 'package.json'), '{}');
        fs.writeFileSync(path.join(fixtureDir, 'src', 'index.ts'), 'export const v = 1;');
        fs.writeFileSync(path.join(fixtureDir, '.env'), 'TOKEN=bad');
        fs.writeFileSync(path.join(fixtureDir, '.env.local'), 'LOCAL=true');
        fs.writeFileSync(path.join(fixtureDir, 'secrets.local'), 'SECRET=key');
        fs.writeFileSync(path.join(fixtureDir, 'ORIGINAL_REQUEST.md'), '# Request');
        fs.writeFileSync(path.join(fixtureDir, '.DS_Store'), 'junk');
        fs.writeFileSync(path.join(fixtureDir, 'node_modules', 'dep', 'index.js'), 'export {}');

        const collected = collectFiles(fixtureDir, 'source');
        const relPaths = collected.map((c: { relPath: string }) => c.relPath);

        expect(relPaths).toContain('package.json');
        expect(relPaths).toContain('src/index.ts');

        expect(relPaths).not.toContain('.env');
        expect(relPaths).not.toContain('.env.local');
        expect(relPaths).not.toContain('secrets.local');
        expect(relPaths).not.toContain('ORIGINAL_REQUEST.md');
        expect(relPaths).not.toContain('.DS_Store');
        expect(relPaths.some((p: string) => p.includes('node_modules'))).toBe(false);
      });

      it('writeZipArchive refuses to overwrite existing archive without overwrite: true', () => {
        const targetZip = path.join(tmpDir, 'existing.zip');
        fs.writeFileSync(targetZip, 'dummy');

        expect(() => {
          writeZipArchive([], targetZip, { overwrite: false });
        }).toThrow(/Refusing to overwrite existing archive/);
      });

      it('writeZipArchive writes real ZIP on disk and verifyZipArchive confirms decompression integrity', () => {
        const fixtureDir = path.join(tmpDir, 'real-zip-fixture');
        fs.mkdirSync(path.join(fixtureDir, 'src'), { recursive: true });

        const pkgContent = '{\n  "name": "aculyx-fixture"\n}\n';
        const srcContent = 'export const test = "deflate-compression-payload-repeated-'.repeat(20) + '";';
        fs.writeFileSync(path.join(fixtureDir, 'package.json'), pkgContent);
        fs.writeFileSync(path.join(fixtureDir, 'src', 'index.ts'), srcContent);

        const files = collectFiles(fixtureDir, 'source');
        const zipPath = path.join(tmpDir, 'output-test.zip');
        const packRes = writeZipArchive(files, zipPath, { overwrite: true });

        expect(packRes.fileCount).toBe(2);
        expect(fs.existsSync(zipPath)).toBe(true);

        const buf = fs.readFileSync(zipPath);
        const entries = parseZipEntries(buf);
        expect(entries).toHaveLength(2);

        const entryNames = entries.map((e) => e.name);
        expect(entryNames).toContain('package.json');
        expect(entryNames).toContain('src/index.ts');

        // Verify each entry decompressibility and byte-for-byte fidelity
        for (const entry of entries) {
          expect(entry.name).not.toContain('\\');
          const decompressed = extractZipEntry(buf, entry).toString('utf8');
          if (entry.name === 'package.json') {
            expect(decompressed).toBe(pkgContent);
          } else if (entry.name === 'src/index.ts') {
            expect(decompressed).toBe(srcContent);
          }
        }
      });

      it('packTarget builds actual project packages into a fresh disposable directory and passes aggregate verification', () => {
        const outDir = path.join(tmpDir, 'live-pack-out');
        fs.mkdirSync(outDir);

        // Pack all 4 targets from actual project repository
        packTarget('source', outDir, { overwrite: true });
        packTarget('chrome', outDir, { overwrite: true });
        packTarget('firefox', outDir, { overwrite: true });
        packTarget('full', outDir, { overwrite: true });

        // Assert all 4 zip files exist on disk
        expect(fs.existsSync(path.join(outDir, 'ACULYX-source.zip'))).toBe(true);
        expect(fs.existsSync(path.join(outDir, 'ACULYX-chrome.zip'))).toBe(true);
        expect(fs.existsSync(path.join(outDir, 'ACULYX-firefox.zip'))).toBe(true);
        expect(fs.existsSync(path.join(outDir, 'ACULYX-full.zip'))).toBe(true);

        // Run full aggregate verification with smoke extraction
        const aggRes = verifyAllArchives(outDir, { smokeExtract: true });
        expect(aggRes.success).toBe(true);
        expect(aggRes.errors).toHaveLength(0);

        // Inspect ACULYX-source.zip entries directly
        const sourceBuf = fs.readFileSync(path.join(outDir, 'ACULYX-source.zip'));
        const sourceEntries = parseZipEntries(sourceBuf).map((e) => e.name);

        expect(sourceEntries).toContain('package.json');
        expect(sourceEntries).toContain('manifest.json');
        expect(sourceEntries.some((e) => e.startsWith('src/'))).toBe(true);

        // Assert no forbidden files exist in the written archive
        expect(sourceEntries).not.toContain('.env');
        expect(sourceEntries).not.toContain('ORIGINAL_REQUEST.md');
        expect(sourceEntries.some((e) => e.endsWith('.local'))).toBe(false);
        expect(sourceEntries.some((e) => e.includes('node_modules/'))).toBe(false);
        expect(sourceEntries.some((e) => e.startsWith('dist/'))).toBe(false);
      });
    });
  });
});
