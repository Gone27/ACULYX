import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as zlib from 'zlib';
import {
  parseZipEntries,
  extractZipEntry,
  verifyZipArchive,
} from '../../scripts/verify-release-zip.mjs';

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
              strict_min_version: '128.0',
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
  });
});
