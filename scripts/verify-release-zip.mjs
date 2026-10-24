import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

/**
 * @typedef {'source' | 'chrome' | 'firefox'} VerificationTarget
 *
 * @typedef {Object} ZipEntry
 * @property {string} name
 * @property {number} compressionMethod
 * @property {number} compressedSize
 * @property {number} uncompressedSize
 * @property {number} localHeaderOffset
 */

/**
 * Parses Central Directory headers from a ZIP buffer
 * @param {Buffer} buf
 * @returns {ZipEntry[]}
 */
export function parseZipEntries(buf) {
  const sig = Buffer.from([0x50, 0x4b, 0x01, 0x02]); // PK\x01\x02
  let offset = 0;
  const entries = [];

  while ((offset = buf.indexOf(sig, offset)) !== -1) {
    if (offset + 46 > buf.length) break;
    const compressionMethod = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const uncompressedSize = buf.readUInt32LE(offset + 24);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localHeaderOffset = buf.readUInt32LE(offset + 42);
    const name = buf.toString('utf8', offset + 46, offset + 46 + nameLen);

    entries.push({
      name,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
    });

    offset += 46 + nameLen + extraLen + commentLen;
  }

  return entries;
}

/**
 * Decompresses and extracts a single entry's data
 * @param {Buffer} buf
 * @param {ZipEntry} entry
 * @returns {Buffer}
 */
export function extractZipEntry(buf, entry) {
  const localSig = buf.readUInt32LE(entry.localHeaderOffset);
  if (localSig !== 0x04034b50) {
    throw new Error(`Corrupt local header for ${entry.name}`);
  }
  const localNameLen = buf.readUInt16LE(entry.localHeaderOffset + 26);
  const localExtraLen = buf.readUInt16LE(entry.localHeaderOffset + 28);
  const dataStart = entry.localHeaderOffset + 30 + localNameLen + localExtraLen;
  const compressedData = buf.subarray(dataStart, dataStart + entry.compressedSize);

  if (entry.compressionMethod === 0) {
    return compressedData;
  } else if (entry.compressionMethod === 8) {
    return zlib.inflateRawSync(compressedData);
  } else {
    throw new Error(`Unsupported compression method ${entry.compressionMethod} for ${entry.name}`);
  }
}

/**
 * Verifies a ZIP release archive according to target specification
 * @param {string} zipPath
 * @param {VerificationTarget} target
 * @param {{ smokeExtract?: boolean; quiet?: boolean }} [options]
 * @returns {{ success: boolean; errors: string[]; entries: string[] }}
 */
export function verifyZipArchive(zipPath, target, options = {}) {
  const errors = [];
  const entries = [];

  if (!fs.existsSync(zipPath)) {
    return {
      success: false,
      errors: [`ZIP file not found: ${zipPath}`],
      entries: [],
    };
  }

  let buf;
  try {
    buf = fs.readFileSync(zipPath);
  } catch (err) {
    return {
      success: false,
      errors: [`Failed to read ZIP file: ${err.message}`],
      entries: [],
    };
  }

  const parsedEntries = parseZipEntries(buf);
  const seen = new Set();

  for (const entry of parsedEntries) {
    entries.push(entry.name);

    if (entry.name.includes('\\')) {
      errors.push(`Entry contains invalid backslash separator: "${entry.name}"`);
    }

    if (entry.name.startsWith('/') || entry.name.includes('../')) {
      errors.push(`Entry contains suspicious path traversal: "${entry.name}"`);
    }

    if (seen.has(entry.name)) {
      errors.push(`Duplicate entry found in archive: "${entry.name}"`);
    }
    seen.add(entry.name);
  }

  if (entries.length === 0) {
    errors.push(`ZIP archive is empty or contains no valid central directory entries`);
    return { success: false, errors, entries };
  }

  // Target-specific validation
  if (target === 'source') {
    const forbiddenPrefixes = [
      'dist/',
      'dist-firefox/',
      'dist-hunter/',
      'node_modules/',
      '.git/',
      '.agents/',
      '.system_generated/',
      'test-results/',
      'playwright-report/',
      'coverage/',
      '.vite-temp/',
    ];

    for (const name of entries) {
      if (forbiddenPrefixes.some((p) => name.startsWith(p))) {
        errors.push(`Source archive contains forbidden built or temporary directory: "${name}"`);
      }
      if (name.endsWith('.zip')) {
        errors.push(`Source archive contains nested ZIP file: "${name}"`);
      }
    }

    const hasPackageJson = entries.includes('package.json');
    const hasManifest = entries.includes('manifest.json');
    const hasSrc = entries.some((e) => e.startsWith('src/'));

    if (!hasPackageJson) errors.push('Essential file missing from source archive: package.json');
    if (!hasManifest) errors.push('Essential file missing from source archive: manifest.json');
    if (!hasSrc) errors.push('Source directory "src/" missing from source archive');
  } else if (target === 'full') {
    const forbiddenPrefixes = [
      'node_modules/',
      '.git/',
      '.agents/',
      '.system_generated/',
      'test-results/',
      'playwright-report/',
      'coverage/',
      '.vite-temp/',
    ];

    for (const name of entries) {
      if (forbiddenPrefixes.some((p) => name.startsWith(p))) {
        errors.push(`Full archive contains forbidden temporary or dependency directory: "${name}"`);
      }
      if (name.endsWith('.zip')) {
        errors.push(`Full archive contains nested ZIP file: "${name}"`);
      }
    }

    const hasPackageJson = entries.includes('package.json');
    const hasManifest = entries.includes('manifest.json');
    const hasSrc = entries.some((e) => e.startsWith('src/'));
    const hasDistManifest = entries.includes('dist/manifest.json');

    if (!hasPackageJson) errors.push('Essential file missing from full archive: package.json');
    if (!hasManifest) errors.push('Essential file missing from full archive: manifest.json');
    if (!hasSrc) errors.push('Source directory "src/" missing from full archive');
    if (!hasDistManifest) errors.push('Built distribution directory "dist/manifest.json" missing from full archive');
  } else if (target === 'chrome' || target === 'firefox') {
    // Both Chrome and Firefox store packages must be FLAT (no wrapper dir)
    const hasRootManifest = entries.includes('manifest.json');
    const wrappedManifest = entries.find((e) => e.endsWith('manifest.json') && e !== 'manifest.json');

    if (!hasRootManifest) {
      if (wrappedManifest) {
        errors.push(`Root manifest.json is missing (found wrapped in directory: "${wrappedManifest}")`);
      } else {
        errors.push('Root manifest.json is missing from browser extension package');
      }
    }

    // Must not contain uncompiled source (.ts/.tsx), tests, git, agents, or node_modules
    const forbiddenStorePrefixes = [
      'tests/',
      'node_modules/',
      '.git/',
      '.agents/',
      '.system_generated/',
      'dist/',
      'dist-firefox/',
      'dist-hunter/',
      'test-results/',
      'playwright-report/',
    ];

    for (const name of entries) {
      if (forbiddenStorePrefixes.some((p) => name.startsWith(p))) {
        errors.push(`Browser package contains forbidden Source or test entry: "${name}"`);
      }
      if (name.endsWith('.ts') || name.endsWith('.tsx')) {
        errors.push(`Browser package contains forbidden Source or test entry: "${name}"`);
      }
      if (name.endsWith('.zip') || name.endsWith('.log')) {
        errors.push(`Browser package contains forbidden file: "${name}"`);
      }
    }

    if (hasRootManifest) {
      const manifestEntry = parsedEntries.find((e) => e.name === 'manifest.json');
      if (manifestEntry) {
        try {
          const manifestContent = extractZipEntry(buf, manifestEntry).toString('utf8');
          const manifest = JSON.parse(manifestContent);

          if (manifest.manifest_version !== 3) {
            errors.push(`Manifest version must be 3, found: ${manifest.manifest_version}`);
          }

          if (target === 'chrome') {
            if (manifest.browser_specific_settings && manifest.browser_specific_settings.gecko) {
              errors.push('Chrome package contains Firefox-specific browser_specific_settings.gecko');
            }

            const broadPatterns = ['<all_urls>', '*://*/*', 'https://*/*', 'http://*/*'];
            const reqPerms = manifest.permissions || [];
            const reqHosts = manifest.host_permissions || [];
            for (const p of broadPatterns) {
              if (reqPerms.includes(p) || reqHosts.includes(p)) {
                errors.push(`Chrome package requests prohibited broad permission in required set: ${p}`);
              }
            }

            const csp = manifest.content_security_policy?.extension_pages || '';
            if (!csp.includes("script-src 'self'")) {
              errors.push(`Chrome package CSP missing "script-src 'self'"`);
            }
          } else if (target === 'firefox') {
            const geckoId = manifest.browser_specific_settings?.gecko?.id;
            if (!geckoId) {
              errors.push('Firefox package missing required browser_specific_settings.gecko.id');
            }

            if (manifest.permissions?.includes('sidePanel')) {
              errors.push('Firefox package contains unsupported Chrome sidePanel permission');
            }

            if (manifest.minimum_chrome_version) {
              errors.push('Firefox package contains minimum_chrome_version');
            }
          }
        } catch (err) {
          errors.push(`Failed to parse manifest.json: ${err.message}`);
        }
      }
    }
  }

  // Smoke extraction test
  if (options.smokeExtract && errors.length === 0) {
    let tmpExtractDir = '';
    try {
      tmpExtractDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-verify-smoke-'));
      for (const entry of parsedEntries) {
        if (entry.name.endsWith('/')) {
          continue; // directory entry
        }
        const data = extractZipEntry(buf, entry);
        const outFilePath = path.join(tmpExtractDir, entry.name);
        fs.mkdirSync(path.dirname(outFilePath), { recursive: true });
        fs.writeFileSync(outFilePath, data);
      }
    } catch (err) {
      errors.push(`Smoke extraction failed: ${err.message}`);
    } finally {
      if (tmpExtractDir && fs.existsSync(tmpExtractDir)) {
        try {
          fs.rmSync(tmpExtractDir, { recursive: true, force: true });
        } catch {
          // ignore cleanup errors
        }
      }
    }
  }

  return {
    success: errors.length === 0,
    errors,
    entries,
  };
}

// CLI execution handling
const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isCli) {
  let target = 'source';
  let zipPath = '';

  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--path' && args[i + 1]) {
      zipPath = args[i + 1];
      i++;
    } else if (args[i] === '--target' && args[i + 1]) {
      target = args[i + 1];
      i++;
    }
  }

  if (!zipPath) {
    if (process.env.ACULYX_ZIP_PATH) {
      zipPath = process.env.ACULYX_ZIP_PATH;
    } else if (target === 'chrome') {
      zipPath = 'D:/Projects/ACULYX-chrome.zip';
    } else if (target === 'firefox') {
      zipPath = 'D:/Projects/ACULYX-firefox.zip';
    } else if (target === 'full') {
      zipPath = 'D:/Projects/ACULYX-full.zip';
    } else {
      zipPath = 'D:/Projects/ACULYX-source.zip';
      if (!fs.existsSync(zipPath) && fs.existsSync('D:/Projects/ACULYX.zip')) {
        zipPath = 'D:/Projects/ACULYX.zip';
      }
    }
  }

  // Auto-detect target from filename if target was not explicitly given
  if (!args.includes('--target')) {
    const base = path.basename(zipPath).toLowerCase();
    if (base.includes('chrome')) target = 'chrome';
    else if (base.includes('firefox')) target = 'firefox';
    else if (base.includes('full')) target = 'full';
    else target = 'source';
  }

  console.log(`Verifying ${zipPath} for target: ${target}...`);
  const result = verifyZipArchive(zipPath, target, { smokeExtract: true });

  console.log(`Total entries: ${result.entries.length}`);
  if (!result.success) {
    console.error('VERIFICATION FAILED:');
    for (const err of result.errors) {
      console.error(` - ${err}`);
    }
    process.exit(1);
  }

  console.log(`✓ ALL VERIFICATION INVARIANTS SATISFIED for ${target} package.`);
}
