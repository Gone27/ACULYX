import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

/**
 * Fallback CRC-32 implementation if zlib.crc32 is unavailable
 */
const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC_TABLE[n] = c;
}

function calculateCrc32(buf) {
  if (typeof zlib.crc32 === 'function') {
    return zlib.crc32(buf) >>> 0;
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Common excluded directory names across source/full packaging
 */
export const SHARED_EXCLUDE_DIRS = new Set([
  'node_modules',
  '.git',
  '.agents',
  '.system_generated',
  'test-results',
  'playwright-report',
  'coverage',
  '.vite-temp',
  '.idea',
  '.vscode',
]);

/**
 * Sensitive and transient file names/patterns that must NEVER enter any release archive
 */
export const SENSITIVE_FILE_NAMES = new Set([
  '.env',
  'ORIGINAL_REQUEST.md',
  '.DS_Store',
  'Thumbs.db',
  'desktop.ini',
]);

export function isExcludedFile(relPath, target = 'source') {
  // Normalize to forward slashes for matching
  const normalized = relPath.replace(/\\/g, '/');
  const parts = normalized.split('/');
  const baseName = parts[parts.length - 1];

  // 1. Directory exclusion
  for (const part of parts.slice(0, -1)) {
    if (SHARED_EXCLUDE_DIRS.has(part)) {
      return true;
    }
  }

  // 2. Sensitive file names
  if (SENSITIVE_FILE_NAMES.has(baseName)) {
    return true;
  }

  // 3. Dot-env variants, local overrides, temporary archives, and logs
  if (baseName.startsWith('.env.') || baseName.endsWith('.local') || baseName.endsWith('.log') || baseName.endsWith('.zip')) {
    return true;
  }

  // 4. Target-specific rules
  if (target === 'source') {
    const topDir = parts[0];
    if (topDir === 'dist' || topDir === 'dist-firefox' || topDir === 'dist-hunter') {
      return true;
    }
  }

  if (target === 'chrome' || target === 'firefox') {
    if (baseName.endsWith('.ts') || baseName.endsWith('.tsx') || baseName.endsWith('.map')) {
      return true;
    }
  }

  return false;
}

/**
 * Recursively scans directory for packable files
 */
export function collectFiles(sourceDir, target) {
  const collected = [];

  function walk(currentDir) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(sourceDir, fullPath);

      if (entry.isDirectory()) {
        if (!isExcludedFile(relPath + '/', target)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        if (!isExcludedFile(relPath, target)) {
          collected.push({
            fullPath,
            relPath: relPath.replace(/\\/g, '/'),
          });
        }
      }
    }
  }

  walk(sourceDir);
  // Sort deterministically for reproducible packaging
  collected.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return collected;
}

/**
 * Creates an RFC 1951 compliant ZIP archive using Deflate compression
 */
export function writeZipArchive(files, destZipPath, options = {}) {
  const { overwrite = false } = options;

  if (fs.existsSync(destZipPath) && !overwrite) {
    throw new Error(
      `Refusing to overwrite existing archive: "${destZipPath}". Pass --overwrite to replace, or specify a new directory with --output-dir.`
    );
  }

  const destDir = path.dirname(destZipPath);
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const file of files) {
    const rawContent = fs.readFileSync(file.fullPath);
    const crc = calculateCrc32(rawContent);
    const compressed = zlib.deflateRawSync(rawContent, { level: 9 });

    // Use method 8 (deflate) unless compression inflated the payload
    const isDeflated = compressed.length < rawContent.length;
    const method = isDeflated ? 8 : 0;
    const payload = isDeflated ? compressed : rawContent;

    const nameBuf = Buffer.from(file.relPath, 'utf8');

    // Local Header (30 bytes + nameLen + payload)
    const local = Buffer.alloc(30 + nameBuf.length + payload.length);
    local.writeUInt32LE(0x04034b50, 0); // Local file header signature
    local.writeUInt16LE(20, 4);          // Version needed: 2.0
    local.writeUInt16LE(0x0800, 6);      // General purpose bit flag: UTF-8
    local.writeUInt16LE(method, 8);      // Compression method
    local.writeUInt16LE(0, 10);          // File last mod time
    local.writeUInt16LE(0, 12);          // File last mod date
    local.writeUInt32LE(crc, 14);        // CRC-32
    local.writeUInt32LE(payload.length, 18); // Compressed size
    local.writeUInt32LE(rawContent.length, 22); // Uncompressed size
    local.writeUInt16LE(nameBuf.length, 26); // File name length
    local.writeUInt16LE(0, 28);          // Extra field length
    nameBuf.copy(local, 30);
    payload.copy(local, 30 + nameBuf.length);
    localHeaders.push(local);

    // Central Directory Header (46 bytes + nameLen)
    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0); // Central file header signature
    central.writeUInt16LE(20, 4);          // Version made by: 2.0
    central.writeUInt16LE(20, 6);          // Version needed: 2.0
    central.writeUInt16LE(0x0800, 8);      // UTF-8 flag
    central.writeUInt16LE(method, 10);     // Method
    central.writeUInt16LE(0, 12);          // Time
    central.writeUInt16LE(0, 14);          // Date
    central.writeUInt32LE(crc, 16);        // CRC-32
    central.writeUInt32LE(payload.length, 20); // Compressed size
    central.writeUInt32LE(rawContent.length, 24); // Uncompressed size
    central.writeUInt16LE(nameBuf.length, 28); // Name length
    central.writeUInt16LE(0, 30);          // Extra field length
    central.writeUInt16LE(0, 32);          // File comment length
    central.writeUInt16LE(0, 34);          // Disk number start
    central.writeUInt16LE(0, 36);          // Internal file attributes
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38); // External file attributes (regular file rw-r--r--)
    central.writeUInt32LE(offset, 42);     // Relative offset of local header
    nameBuf.copy(central, 46);
    centralHeaders.push(central);

    offset += local.length;
  }

  const centralOffset = offset;
  const centralDir = Buffer.concat(centralHeaders);

  // End of Central Directory Record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4);          // Number of this disk
  eocd.writeUInt16LE(0, 6);          // Disk with central directory
  eocd.writeUInt16LE(files.length, 8); // Entries on disk
  eocd.writeUInt16LE(files.length, 10); // Total entries
  eocd.writeUInt32LE(centralDir.length, 12); // Size of central directory
  eocd.writeUInt32LE(centralOffset, 16);     // Offset of central directory
  eocd.writeUInt16LE(0, 20);          // Comment length

  const fullZipBuffer = Buffer.concat([...localHeaders, centralDir, eocd]);
  fs.writeFileSync(destZipPath, fullZipBuffer);

  return {
    path: destZipPath,
    fileCount: files.length,
    sizeBytes: fullZipBuffer.length,
  };
}

/**
 * Packages specified release target
 */
export function packTarget(target, outputDir, options = {}) {
  const { overwrite = false } = options;

  if (target === 'source') {
    const destZip = path.join(outputDir, 'ACULYX-source.zip');
    const files = collectFiles(repoRoot, 'source');
    return writeZipArchive(files, destZip, { overwrite });
  }

  if (target === 'full') {
    const distManifest = path.join(repoRoot, 'dist', 'manifest.json');
    if (!fs.existsSync(distManifest)) {
      throw new Error('dist/manifest.json not found. Run "npm run build" before packaging full.');
    }
    const destZip = path.join(outputDir, 'ACULYX-full.zip');
    const legacyZip = path.join(outputDir, 'ACULYX.zip');

    if (fs.existsSync(legacyZip) && !overwrite) {
      throw new Error(
        `Refusing to overwrite existing legacy archive: "${legacyZip}". Pass --overwrite to replace, or specify a new directory with --output-dir.`
      );
    }

    const files = collectFiles(repoRoot, 'full');
    const res = writeZipArchive(files, destZip, { overwrite });

    // Synchronize legacy ACULYX.zip atomically from freshly written full archive
    fs.copyFileSync(destZip, legacyZip);
    return res;
  }

  if (target === 'chrome') {
    const chromeDir = path.join(repoRoot, 'dist');
    const manifestPath = path.join(chromeDir, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error('dist/manifest.json not found. Run "npm run build" before packaging chrome.');
    }
    const destZip = path.join(outputDir, 'ACULYX-chrome.zip');
    const files = collectFiles(chromeDir, 'chrome');
    return writeZipArchive(files, destZip, { overwrite });
  }

  if (target === 'firefox') {
    const firefoxDir = path.join(repoRoot, 'dist-firefox');
    const manifestPath = path.join(firefoxDir, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error('dist-firefox/manifest.json not found. Run "npm run build:firefox" before packaging firefox.');
    }
    const destZip = path.join(outputDir, 'ACULYX-firefox.zip');
    const files = collectFiles(firefoxDir, 'firefox');
    return writeZipArchive(files, destZip, { overwrite });
  }

  throw new Error(`Unknown packaging target: "${target}". Valid targets: source, full, chrome, firefox, all.`);
}

/**
 * Generates SHA256SUMS manifest file for generated release archives
 */
export function generateChecksumManifest(outputDir) {
  const archives = [
    'ACULYX-source.zip',
    'ACULYX-full.zip',
    'ACULYX-chrome.zip',
    'ACULYX-firefox.zip',
    'ACULYX.zip',
  ];
  const lines = [];
  for (const name of archives) {
    const fullPath = path.join(outputDir, name);
    if (fs.existsSync(fullPath)) {
      const data = fs.readFileSync(fullPath);
      const hash = crypto.createHash('sha256').update(data).digest('hex');
      lines.push(`${hash}  ${name}`);
    }
  }
  if (lines.length > 0) {
    const manifestPath = path.join(outputDir, 'SHA256SUMS');
    fs.writeFileSync(manifestPath, lines.join('\n') + '\n', 'utf8');
    return { manifestPath, lines };
  }
  return null;
}

/**
 * CLI runner
 */
const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isCli) {
  let target = 'all';
  let outputDir = '';
  let overwrite = false;

  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--target' && args[i + 1]) {
      target = args[i + 1];
      i++;
    } else if (args[i] === '--output-dir' && args[i + 1]) {
      outputDir = args[i + 1];
      i++;
    } else if (args[i] === '--overwrite' || args[i] === '--force') {
      overwrite = true;
    }
  }

  if (!outputDir) {
    outputDir = path.resolve(repoRoot, '..');
  } else {
    outputDir = path.resolve(outputDir);
  }

  const targets = target === 'all' ? ['source', 'full', 'chrome', 'firefox'] : [target];

  console.log(`Packaging ACULYX release archives [${targets.join(', ')}] -> ${outputDir}`);
  for (const t of targets) {
    try {
      const info = packTarget(t, outputDir, { overwrite });
      const mb = (info.sizeBytes / (1024 * 1024)).toFixed(2);
      console.log(`✓ Packed ${path.basename(info.path)} (${mb} MB, ${info.fileCount} files)`);
    } catch (err) {
      console.error(`Packaging failed for target "${t}": ${err.message}`);
      process.exit(1);
    }
  }

  if (target === 'all') {
    const checksums = generateChecksumManifest(outputDir);
    if (checksums) {
      console.log(`✓ Generated ${path.basename(checksums.manifestPath)} with ${checksums.lines.length} archive checksums`);
    }
  }
}
