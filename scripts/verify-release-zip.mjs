import fs from 'node:fs';

const zipPath = 'D:/Projects/ACULYX.zip';

if (!fs.existsSync(zipPath)) {
  console.error(`ZIP file not found: ${zipPath}`);
  process.exit(1);
}

const buf = fs.readFileSync(zipPath);
const sig = Buffer.from([0x50, 0x4b, 0x01, 0x02]); // Central directory header PK\x01\x02
let offset = 0;
const entries = [];

while ((offset = buf.indexOf(sig, offset)) !== -1) {
  if (offset + 46 > buf.length) break;
  const nameLen = buf.readUInt16LE(offset + 28);
  const extraLen = buf.readUInt16LE(offset + 30);
  const commentLen = buf.readUInt16LE(offset + 32);
  const name = buf.toString('utf8', offset + 46, offset + 46 + nameLen);
  entries.push(name);
  offset += 46 + nameLen + extraLen + commentLen;
}

console.log(`Verified ${entries.length} entries in ${zipPath}`);

const backslashEntries = entries.filter((e) => e.includes('\\'));
const excludedDirPrefixes = [
  '.agents/',
  '.system_generated/',
  'node_modules/',
  '.git/',
  'test-results/',
  'playwright-report/',
  'coverage/',
  '.vite-temp/',
];

const forbiddenEntries = entries.filter((e) => {
  return excludedDirPrefixes.some((p) => e.startsWith(p)) || e.endsWith('.zip');
});

console.log(`Backslash entries count: ${backslashEntries.length}`);
console.log(`Forbidden/excluded entries count: ${forbiddenEntries.length}`);

if (backslashEntries.length > 0) {
  console.error('Entries contain backslashes:', backslashEntries.slice(0, 5));
  process.exit(1);
}

if (forbiddenEntries.length > 0) {
  console.error('Archive contains forbidden files:', forbiddenEntries.slice(0, 5));
  process.exit(1);
}

const projectRoot = 'D:/Projects/ACULYX';
const rootItems = fs.readdirSync(projectRoot);
const internalZips = rootItems.filter((f) => f.endsWith('.zip'));

console.log('Internal ZIP files in root:', internalZips.length === 0 ? '0 (Clean)' : internalZips);

if (internalZips.length > 0) {
  process.exit(1);
}

console.log('ALL VERIFICATION INVARIANTS SATISFIED.');
