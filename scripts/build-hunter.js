import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');
const hunterDistDir = path.join(rootDir, 'dist-hunter');

if (!fs.existsSync(distDir)) {
  console.error('Error: dist directory does not exist. Run "npm run build" first.');
  process.exit(1);
}

// 1. Clean and copy dist/ to dist-hunter/ recursively
if (fs.existsSync(hunterDistDir)) {
  fs.rmSync(hunterDistDir, { recursive: true, force: true });
}
fs.cpSync(distDir, hunterDistDir, { recursive: true });

// 2. Read compiled manifest
const manifestPath = path.join(hunterDistDir, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// 3. Configure Hunter Edition manifest
manifest.name = 'ACULYX (Hunter Edition): Active Probe Security Checker';
manifest.short_name = 'ACULYX-Hunter';
manifest.description = 'ACULYX Hunter Edition: Multi-sensor passive security intelligence with gated, active out-of-band HTTP/OOB probing.';

// Relax connect-src from 'none' to allow active HTTP probes to targets
if (manifest.content_security_policy) {
  manifest.content_security_policy.extension_pages = "script-src 'self'; object-src 'none'; connect-src 'self' http: https:";
}

// Grant host permissions so background fetch can probe target endpoints without CORS blocking
manifest.host_permissions = ['<all_urls>'];

// 4. Save adjusted manifest
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

console.log('✓ Hunter Edition build generated successfully in dist-hunter/');
