import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');
const firefoxDistDir = path.join(rootDir, 'dist-firefox');

if (!fs.existsSync(distDir)) {
  console.error('Error: dist directory does not exist. Run "npm run build" first.');
  process.exit(1);
}

// 1. Copy dist/ to dist-firefox/ recursively
fs.cpSync(distDir, firefoxDistDir, { recursive: true });

// 2. Read compiled manifest
const manifestPath = path.join(firefoxDistDir, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// 3. Firefox MV3 adjustments
manifest.browser_specific_settings = {
  gecko: {
    id: "seccheck@security-checker.local",
    strict_min_version: "109.0"
  }
};

if (manifest.background) {
  const sw = manifest.background.service_worker;
  manifest.background = {
    scripts: [sw || "service-worker-loader.js"],
    type: "module"
  };
}

if (manifest.optional_host_permissions && !manifest.optional_permissions) {
  manifest.optional_permissions = [...manifest.optional_host_permissions];
}

delete manifest.minimum_chrome_version;

// 4. Save adjusted manifest
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

console.log('✓ Firefox MV3 build generated successfully in dist-firefox/');
