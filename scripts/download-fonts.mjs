import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fontsDir = path.resolve(__dirname, '..', 'src', 'assets', 'fonts');

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return get(res.headers.location).then(resolve, reject);
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

async function main() {
  const cssUrl = 'https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Space+Grotesk:wght@400;700&display=swap';
  console.log('Fetching Google Fonts CSS...');
  const cssBuffer = await get(cssUrl);
  const css = cssBuffer.toString('utf8');
  console.log('CSS fetched, length:', css.length);

  if (!fs.existsSync(fontsDir)) {
    fs.mkdirSync(fontsDir, { recursive: true });
  }

  const blocks = css.split('@font-face').slice(1);
  const targets = [
    { family: 'Space Grotesk', weight: '400', filename: 'SpaceGrotesk-Regular.woff2' },
    { family: 'Space Grotesk', weight: '700', filename: 'SpaceGrotesk-Bold.woff2' },
    { family: 'IBM Plex Mono', weight: '400', filename: 'IBMPlexMono-Regular.woff2' },
    { family: 'IBM Plex Mono', weight: '600', filename: 'IBMPlexMono-SemiBold.woff2' },
  ];

  for (const target of targets) {
    let found = false;
    for (const block of blocks) {
      const famMatch = block.match(/font-family:\s*['"]?([^'";]+)/);
      const wtMatch = block.match(/font-weight:\s*(\d+)/);
      const urlMatch = block.match(/src:\s*url\((https:[^)]+)\)\s*format\(['"]woff2['"]\)/);
      const uniMatch = block.match(/unicode-range:\s*([^;]+);/);

      if (famMatch && wtMatch && urlMatch && uniMatch) {
        const fam = famMatch[1].trim();
        const wt = wtMatch[1].trim();
        const uni = uniMatch[1].trim();
        if (fam === target.family && wt === target.weight && uni.includes('U+0000-00FF')) {
          console.log(`Found ${target.filename}: ${urlMatch[1]}`);
          const fontBuf = await get(urlMatch[1]);
          fs.writeFileSync(path.join(fontsDir, target.filename), fontBuf);
          console.log(`Saved ${target.filename} (${fontBuf.length} bytes)`);
          found = true;
          break;
        }
      }
    }
    if (!found) {
      console.warn(`Could not find latin subset for ${target.filename}`);
    }
  }
}

main().catch(err => {
  console.error('Font download error:', err);
  process.exit(1);
});
