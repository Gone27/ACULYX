/**
 * @file origin-header.spec.ts
 * Real-browser proof that the Hunter CORS probe can set the Origin header.
 * Browsers treat Origin as a forbidden header name for page scripts, but an extension service worker with
 * host permission does send it. If this test ever fails, executeHunterCorsProbe can no longer reproduce
 * origin reflection and every CORS verdict would silently become "uncertain".
 */
import { test, expect, chromium } from '@playwright/test';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const hunterDist = path.resolve(__dirname, '../../dist-hunter');

test.describe('Hunter CORS probe Origin header (real Chromium)', () => {
  test('extension service worker fetch sends the script-set Origin header', async () => {
    test.skip(!fs.existsSync(hunterDist), 'dist-hunter not built (run npm run build:all)');

    const seen: Array<{ url: string; origin: string }> = [];
    const server = http.createServer((req, res) => {
      seen.push({ url: req.url ?? '', origin: String(req.headers['origin'] ?? '(none)') });
      res.setHeader('Access-Control-Allow-Origin', String(req.headers['origin'] ?? '*'));
      res.end('ok');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    const extDir = path.resolve(__dirname, '../../dist-e2e-origin');
    fs.rmSync(extDir, { recursive: true, force: true });
    fs.cpSync(hunterDist, extDir, { recursive: true });
    const manifestPath = path.join(extDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as { host_permissions?: string[] };
    manifest.host_permissions = ['http://127.0.0.1/*'];
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    let context;
    try {
      context = await chromium.launchPersistentContext('', {
        headless: false,
        args: ['--headless=new', `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
      });
      let [sw] = context.serviceWorkers();
      if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15_000 });

      const status = await sw.evaluate(async (url: string) => {
        const r = await fetch(url, { method: 'GET', headers: { Origin: 'https://evil.example' }, credentials: 'omit', redirect: 'manual', cache: 'no-store', mode: 'cors' });
        return r.status;
      }, `http://127.0.0.1:${port}/origin-probe`);

      expect(status).toBe(200);
      expect(seen.find((s) => s.url === '/origin-probe')?.origin).toBe('https://evil.example');
    } finally {
      if (context) await context.close();
      server.close();
      fs.rmSync(extDir, { recursive: true, force: true });
    }
  });
});
