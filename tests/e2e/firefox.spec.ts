/**
 * @file firefox.spec.ts
 * Playwright E2E integration suite executing in live Firefox runtime.
 *
 * Verifies:
 *  1. Dynamic RDP temporary addon installation of dist-firefox/ in live Firefox browser.
 *  2. Header analysis, cookie inspection, and DOM security in live Firefox runtime.
 */

import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, firefox } from '@playwright/test';
import { startServer } from '../server/index';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const firefoxDistPath = path.resolve(__dirname, '../../dist-firefox');

/**
 * Connects to Firefox Remote Debugging Protocol (RDP) server and installs the temporary extension.
 * Retries connection with backoff to accommodate browser debugger server initialization in CI.
 */
function installFirefoxAddon(port: number, addonPath: string): Promise<{ id: string }> {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const maxAttempts = 30;
    let socket: net.Socket | null = null;
    let buffer = '';

    function tryConnect() {
      attempts++;
      socket = net.connect({ port, host: '127.0.0.1' });
      buffer = '';

      function send(obj: Record<string, unknown>) {
        const msg = JSON.stringify(obj);
        socket?.write(`${Buffer.byteLength(msg)}:${msg}`);
      }

      socket.on('connect', () => {
        send({ to: 'root', type: 'getRoot' });
      });

      socket.on('data', (chunk) => {
        buffer += chunk.toString();
        while (true) {
          const colonIdx = buffer.indexOf(':');
          if (colonIdx === -1) break;
          const len = parseInt(buffer.slice(0, colonIdx), 10);
          if (isNaN(len)) {
            socket?.destroy();
            return reject(new Error('Invalid RDP length prefix'));
          }
          if (buffer.length < colonIdx + 1 + len) break;
          const jsonStr = buffer.slice(colonIdx + 1, colonIdx + 1 + len);
          buffer = buffer.slice(colonIdx + 1 + len);

          try {
            const packet = JSON.parse(jsonStr) as {
              addonsActor?: string;
              addon?: { id: string };
              error?: string;
              message?: string;
            };

            if (typeof packet.addonsActor === 'string' && packet.addonsActor.length > 0) {
              send({
                to: packet.addonsActor,
                type: 'installTemporaryAddon',
                addonPath: path.resolve(addonPath),
              });
            } else if (packet.addon !== undefined) {
              socket?.end();
              return resolve(packet.addon);
            } else if (typeof packet.error === 'string' && packet.error.length > 0) {
              socket?.end();
              return reject(new Error(`RDP Error: ${packet.error} - ${packet.message ?? ''}`));
            }
          } catch (e) {
            socket?.destroy();
            return reject(e instanceof Error ? e : new Error(String(e)));
          }
        }
      });

      socket.on('error', (err) => {
        socket?.destroy();
        if (attempts < maxAttempts) {
          setTimeout(tryConnect, 100);
        } else {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    }

    tryConnect();
  });
}

test.describe('Firefox Runtime Extension E2E', () => {
  test('launches Firefox, installs ACULYX via RDP, and verifies security headers and cookies', async () => {
    const debugPort = 14920 + Math.floor(Math.random() * 500);
    const { server, baseUrl } = await startServer(3510, '127.0.0.1');

    const browser = await firefox.launch({
      headless: true,
      args: ['-start-debugger-server', String(debugPort)],
      firefoxUserPrefs: {
        'devtools.debugger.remote-enabled': true,
        'devtools.debugger.prompt-connection': false,
        'xpinstall.signatures.required': false,
        'extensions.autoDisableScopes': 0,
      },
    });

    try {
      // 1. Install ACULYX extension in live Firefox
      const addon = await installFirefoxAddon(debugPort, firefoxDistPath);
      expect(addon).toBeDefined();
      expect(addon.id).toBe('aculyx@dhyanpatel.com');

      const page = await browser.newPage();

      // 2. Navigate to /good-headers in live Firefox
      const response = await page.goto(`${baseUrl}/good-headers`);
      expect(response).not.toBeNull();
      expect(response?.headers()['x-content-type-options']).toBe('nosniff');
      expect(response?.headers()['x-frame-options']).toBe('DENY');
      expect(response?.headers()['cache-control']).toBe('no-store');
      expect(response?.headers()['strict-transport-security']).toBe('max-age=31536000; includeSubDomains');

      // 3. Verify /cookie-test sets cookies properly in Firefox
      await page.goto(`${baseUrl}/cookie-test`);
      const cookies = await page.context().cookies();
      const sessionCookie = cookies.find((c) => c.name === 'test_session');
      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.httpOnly).toBe(true);

      // 4. Verify /xss-in-headers does not execute scripts in Firefox
      let xssTriggered = false;
      page.on('dialog', () => {
        xssTriggered = true;
      });
      await page.goto(`${baseUrl}/xss-in-headers`);
      expect(xssTriggered).toBe(false);
    } finally {
      await browser.close();
      server.close();
    }
  });
});
