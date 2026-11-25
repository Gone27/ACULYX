/**
 * @file index.ts
 * Minimal Express HTTP server for header-security e2e testing.
 *
 * Can be started programmatically from test code or run standalone with
 * `node --loader ts-node/esm tests/server/index.ts` for manual inspection.
 */

import express from 'express';
import { createServer, type Server as HttpServer } from 'http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'https';
import { createEphemeralTestCert } from './ephemeral-cert';
import { registerRoutes } from './routes';

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

/** Shape returned by {@link startServer} and {@link startHttpsServer}. */
export interface TestServerHandle {
  /** The underlying Node.js HTTP/HTTPS server (call `.close()` to shut down). */
  server: HttpServer | HttpsServer;
  /** Base URL the server is listening on, e.g. `http://127.0.0.1:3456` or `https://127.0.0.1:3457`. */
  baseUrl: string;
}

/**
 * Start the Express HTTP test server on the given port (pass 0 for ephemeral port).
 */
export function startServer(port = 3456, host = '127.0.0.1'): Promise<TestServerHandle> {
  const app = express();

  // Disable the default "X-Powered-By: Express" header so it does not
  // interfere with the LEAK-001 rule tests on unrelated routes.
  app.disable('x-powered-by');

  registerRoutes(app);

  return new Promise<TestServerHandle>((resolve, reject) => {
    const server = createServer(app);
    server.on('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const boundPort = typeof addr === 'object' && addr !== null ? addr.port : port;
      resolve({ server, baseUrl: `http://${host}:${boundPort}` });
    });
  });
}

/**
 * Start the Express HTTPS test server with an ephemeral in-memory self-signed certificate.
 * Used for valid TLS HSTS fixture testing (absent, short max-age, includeSubDomains, preload).
 */
export function startHttpsServer(port = 0, host = '127.0.0.1'): Promise<TestServerHandle> {
  const app = express();
  app.disable('x-powered-by');
  registerRoutes(app);

  const tls = createEphemeralTestCert();

  return new Promise<TestServerHandle>((resolve, reject) => {
    const server = createHttpsServer({ key: tls.key, cert: tls.cert }, app);
    server.on('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const boundPort = typeof addr === 'object' && addr !== null ? addr.port : port;
      resolve({ server, baseUrl: `https://${host}:${boundPort}` });
    });
  });
}

// --------------------------------------------------------------------------
// Standalone entry-point
// Allow running: `node --loader ts-node/esm tests/server/index.ts`
// --------------------------------------------------------------------------

// `import.meta.url` is only defined in ESM context. The conditional makes
// this file safe to import in both CJS and ESM environments.
if (
  typeof import.meta !== 'undefined' &&
  typeof process.argv[1] === 'string' &&
  import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`
) {
  void startServer().then(({ baseUrl }) => {
    process.stdout.write(`Test server running at ${baseUrl}\n`);
    process.stdout.write('Press Ctrl+C to stop.\n');
  });
}
