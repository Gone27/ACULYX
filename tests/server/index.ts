/**
 * @file index.ts
 * Minimal Express HTTP server for header-security e2e testing.
 *
 * Can be started programmatically from test code or run standalone with
 * `node --loader ts-node/esm tests/server/index.ts` for manual inspection.
 */

import express from 'express';
import { createServer } from 'http';
import { registerRoutes } from './routes';

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

/** Shape returned by {@link startServer}. */
export interface TestServerHandle {
  /** The underlying Node.js HTTP server (call `.close()` to shut down). */
  server: ReturnType<typeof createServer>;
  /** Base URL the server is listening on, e.g. `http://localhost:3456`. */
  baseUrl: string;
}

/**
 * Start the Express test server on the given port.
 *
 * @param port - TCP port to listen on. Defaults to 3456.
 * @returns A Promise that resolves once the server is accepting connections.
 *
 * @example
 * ```ts
 * const { server, baseUrl } = await startServer(3456);
 * // … run tests …
 * server.close();
 * ```
 */
export function startServer(port = 3456): Promise<TestServerHandle> {
  const app = express();

  // Disable the default "X-Powered-By: Express" header so it does not
  // interfere with the LEAK-001 rule tests on unrelated routes.
  app.disable('x-powered-by');

  registerRoutes(app);

  return new Promise<TestServerHandle>((resolve, reject) => {
    const server = app.listen(port, () => {
      resolve({ server, baseUrl: `http://localhost:${port}` });
    });
    server.on('error', reject);
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
