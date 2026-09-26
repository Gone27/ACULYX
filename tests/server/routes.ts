/**
 * @file routes.ts
 * Express route handlers for the header-security test server.
 *
 * Each route exercises a specific security-header scenario so that e2e tests
 * and manual extension testing can verify detection against a real HTTP
 * server.
 *
 * Security note: cookie values here are static test placeholders.
 * No real credentials are generated or stored.
 */

import type { Express, Request, Response } from 'express';

// --------------------------------------------------------------------------
// Shared HTML template — keeps body content minimal and reproducible.
// --------------------------------------------------------------------------

/** Build a plain HTML page body identifying the route. */
function htmlPage(routeName: string, extra = ''): string {
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head><meta charset="UTF-8"><title>Test: ' + routeName + '</title></head>',
    '<body>',
    '<h1>Route: ' + routeName + '</h1>',
    extra ? '<p>' + extra + '</p>' : '',
    '</body>',
    '</html>',
  ].join('\n');
}

// --------------------------------------------------------------------------
// Route: GET /good-headers
// All recommended security headers correctly set.
// --------------------------------------------------------------------------

function handleGoodHeaders(_req: Request, res: Response): void {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/good-headers'));
}

// --------------------------------------------------------------------------
// Route: GET /no-headers
// No security headers — every applicable rule should fire.
// --------------------------------------------------------------------------

function handleNoHeaders(_req: Request, res: Response): void {
  // Only set the bare minimum that Express adds automatically; nothing extra.
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/no-headers'));
}

// --------------------------------------------------------------------------
// Route: GET /bad-csp
// Deliberately weak CSP: wildcard default-src plus unsafe-inline/eval.
// Expects: CSP-002, CSP-003, CSP-004, CSP-005, CSP-006, CSP-007
// --------------------------------------------------------------------------

function handleBadCsp(_req: Request, res: Response): void {
  res.setHeader(
    'Content-Security-Policy',
    "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/bad-csp'));
}

// --------------------------------------------------------------------------
// Route: GET /cookie-test
// Sets a test session cookie without Cache-Control: no-store.
// Expects: CACHE-001
//
// The cookie value is a static, meaningless test token — never a real secret.
// --------------------------------------------------------------------------

function handleCookieTest(_req: Request, res: Response): void {
  // Static placeholder value — not a real credential.
  res.setHeader('Set-Cookie', 'test_session=REDACTED_IN_TEST; Path=/; HttpOnly');
  // Intentionally omit Cache-Control: no-store to trigger CACHE-001.
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/cookie-test', 'Cookie set by server'));
}

// --------------------------------------------------------------------------
// Route: GET /version-leak
// Server and X-Powered-By headers expose version strings.
// Expects: LEAK-001
// --------------------------------------------------------------------------

function handleVersionLeak(_req: Request, res: Response): void {
  res.setHeader('Server', 'Apache/2.4.51');
  res.setHeader('X-Powered-By', 'PHP/8.1.0');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/version-leak'));
}

// --------------------------------------------------------------------------
// Route: GET /hsts-short
// HSTS header with max-age well below the recommended minimum.
// Expects: HSTS-002, HSTS-003 (no includeSubDomains)
// --------------------------------------------------------------------------

function handleHstsShort(_req: Request, res: Response): void {
  res.setHeader('Strict-Transport-Security', 'max-age=86400');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/hsts-short'));
}

// --------------------------------------------------------------------------
// Route: GET /xss-in-headers
// Returns header values that contain XSS payloads.
// Used to verify the extension popup renders evidence safely (no execution).
//
// IMPORTANT: these values are intentionally placed in non-interpreted response
// headers (X-Custom-Debug) so they do not execute in the browser page itself.
// They should only reach the extension's popup via the rule engine's evidence
// string, where sanitizeEvidence() must neutralise them.
// --------------------------------------------------------------------------

function handleXssInHeaders(_req: Request, res: Response): void {
  // XSS payload in a custom debug header — browsers never render header values
  // as HTML so this is safe for the served page.
  res.setHeader('X-Custom-Debug', '<script>alert(1)</script>');
  // Version-leak-style server header that also contains an XSS token.
  res.setHeader('Server', 'Apache <img src=x onerror=alert(1)>/2.4');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).end(htmlPage('/xss-in-headers'));
}

// --------------------------------------------------------------------------
// Registration
// --------------------------------------------------------------------------

/**
 * Register all test routes on the provided Express application.
 *
 * @param app - The Express application instance to attach routes to.
 */
export function registerRoutes(app: Express): void {
  app.get('/good-headers', handleGoodHeaders);
  app.get('/no-headers', handleNoHeaders);
  app.get('/bad-csp', handleBadCsp);
  app.get('/cookie-test', handleCookieTest);
  app.get('/version-leak', handleVersionLeak);
  app.get('/hsts-short', handleHstsShort);
  app.get('/xss-in-headers', handleXssInHeaders);

  // --------------------------------------------------------------------------
  // Index route: lists available test endpoints for manual inspection.
  // --------------------------------------------------------------------------
  app.get('/', (_req: Request, res: Response) => {
    const routes = [
      '/good-headers  — All security headers correctly set',
      '/no-headers    — No security headers at all',
      '/bad-csp       — Weak CSP with unsafe-inline / unsafe-eval',
      '/cookie-test   — Set-Cookie without Cache-Control: no-store',
      '/version-leak  — Server + X-Powered-By expose version strings',
      '/hsts-short    — HSTS max-age=86400 (too short)',
      '/xss-in-headers— XSS payloads embedded in response headers',
    ].join('\n');

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).end('Header-Security Test Server\n\nAvailable routes:\n' + routes + '\n');
  });
}
