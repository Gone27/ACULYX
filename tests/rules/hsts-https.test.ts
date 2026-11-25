/**
 * @file hsts-https.test.ts
 * P2 HSTS rule validation against real HTTPS and HTTP test server fixtures.
 *
 * Uses an ephemeral TLS server (`startHttpsServer`) with real TLS connections and raw HTTP
 * headers to verify HSTS-001..HSTS-005 over HTTPS, while retaining the HTTP server (`startServer`)
 * as a negative control proving insecure HTTP responses do not yield HSTS findings.
 */

import http from 'node:http';
import https from 'node:https';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startServer, startHttpsServer, type TestServerHandle } from '../server';
import { checkHsts } from '../../src/rules/headers/hsts';
import type { Hop } from '../../src/shared/types';

function fetchResponseAsHop(fullUrl: string): Promise<Hop> {
  return new Promise((resolve, reject) => {
    const isHttps = fullUrl.startsWith('https://');
    const mod = isHttps ? https : http;
    const req = mod.get(
      fullUrl,
      isHttps ? { rejectUnauthorized: false } : {},
      (res) => {
        const headers: Record<string, string> = {};
        const rawHeaders: Array<{ name: string; value: string }> = [];

        for (let i = 0; i < res.rawHeaders.length; i += 2) {
          const name = res.rawHeaders[i] ?? '';
          const value = res.rawHeaders[i + 1] ?? '';
          rawHeaders.push({ name, value });
          const lower = name.toLowerCase();
          headers[lower] = headers[lower] !== undefined ? `${headers[lower]}, ${value}` : value;
        }

        res.resume();
        res.on('end', () => {
          resolve({
            requestId: `req-${Math.random().toString(36).slice(2)}`,
            url: fullUrl,
            status: res.statusCode ?? 200,
            headers,
            rawHeaders,
            fromCache: false,
            isHstsUpgrade: false,
            capturedAt: 'onResponseStarted',
            headersDiffer: false,
            timestamp: Date.now(),
          });
        });
      },
    );
    req.on('error', reject);
  });
}

describe('P2 HSTS Validation with Real HTTPS & HTTP Fixtures', () => {
  let httpHandle: TestServerHandle;
  let httpsHandle: TestServerHandle;

  beforeAll(async () => {
    [httpHandle, httpsHandle] = await Promise.all([
      startServer(0, '127.0.0.1'),
      startHttpsServer(0, '127.0.0.1'),
    ]);
  });

  afterAll(async () => {
    await Promise.all([
      new Promise<void>((resolve) => httpHandle.server.close(() => resolve())),
      new Promise<void>((resolve) => httpsHandle.server.close(() => resolve())),
    ]);
  });

  it('detects HSTS-001 (missing header) over real HTTPS /hsts-absent', async () => {
    const hop = await fetchResponseAsHop(`${httpsHandle.baseUrl}/hsts-absent`);
    expect(hop.headers['strict-transport-security']).toBeUndefined();

    const findings = checkHsts(hop);
    expect(findings.map((f) => f.ruleId)).toEqual(['HSTS-001']);
    expect(findings[0]?.severity).toBe('high');
  });

  it('detects HSTS-002 (short max-age) and HSTS-003 (missing includeSubDomains) over real HTTPS /hsts-short', async () => {
    const hop = await fetchResponseAsHop(`${httpsHandle.baseUrl}/hsts-short`);
    expect(hop.headers['strict-transport-security']).toBe('max-age=86400');

    const findings = checkHsts(hop);
    expect(findings.map((f) => f.ruleId)).toEqual(['HSTS-002', 'HSTS-003']);
  });

  it('detects HSTS-003 over real HTTPS /hsts-no-subdomains when max-age >= 1y without includeSubDomains', async () => {
    const hop = await fetchResponseAsHop(`${httpsHandle.baseUrl}/hsts-no-subdomains`);
    expect(hop.headers['strict-transport-security']).toBe('max-age=31536000');

    const findings = checkHsts(hop);
    expect(findings.map((f) => f.ruleId)).toEqual(['HSTS-003']);
    expect(findings[0]?.severity).toBe('low');
  });

  it('detects HSTS-002, HSTS-003, and HSTS-004 when preload token lacks directives over real HTTPS', async () => {
    const hop = await fetchResponseAsHop(`${httpsHandle.baseUrl}/hsts-preload-incomplete`);
    expect(hop.headers['strict-transport-security']).toBe('max-age=86400; preload');

    const findings = checkHsts(hop);
    expect(findings.map((f) => f.ruleId)).toEqual(['HSTS-002', 'HSTS-003', 'HSTS-004']);
  });

  it('emits zero HSTS findings over real HTTPS /hsts-preload-valid (max-age=31536000; includeSubDomains; preload)', async () => {
    const hop = await fetchResponseAsHop(`${httpsHandle.baseUrl}/hsts-preload-valid`);
    expect(hop.headers['strict-transport-security']).toBe('max-age=31536000; includeSubDomains; preload');

    const findings = checkHsts(hop);
    expect(findings).toHaveLength(0);
  });

  it('retains HTTP routes as negative controls: insecure HTTP never produces HSTS findings even when STS header is sent', async () => {
    const httpShortHop = await fetchResponseAsHop(`${httpHandle.baseUrl}/hsts-short`);
    expect(httpShortHop.url.startsWith('http://')).toBe(true);
    expect(httpShortHop.headers['strict-transport-security']).toBe('max-age=86400');
    expect(checkHsts(httpShortHop)).toHaveLength(0);

    const httpAbsentHop = await fetchResponseAsHop(`${httpHandle.baseUrl}/hsts-absent`);
    expect(checkHsts(httpAbsentHop)).toHaveLength(0);
  });
});
