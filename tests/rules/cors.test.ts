import { describe, it, expect } from 'vitest';
import { checkCors } from '../../src/rules/headers/cors';
import type { Hop } from '../../src/shared/types';

function makeHop(headers: Record<string, string>): Hop {
  return {
    requestId: 'test',
    url: 'https://example.com/',
    status: 200,
    headers,
    rawHeaders: Object.entries(headers).map(([name, value]) => ({ name, value })),
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
    redirectCount: 0,
  };
}

describe('checkCors', () => {
  it('flags ACAO: * on non-HTML responses', () => {
    const findings = checkCors(makeHop({ 'access-control-allow-origin': '*', 'content-type': 'application/json' }));
    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('CORS-001');
  });

  it('skips HTML responses even with ACAO: *', () => {
    const findings = checkCors(makeHop({ 'access-control-allow-origin': '*', 'content-type': 'text/html; charset=utf-8' }));
    expect(findings.length).toBe(0);
  });
});
