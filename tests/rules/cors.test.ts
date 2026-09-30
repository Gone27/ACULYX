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

  it('skips document responses with missing Content-Type even with ACAO: *', () => {
    const findings = checkCors(makeHop({ 'access-control-allow-origin': '*' }));
    expect(findings.length).toBe(0);
  });

  it("flags ACAO: null as CORS-001 with high/medium severity", () => {
    const findings = checkCors(makeHop({ 'access-control-allow-origin': 'null', 'content-type': 'application/json' }));
    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('CORS-001');
    expect(findings[0]?.confidence).toBe('deterministic');
    expect(findings[0]?.title).toContain("'null'");
  });

  it('flags reflected Origin with credentials as CORS-001 medium with heuristic confidence', () => {
    const apiHop = {
      ...makeHop({
        'access-control-allow-origin': 'https://evil.example.com',
        'access-control-allow-credentials': 'true',
        'content-type': 'application/json',
      }),
      tabId: 1,
      normalizedPath: 'https://example.com/api',
      method: 'GET',
      requestOrigin: 'https://evil.example.com',
    };
    const findings = checkCors(apiHop);
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.confidence).toBe('heuristic');
    expect(findings[0]?.title).toContain('potential reflection');
  });

  it('does not skip HTML responses for API hops with ACAO: *', () => {
    const apiHop = {
      ...makeHop({
        'access-control-allow-origin': '*',
        'content-type': 'text/html; charset=utf-8',
      }),
      tabId: 1,
      normalizedPath: 'https://example.com/api/fragment',
      method: 'GET',
      requestOrigin: 'https://example.com',
    };
    const findings = checkCors(apiHop);
    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('CORS-001');
  });
});
