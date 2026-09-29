import { describe, it, expect } from 'vitest';
import { checkCors } from '../../src/rules/headers/cors';

function makeHop(headers: Record<string, string>): any {
  return {
    headers,
    rawHeaders: Object.entries(headers).map(([name, value]) => ({ name, value }))
  };
}

describe('checkCors', () => {
  it('flags ACAO: * on non-HTML responses', () => {
    const findings = checkCors(makeHop({ 'access-control-allow-origin': '*', 'content-type': 'application/json' }));
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('CORS-001');
  });

  it('skips HTML responses even with ACAO: *', () => {
    const findings = checkCors(makeHop({ 'access-control-allow-origin': '*', 'content-type': 'text/html; charset=utf-8' }));
    expect(findings.length).toBe(0);
  });
});
