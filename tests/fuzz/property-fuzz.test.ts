import { describe, it, expect } from 'vitest';
import { sanitizeEvidence, redactUrlQueryParams } from '../../src/rules/utils';
import { computeScore } from '../../src/rules/scoring';
import { assertNoSensitiveSecrets } from '../../src/shared/storage';
import type { TabState, Finding, CookieRecord } from '../../src/shared/types';

describe('Property & Fuzz Tests', () => {
  describe('sanitizeEvidence', () => {
    it('handles oversized inputs safely without ReDoS', () => {
      const hugeInput = 'A'.repeat(10000);
      const start = performance.now();
      const result = sanitizeEvidence(hugeInput);
      const end = performance.now();
      expect(result.length).toBeLessThanOrEqual(600); // Truncation length plus suffix
      expect(end - start).toBeLessThan(50); // Should be very fast
    });

    it('handles BiDi override and control characters', () => {
      const bidi = '\u202E' + 'test' + '\u202C' + '\x00\x08';
      const sanitized = sanitizeEvidence(bidi);
      // Assuming it strips control chars or handles them safely. It should not throw.
      expect(typeof sanitized).toBe('string');
      // Should not contain null byte
      expect(sanitized.includes('\x00')).toBe(false);
    });

    it('is idempotent', () => {
      const x = 'Hello <script>alert(1)</script>';
      const once = sanitizeEvidence(x);
      const twice = sanitizeEvidence(once);
      expect(once).toBe(twice);
    });
  });

  describe('redactUrlQueryParams', () => {
    it('is idempotent', () => {
      const url = 'https://example.com/path?secret=123&token=abc';
      const once = redactUrlQueryParams(url);
      const twice = redactUrlQueryParams(once);
      expect(once).toBe(twice);
    });
  });

  describe('computeScore', () => {
    it('always returns valid score and grade', () => {
      for (let i = 0; i < 100; i++) {
        // Fuzz findings array
        const numFindings = Math.floor(Math.random() * 20);
        const findings: Finding[] = [];
        for (let j = 0; j < numFindings; j++) {
          findings.push({
            ruleId: `HSTS-00${(j % 3) + 1}`,
            title: 'Test Rule',
            category: 'header',
            severity: ['info', 'low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 5)] as Finding['severity'],
            evidence: 'test',
            recommendation: 'Fix it',
            reference: 'https://example.com',
          });
        }

        const { score, grade } = computeScore(findings);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
        expect(Number.isNaN(score)).toBe(false);
        expect(['A', 'B', 'C', 'D', 'F']).toContain(grade);
      }
    });
  });

  describe('assertNoSensitiveSecrets', () => {
    it('catches raw cookie values', () => {
      const badState = {
        tabId: 1,
        origin: 'https://example.com',
        cookies: [
          { name: 'session', domain: 'example.com', path: '/', secure: true, httpOnly: true, value: 'secret123' } as unknown as CookieRecord
        ],
        hops: [],
        apiEndpoints: new Map()
      } as unknown as TabState;
      expect(() => assertNoSensitiveSecrets(badState)).toThrowError(/Cookie value detected/);
    });

    it('catches unredacted set-cookie headers', () => {
      const badState = {
        tabId: 1,
        origin: 'https://example.com',
        cookies: [],
        hops: [
          {
            url: 'https://example.com',
            status: 200,
            headers: { 'set-cookie': 'session=secret123; Secure; HttpOnly' },
            rawHeaders: [],
          }
        ],
        apiEndpoints: new Map()
      } as unknown as TabState;
      expect(() => assertNoSensitiveSecrets(badState)).toThrowError(/Unredacted/);
    });

    it('passes redacted cookie values', () => {
      const goodState = {
        tabId: 1,
        origin: 'https://example.com',
        cookies: [
          { name: 'session', domain: 'example.com', path: '/', secure: true, httpOnly: true } as unknown as CookieRecord // no value property
        ],
        hops: [
          {
            url: 'https://example.com',
            status: 200,
            headers: { 'set-cookie': 'session=[REDACTED]; Secure; HttpOnly' },
            rawHeaders: [],
          }
        ],
        apiEndpoints: new Map()
      } as unknown as TabState;
      expect(() => assertNoSensitiveSecrets(goodState)).not.toThrow();
    });
  });
});
