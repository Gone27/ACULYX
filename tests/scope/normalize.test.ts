import { describe, it, expect } from 'vitest';
import {
  normalizeHostname,
  extractExplicitPort,
  parseScheme,
  normalizeScopeTarget,
} from '../../src/shared/scope/normalize';

describe('Scope Normalization', () => {
  describe('normalizeHostname', () => {
    it('lowercases uppercase domains', () => {
      expect(normalizeHostname('EXAMPLE.COM')).toBe('example.com');
      expect(normalizeHostname('API.Target.IO')).toBe('api.target.io');
    });

    it('strips trailing dots cleanly', () => {
      expect(normalizeHostname('example.com.')).toBe('example.com');
      expect(normalizeHostname('sub.domain.org...')).toBe('sub.domain.org');
    });

    it('converts IDNA internationalized domain names to punycode', () => {
      expect(normalizeHostname('münchen.de')).toBe('xn--mnchen-3ya.de');
      expect(normalizeHostname('xn--e1afmkfd.xn--p1ai')).toBe('xn--e1afmkfd.xn--p1ai');
    });

    it('preserves IPv6 bracketed hosts', () => {
      expect(normalizeHostname('[::1]')).toBe('[::1]');
      expect(normalizeHostname('[2001:db8::1]')).toBe('[2001:db8::1]');
    });

    it('throws on empty hostname', () => {
      expect(() => normalizeHostname('')).toThrow(/Hostname cannot be empty/);
      expect(() => normalizeHostname('   ')).toThrow(/Hostname cannot be empty/);
    });
  });

  describe('extractExplicitPort', () => {
    it('preserves explicit standard ports 80 and 443 without stripping', () => {
      expect(extractExplicitPort('https://example.com:443')).toBe(443);
      expect(extractExplicitPort('http://example.com:80')).toBe(80);
      expect(extractExplicitPort('example.com:443')).toBe(443);
    });

    it('extracts custom ports from hosts and full URLs', () => {
      expect(extractExplicitPort('api.example.com:8443')).toBe(8443);
      expect(extractExplicitPort('https://target.io:9000/login?token=abc#hash')).toBe(9000);
      expect(extractExplicitPort('[::1]:8080')).toBe(8080);
    });

    it('returns undefined when no port is specified', () => {
      expect(extractExplicitPort('https://example.com/')).toBeUndefined();
      expect(extractExplicitPort('api.example.com')).toBeUndefined();
    });

    it('throws on out-of-range or invalid ports', () => {
      expect(() => extractExplicitPort('example.com:70000')).toThrow(/Invalid port number/);
      expect(() => extractExplicitPort('example.com:0')).toThrow(/Invalid port number/);
      expect(() => extractExplicitPort('example.com:abc')).toThrow(/Invalid port number/);
    });
  });

  describe('parseScheme', () => {
    it('extracts http and https schemes', () => {
      expect(parseScheme('https://example.com')).toBe('https');
      expect(parseScheme('http://example.com')).toBe('http');
      expect(parseScheme('wss://stream.example.com')).toBe('wss');
    });

    it('returns undefined when scheme is omitted', () => {
      expect(parseScheme('example.com')).toBeUndefined();
      expect(parseScheme('*.example.com')).toBeUndefined();
    });
  });

  describe('normalizeScopeTarget', () => {
    it('normalizes an apex domain pattern', () => {
      const target = normalizeScopeTarget('example.com');
      expect(target.hostname).toBe('example.com');
      expect(target.isWildcard).toBe(false);
      expect(target.scheme).toBeUndefined();
      expect(target.port).toBeUndefined();
    });

    it('normalizes a wildcard domain pattern', () => {
      const target = normalizeScopeTarget('*.example.com');
      expect(target.hostname).toBe('example.com');
      expect(target.isWildcard).toBe(true);
    });

    it('preserves scheme and explicit port on full URLs with path and userinfo', () => {
      const target = normalizeScopeTarget('https://user:pass@staging.example.com:8443/login?q=1#sec');
      expect(target.scheme).toBe('https');
      expect(target.hostname).toBe('staging.example.com');
      expect(target.port).toBe(8443);
      expect(target.isWildcard).toBe(false);
    });

    it('handles wildcard with explicit port', () => {
      const target = normalizeScopeTarget('*.target.io:9443');
      expect(target.hostname).toBe('target.io');
      expect(target.port).toBe(9443);
      expect(target.isWildcard).toBe(true);
    });

    it('throws on empty or non-string input', () => {
      expect(() => normalizeScopeTarget('')).toThrow(/Scope target must be a non-empty string/);
    });
  });
});
