import { describe, it, expect } from 'vitest';
import { validateScopeRule, validateScopeProfile } from '../../src/shared/scope/validate';

describe('Scope Validation', () => {
  describe('validateScopeRule', () => {
    it('accepts valid include and exclude rules', () => {
      expect(validateScopeRule({ pattern: 'example.com', type: 'include' })).toEqual({ valid: true });
      expect(validateScopeRule({ pattern: '*.example.com', type: 'exclude' })).toEqual({ valid: true });
      expect(validateScopeRule({ pattern: 'https://api.target.com:8443', type: 'include' })).toEqual({ valid: true });
    });

    it('rejects non-object rules', () => {
      expect(validateScopeRule(null).valid).toBe(false);
      expect(validateScopeRule(undefined).valid).toBe(false);
      expect(validateScopeRule('string').valid).toBe(false);
    });

    it('rejects missing or empty pattern', () => {
      expect(validateScopeRule({ pattern: '', type: 'include' }).valid).toBe(false);
      expect(validateScopeRule({ pattern: '   ', type: 'include' }).valid).toBe(false);
      expect(validateScopeRule({ type: 'include' }).valid).toBe(false);
    });

    it('rejects invalid rule type', () => {
      expect(validateScopeRule({ pattern: 'example.com', type: 'invalid' }).valid).toBe(false);
      expect(validateScopeRule({ pattern: 'example.com' }).valid).toBe(false);
    });

    it('rejects malformed wildcard patterns fail-closed', () => {
      const res = validateScopeRule({ pattern: '*example.com', type: 'include' });
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/wildcards must use the explicit "\*\." prefix/);
    });

    it('rejects invalid port patterns', () => {
      const res = validateScopeRule({ pattern: 'example.com:99999', type: 'include' });
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Invalid port number/);
    });
  });

  describe('validateScopeProfile', () => {
    it('accepts a valid scope profile with rules', () => {
      const profile = {
        id: 'prof-1',
        name: 'HackerOne Target',
        rules: [
          { pattern: 'example.com', type: 'include' },
          { pattern: '*.example.com', type: 'include' },
          { pattern: 'out-of-scope.example.com', type: 'exclude' },
        ],
      };
      expect(validateScopeProfile(profile)).toEqual({ valid: true });
    });

    it('rejects non-object profile', () => {
      expect(validateScopeProfile(null).valid).toBe(false);
      expect(validateScopeProfile('str').valid).toBe(false);
    });

    it('rejects profile with empty id or name', () => {
      expect(validateScopeProfile({ id: '', name: 'Test', rules: [] }).valid).toBe(false);
      expect(validateScopeProfile({ id: '1', name: '  ', rules: [] }).valid).toBe(false);
    });

    it('rejects profile with non-array rules', () => {
      expect(validateScopeProfile({ id: '1', name: 'Test', rules: null }).valid).toBe(false);
    });

    it('rejects profile containing an invalid rule', () => {
      const profile = {
        id: 'prof-1',
        name: 'HackerOne Target',
        rules: [
          { pattern: 'example.com', type: 'include' },
          { pattern: '*example.com', type: 'include' },
        ],
      };
      const res = validateScopeProfile(profile);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Rule at index 1 is invalid/);
    });
  });
});
