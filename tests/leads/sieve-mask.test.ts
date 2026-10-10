import { describe, it, expect } from 'vitest';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';

describe('Sieve Masking & Redaction Contracts', () => {
  it('masks short strings securely', () => {
    const masked = maskSecret('abc');
    expect(masked).toBe('***');
  });

  it('masks sensitive vendor tokens preserving only head and tail with hash', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const masked = maskSecret(secret);
    expect(masked).toContain('AKIA...');
    expect(masked).toContain('LE');
    expect(masked).toContain('(len 20)');
    expect(masked).not.toContain('OSFODNN7EXAMP');
  });

  it('masks URLs with sensitive credentials and tokens in query', () => {
    const url = 'https://admin:superSecretPassword@example.com/api/v1?token=CANARY_JWT_12345&auth_token=AUTH999';
    const maskedLoc = maskLocation(url);
    expect(maskedLoc).not.toContain('superSecretPassword');
    expect(maskedLoc).not.toContain('CANARY_JWT_12345');
    expect(maskedLoc).not.toContain('AUTH999');
    expect(maskedLoc).toContain('example.com/api/v1');
  });

  it('never leaks secret canary substring in masked preview', () => {
    const canary = 'CANARY_LEAD_SECRET_987654321';
    const masked = maskSecret(canary);
    expect(masked).not.toContain('LEAD_SECRET');
  });
});
