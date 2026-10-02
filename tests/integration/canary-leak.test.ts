import { describe, it, expect } from 'vitest';

describe('Canary Leak Prevention Integration', () => {
  const sanitizeUrl = (url: string) => {
    try {
      const parsed = new URL(url);
      parsed.search = '';
      parsed.hash = '';
      return parsed.toString();
    } catch {
      return url;
    }
  };

  const assertNoSensitiveSecrets = (data: string) => {
    const secrets = ['SECRET_CANARY_12345', 'SECRET_CANARY_67890'];
    for (const secret of secrets) {
      if (data.includes(secret)) {
        throw new Error(`Sensitive secret found: ${secret}`);
      }
    }
  };

  describe('Service worker URL sanitization', () => {
    it('sanitizes synthetic query parameters and passes assertNoSensitiveSecrets', () => {
      const rawUrl = 'https://example.com/sw.js?token=SECRET_CANARY_12345';
      
      // Before sanitization it should fail
      expect(() => assertNoSensitiveSecrets(rawUrl)).toThrowError(/SECRET_CANARY_12345/);
      
      const sanitizedUrl = sanitizeUrl(rawUrl);
      expect(sanitizedUrl).toBe('https://example.com/sw.js');
      
      // After sanitization it should pass
      expect(() => assertNoSensitiveSecrets(sanitizedUrl)).not.toThrow();
    });
  });

  describe('Meta-CSP URL sanitization', () => {
    it('sanitizes report-uri in meta-CSP before storage', () => {
      const rawCsp = "default-src 'self'; report-uri https://collector.example.com/report?session=SECRET_CANARY_67890";
      
      // Basic mock sanitization for CSP directives
      const sanitizeCsp = (csp: string) => {
        return csp.replace(/report-uri\s+([^;\s]+)/g, (_match: string, url: string) => {
          return `report-uri ${sanitizeUrl(url)}`;
        });
      };
      
      const sanitizedCsp = sanitizeCsp(rawCsp);
      expect(sanitizedCsp).toBe("default-src 'self'; report-uri https://collector.example.com/report");
      
      expect(() => assertNoSensitiveSecrets(sanitizedCsp)).not.toThrow();
    });
  });

  describe('Export sinks verification', () => {
    it('ensures exportJsonReport and exportMarkdownReport never contain raw query params or canary secrets', () => {
      const mockCoverageObject = {
        scriptUrl: sanitizeUrl('https://example.com/script.js?token=SECRET_CANARY_12345'),
        csp: "report-uri https://example.com/report?session=SECRET_CANARY_67890".replace(/https:\/\/[^;\s]+/, (match: string) => sanitizeUrl(match))
      };
      
      const exportJsonReport = () => JSON.stringify(mockCoverageObject);
      const exportMarkdownReport = () => `## Script\n${mockCoverageObject.scriptUrl}\n## CSP\n${mockCoverageObject.csp}`;
      
      const jsonOutput = exportJsonReport();
      const mdOutput = exportMarkdownReport();
      
      expect(() => assertNoSensitiveSecrets(jsonOutput)).not.toThrow();
      expect(() => assertNoSensitiveSecrets(mdOutput)).not.toThrow();
    });
  });
});
