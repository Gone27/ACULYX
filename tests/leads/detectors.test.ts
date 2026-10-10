import { describe, it, expect } from 'vitest';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';
import { detectEndpoints } from '../../src/leads/detectors/f2-endpoints';
import { detectSourceMaps } from '../../src/leads/detectors/f3-sourcemaps';
import { detectAuthLeads } from '../../src/leads/detectors/f4-auth';
import { detectParamLeads, classifyParamName, detectReflectedInput } from '../../src/leads/detectors/f5-params';
import { detectHeaderLeads } from '../../src/leads/detectors/f6-headers';
import { detectBodyLeads } from '../../src/leads/detectors/f7-body';
import { detectReconLeads } from '../../src/leads/detectors/f8-recon';

describe('Detector F1: Secrets', () => {
  it('detects AWS access key with high confidence', () => {
    const code = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const leads = detectSecrets(code, 'https://example.com/main.js', 'in-scope');
    const awsLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('aws'));
    expect(awsLead).toBeDefined();
    expect(awsLead?.potential).toBe('critical');
    expect(awsLead?.tier).toBe('observed');
    expect(awsLead?.evidence.preview).toContain('AKIA...');
  });

  it('classifies Stripe publishable key as public info, never critical secret', () => {
    const code = 'const stripe = Stripe("pk_live_51Abcdefghijklmnopqrstuvwx1234567890");';
    const leads = detectSecrets(code, 'https://example.com/checkout.js', 'in-scope');
    const pkLead = leads.find(l => l.evidence.preview.includes('pk_live'));
    if (pkLead) {
      expect(pkLead.potential).toBe('info');
    }
  });

  it('detects MongoDB URI with embedded credentials (SEC-002)', () => {
    const code = 'const db = "mongodb+srv://dbuser:SecretPass123!@cluster.mongodb.net/app";';
    const leads = detectSecrets(code, 'https://example.com/db.js', 'in-scope');
    const dbLead = leads.find(l => l.ruleId === 'SEC-002');
    expect(dbLead).toBeDefined();
    expect(dbLead?.tags).toContain('database');
  });

  it('filters out common placeholders', () => {
    const code = 'const fake = "AKIA_YOUR_KEY_HERE_123"; const dummy = "xxxx-xxxx-xxxx";';
    const leads = detectSecrets(code, 'https://example.com/test.js', 'in-scope');
    expect(leads.filter(l => l.potential !== 'info')).toHaveLength(0);
  });
});

describe('Detector F2: Endpoints & Hidden Surface', () => {
  it('extracts API paths from fetch calls (END-001)', () => {
    const code = 'fetch("/api/v2/admin/users", { method: "GET" });';
    const leads = detectEndpoints(code, 'https://example.com/app.js', 'in-scope');
    const endLead = leads.find(l => l.ruleId === 'END-001' || l.ruleId === 'END-004');
    expect(endLead).toBeDefined();
    expect(endLead?.tags).toContain('admin');
  });

  it('detects GraphQL operations and endpoint (END-003)', () => {
    const code = 'const query = `query GetAdminProfile { admin { id email } }`; fetch("/graphql", { body: query });';
    const leads = detectEndpoints(code, 'https://example.com/app.js', 'in-scope');
    const gqlLead = leads.find(l => l.ruleId === 'END-003');
    expect(gqlLead).toBeDefined();
  });
});

describe('Detector F3: Source Maps', () => {
  it('detects sourceMappingURL reference (MAP-001)', () => {
    const code = 'console.log("ready");\n//# sourceMappingURL=bundle.js.map';
    const leads = detectSourceMaps(code, {}, 'https://example.com/bundle.js', 'in-scope');
    const mapLead = leads.find(l => l.ruleId === 'MAP-001');
    expect(mapLead).toBeDefined();
  });
});

describe('Detector F4: Auth, OAuth, Forms', () => {
  it('detects OAuth implicit response_type=token (AUTH-001)', () => {
    const url = 'https://example.com/oauth/authorize?client_id=123&response_type=token&redirect_uri=https://other.com';
    const leads = detectAuthLeads({ url, forms: [], storageKeys: [] }, 'in-scope');
    const oauthLead = leads.find(l => l.ruleId === 'AUTH-001');
    expect(oauthLead).toBeDefined();
    expect(oauthLead?.potential).toBe('high');
  });

  it('detects state-changing POST forms without CSRF tokens (AUTH-002)', () => {
    const form = {
      action: '/account/update-email',
      method: 'POST',
      inputs: [{ name: 'email', type: 'email' }],
    };
    const leads = detectAuthLeads({ url: 'https://example.com/profile', forms: [form], storageKeys: [] }, 'in-scope');
    const csrfLead = leads.find(l => l.ruleId === 'AUTH-002');
    expect(csrfLead).toBeDefined();
  });
});

describe('Detector F5: Parameter Intelligence', () => {
  it('classifies parameter names by vulnerability class (PAR-002)', () => {
    expect(classifyParamName('redirect_uri')).toBe('redirect');
    expect(classifyParamName('next')).toBe('redirect');
    expect(classifyParamName('webhook')).toBe('ssrf');
    expect(classifyParamName('file')).toBe('file');
    expect(classifyParamName('account_id')).toBe('idor');
    expect(classifyParamName('debug')).toBe('debug');
  });

  it('detects passive reflected inputs across contexts (PAR-003)', () => {
    const html = '<div>Hello test_reflection_token_123</div>';
    const params = { q: 'test_reflection_token_123' };
    const leads = detectReflectedInput(html, params, 'https://example.com?q=test_reflection_token_123', 'in-scope');
    expect(leads.length).toBeGreaterThanOrEqual(1);
    expect(leads[0].ruleId).toBe('PAR-003');
    expect(leads[0].tags).toContain('html-context');
  });
});

describe('Detector F6: Headers & CORS', () => {
  it('detects Origin reflection with ACAC true (COR-001)', () => {
    const headers = {
      'access-control-allow-origin': 'https://attacker.com',
      'access-control-allow-credentials': 'true',
    };
    const leads = detectHeaderLeads(headers, 'https://example.com', 'https://attacker.com', 'in-scope');
    const corsLead = leads.find(l => l.ruleId === 'COR-001');
    expect(corsLead).toBeDefined();
    expect(corsLead?.potential).toBe('high');
  });

  it('detects internal RFC1918 address in headers (INF-001)', () => {
    const headers = {
      'x-backend-server': '10.0.14.22',
      'x-upstream': '192.168.1.50',
    };
    const leads = detectHeaderLeads(headers, 'https://example.com', null, 'in-scope');
    const infLead = leads.find(l => l.ruleId === 'INF-001');
    expect(infLead).toBeDefined();
  });
});

describe('Detector F7: Body-Aware', () => {
  it('detects Werkzeug and Python stack traces (ERR-001)', () => {
    const body = 'Traceback (most recent call last):\n  File "/var/app/run.py", line 12\nZeroDivisionError';
    const leads = detectBodyLeads(body, 'text/html', 'https://example.com/err', 'in-scope');
    const errLead = leads.find(l => l.ruleId === 'ERR-001');
    expect(errLead).toBeDefined();
    expect(errLead?.potential).toBe('high');
  });

  it('detects excess data exposure in JSON APIs (API-001)', () => {
    const jsonBody = JSON.stringify({
      id: 1,
      name: 'Alice',
      password_hash: '$2a$12$abcdef...',
      is_admin: true,
      ssn: '000-00-0000',
    });
    const leads = detectBodyLeads(jsonBody, 'application/json', 'https://example.com/api/user', 'in-scope');
    const apiLead = leads.find(l => l.ruleId === 'API-001');
    expect(apiLead).toBeDefined();
    expect(apiLead?.evidence.extractedNames).toContain('password_hash');
  });
});

describe('Detector F8: Third-Party & Recon Feed', () => {
  it('extracts AWS and GCP cloud buckets (CLD-001)', () => {
    const content = '<img src="https://my-bucket.s3.amazonaws.com/logo.png" /> <a href="https://storage.googleapis.com/backup-data/file.zip">';
    const leads = detectReconLeads(content, 'https://example.com', 'in-scope');
    const cldLead = leads.find(l => l.ruleId === 'CLD-001');
    expect(cldLead).toBeDefined();
  });
});
