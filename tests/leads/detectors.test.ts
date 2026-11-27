import { describe, it, expect } from 'vitest';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';
import { detectEndpoints } from '../../src/leads/detectors/f2-endpoints';
import { detectSourceMaps } from '../../src/leads/detectors/f3-sourcemaps';
import { detectAuthLeads } from '../../src/leads/detectors/f4-auth';
import { classifyParamName, detectReflectedInput } from '../../src/leads/detectors/f5-params';
import { detectHeaderLeads } from '../../src/leads/detectors/f6-headers';
import { detectBodyLeads } from '../../src/leads/detectors/f7-body';
import { detectReconLeads } from '../../src/leads/detectors/f8-recon';
import { handleMainWorldEvent } from '../../src/background/leads-handler';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';

describe('Detector F1: Secrets', () => {
  it('detects AWS access key with calibrated confidence for unpaired key ID', () => {
    const awsKey = ['AKIA', '2345', '6789', 'BCDF', 'GHJK'].join('');
    const code = `const key = "${awsKey}";`;
    const leads = detectSecrets(code, 'https://example.com/main.js', 'in-scope');
    const awsLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('aws'));
    expect(awsLead).toBeDefined();
    expect(awsLead?.potential).toBe('low');
    expect(awsLead?.confidence).toBe(0.65);
    expect(awsLead?.title).toContain('Unpaired');
    expect(awsLead?.tier).toBe('observed');
    expect(awsLead?.evidence.preview).toContain('AKIA...');
  });

  it('detects paired AWS access key and secret with critical potential', () => {
    const awsKey = ['AKIA', '2345', '6789', 'BCDF', 'GHJK'].join('');
    const code = `const key = "${awsKey}"; const aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";`;
    const leads = detectSecrets(code, 'https://example.com/main.js', 'in-scope');
    const awsLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('aws'));
    expect(awsLead).toBeDefined();
    expect(awsLead?.potential).toBe('critical');
    expect(awsLead?.confidence).toBe(0.95);
  });

  it('does not suppress high-entropy API key containing environment marker word like staging', () => {
    const code = 'const api_key = "sec_staging_4f9b8c2d1e0a7f3e8b4c1a9d0e2f4a6b";';
    const leads = detectSecrets(code, 'https://example.com/config.js', 'in-scope');
    expect(leads.length).toBeGreaterThan(0);
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

  it('detects Slack xoxb- bot token with numeric ID segments', () => {
    const slackToken = ['xoxb', '1234567890', '1234567890', 'abcdef123456'].join('-');
    const code = `const token = "${slackToken}";`;
    const leads = detectSecrets(code, 'https://example.com/slack.js', 'in-scope');
    const slackLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('slack'));
    expect(slackLead).toBeDefined();
    expect(slackLead?.potential).toBe('high');
    expect(slackLead?.evidence.preview).toContain('xoxb...');
  });

  it('detects unsigned JWT with alg=none and empty signature', () => {
    const jwt = ['eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0', ''].join('.');
    const code = `const authJwt = "${jwt}";`;
    const leads = detectSecrets(code, 'https://example.com/auth.js', 'in-scope');
    const jwtLead = leads.find(l => l.ruleId === 'SEC-004');
    expect(jwtLead).toBeDefined();
    expect(jwtLead?.potential).toBe('high');
    expect(jwtLead?.title).toContain('alg=none');
    expect(jwtLead?.tags).toContain('alg-none');
  });

  it('sanitizes query parameters in lead url and location to prevent secret leakage', () => {
    const awsKey = ['AKIA', '2345', '6789', 'BCDF', 'GHJK'].join('');
    const code = `const apiKey = "${awsKey}";`;
    const rawUrl = 'https://example.com/api?token=SUPERSECRETTOKEN123456789&secret=PRIVATEKEY';
    const leads = detectSecrets(code, rawUrl, 'in-scope');
    const lead = leads[0];
    expect(lead).toBeDefined();
    expect(lead?.url).not.toContain('SUPERSECRETTOKEN');
    expect(lead?.url).toContain('token=***');
    expect(lead?.evidence.location).not.toContain('SUPERSECRETTOKEN');
  });

  it('calibrates Google API key (AIza...) to strong medium potential at 0.75 confidence', () => {
    const gcpKey = ['AIza', 'SyD-7abcdef1234567890abcdef12345678'].join('');
    const code = `window.__CONFIG = { mapsApiKey: "${gcpKey}" };`;
    const leads = detectSecrets(code, 'https://example.com/app.js', 'in-scope');
    const gcpLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('gcp'));
    expect(gcpLead).toBeDefined();
    expect(gcpLead?.tier).toBe('strong');
    expect(gcpLead?.potential).toBe('medium');
    expect(gcpLead?.confidence).toBe(0.75);
    expect(gcpLead?.title).toBe('Google API Key Format Matched (Restrictions Unverified)');
  });

  it('filters out common placeholders', () => {
    const code = 'const fake = "AKIA_YOUR_KEY_HERE_123"; const dummy = "xxxx-xxxx-xxxx";';
    const leads = detectSecrets(code, 'https://example.com/test.js', 'in-scope');
    expect(leads.filter(l => l.potential !== 'info')).toHaveLength(0);
  });

  it('detects quoted JSON keys with template literals and special characters (quoted JSON gap fix)', () => {
    const code = '{"password": "StagingSecretPassword2024!#.", "apiKey": "AIzaSyD-7abcdef1234567890abcdef12345678"}';
    const leads = detectSecrets(code, 'https://example.com/config.json', 'in-scope');
    const pwdLead = leads.find(l => l.ruleId === 'SEC-003');
    expect(pwdLead).toBeDefined();
    expect(pwdLead?.title).toContain('password');
    const gcpLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('gcp'));
    expect(gcpLead).toBeDefined();
  });

  it('detects OpenAI and Anthropic secret keys', () => {
    const code = `
      const openai = "sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef";
      const claude = "sk-ant-api03-1234567890abcdef1234567890abcdef123456";
    `;
    const leads = detectSecrets(code, 'https://example.com/ai.js', 'in-scope');
    const oaiLead = leads.find(l => l.tags.includes('openai'));
    expect(oaiLead).toBeDefined();
    expect(oaiLead?.potential).toBe('critical');

    const antLead = leads.find(l => l.tags.includes('anthropic'));
    expect(antLead).toBeDefined();
    expect(antLead?.potential).toBe('critical');
  });

  it('detects Telegram bot token and Discord incoming webhook', () => {
    const code = `
      const bot = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789";
      const hook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";
    `;
    const leads = detectSecrets(code, 'https://example.com/notify.js', 'in-scope');
    const tgLead = leads.find(l => l.tags.includes('telegram'));
    expect(tgLead).toBeDefined();
    const dcLead = leads.find(l => l.tags.includes('discord'));
    expect(dcLead).toBeDefined();
  });

  it('detects embedded basic authentication in URLs and Redis connection strings', () => {
    const code = `
      const url = "https://admin:SuperSecretPass123!@api.example.com/v1";
      const redis = "redis://user:MyRedisSecretPassword@cache.internal.net:6379";
    `;
    const leads = detectSecrets(code, 'https://example.com/app.js', 'in-scope');
    const basicLead = leads.find(l => l.tags.includes('basic-auth'));
    expect(basicLead).toBeDefined();
    const redisLead = leads.find(l => l.tags.includes('database'));
    expect(redisLead).toBeDefined();
  });

  it('detects GOCSPX secrets even when ending in dash or underscore without trailing word boundary failure', () => {
    const code = 'const clientSecret = "GOCSPX-1234567890abcdef1234567890ab-";';
    const leads = detectSecrets(code, 'https://example.com/oauth.js', 'in-scope');
    const gocspxLead = leads.find(l => l.ruleId === 'SEC-001' && l.tags.includes('google'));
    expect(gocspxLead).toBeDefined();
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

  it('rejects invalid inline source map data URLs without emitting MAP-001 or MAP-002', () => {
    const invalidCode = 'console.log("fail");\n//# sourceMappingURL=data:application/json;base64,not-valid';
    const leads = detectSourceMaps(invalidCode, {}, 'https://example.com/app.js', 'in-scope');
    expect(leads.filter(l => l.ruleId === 'MAP-001' || l.ruleId === 'MAP-002')).toHaveLength(0);
  });

  it('detects valid inline source map with internal build paths (MAP-002)', () => {
    const validMap = {
      version: 3,
      sources: ['/Users/dev/project/src/index.ts', 'webpack:///internal/auth.ts'],
    };
    const b64 = Buffer.from(JSON.stringify(validMap)).toString('base64');
    const code = `console.log("ok");\n//# sourceMappingURL=data:application/json;base64,${b64}`;
    const leads = detectSourceMaps(code, {}, 'https://example.com/app.js', 'in-scope');
    const mapLead = leads.find(l => l.ruleId === 'MAP-002');
    expect(mapLead).toBeDefined();
    expect(mapLead?.title).toBe('Inline Source Map with Internal Build Paths');
    expect(mapLead?.potential).toBe('medium');
    expect(mapLead?.evidence.preview).toContain('/Users/dev/project/src/index.ts');
  });

  it('detects valid inline source map without internal build paths as generic inline map', () => {
    const publicMap = {
      version: 3,
      sources: ['index.js', 'vendor.js'],
    };
    const b64 = Buffer.from(JSON.stringify(publicMap)).toString('base64');
    const code = `console.log("ok");\n//# sourceMappingURL=data:application/json;base64,${b64}`;
    const leads = detectSourceMaps(code, {}, 'https://example.com/app.js', 'in-scope');
    const mapLead = leads.find(l => l.ruleId === 'MAP-002');
    expect(mapLead).toBeDefined();
    expect(mapLead?.title).toBe('Inline JavaScript Source Map Detected');
    expect(mapLead?.potential).toBe('low');
  });

  it('masks credentials and fragments in source map reference URLs (MAP-001)', () => {
    const code = 'console.log("ready");\n//# sourceMappingURL=https://admin:supersecret@cdn.example.com/assets/app.js.map#access_token=xyz123';
    const leads = detectSourceMaps(code, {}, 'https://example.com/bundle.js', 'in-scope');
    const mapLead = leads.find(l => l.ruleId === 'MAP-001');
    expect(mapLead).toBeDefined();
    expect(mapLead?.title).not.toContain('supersecret');
    expect(mapLead?.title).not.toContain('access_token=xyz123');
    expect(mapLead?.evidence.preview).not.toContain('supersecret');
    expect(mapLead?.evidence.preview).not.toContain('access_token=xyz123');
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

  it('detects cleartext password input with case-insensitive PASSWORD type and unnamed input field (AUTH-003)', () => {
    const form = {
      action: 'http://insecure.example.com/login',
      method: 'POST',
      inputs: [{ type: 'PASSWORD' }],
    };
    const leads = detectAuthLeads({ url: 'https://example.com/login', forms: [form], storageKeys: [] }, 'in-scope');
    const cleartextLead = leads.find(l => l.ruleId === 'AUTH-003' && l.tags.includes('cleartext-credentials'));
    expect(cleartextLead).toBeDefined();
    expect(cleartextLead?.potential).toBe('high');
  });

  it('does not flag non-password input named password on cleartext page as cleartext password', () => {
    const form = {
      action: 'http://insecure.example.com/search',
      method: 'GET',
      inputs: [{ name: 'password', type: 'text' }],
    };
    const leads = detectAuthLeads({ url: 'http://insecure.example.com/search', forms: [form], storageKeys: [] }, 'in-scope');
    const cleartextLead = leads.find(l => l.ruleId === 'AUTH-003' && l.tags.includes('cleartext-credentials'));
    expect(cleartextLead).toBeUndefined();
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
    expect(leads[0]?.ruleId).toBe('PAR-003');
    expect(leads[0]?.tags).toContain('html-context');
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

  it('does not fire ERR-001 on documentation containing only the phrase Traceback (most recent call last): without stack frames', () => {
    const docBody = '<html><body><h1>Python Guide</h1><p>In Python, unhandled exceptions print <code>Traceback (most recent call last):</code> followed by the frame stack.</p></body></html>';
    const leads = detectBodyLeads(docBody, 'text/html', 'https://example.com/docs/python', 'in-scope');
    expect(leads.filter(l => l.ruleId === 'ERR-001')).toHaveLength(0);
  });

  it('does not fire ERR-001 on documentation mentioning Illuminate\\ namespace without error context', () => {
    const docBody = '<p>Import the namespace Illuminate\\Support\\Facades\\DB in your service provider.</p>';
    const leads = detectBodyLeads(docBody, 'text/html', 'https://example.com/docs/laravel', 'in-scope');
    expect(leads.filter(l => l.ruleId === 'ERR-001')).toHaveLength(0);
  });

  it('bounds response body processing to 512 KB', () => {
    const hugeBody = 'A'.repeat(2 * 1024 * 1024);
    const leads = detectBodyLeads(hugeBody, 'text/plain', 'https://example.com/huge', 'in-scope');
    expect(leads).toHaveLength(0);
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

  it('correctly attributes Cloudflare R2 buckets without defaulting to DigitalOcean', () => {
    const content = '<a href="https://assets-bucket.r2.cloudflarestorage.com/download.tar.gz">R2 Bucket</a>';
    const leads = detectReconLeads(content, 'https://example.com', 'in-scope');
    const cldLead = leads.find(l => l.ruleId === 'CLD-001');
    expect(cldLead).toBeDefined();
    expect(cldLead?.tags).toContain('cloudflare-r2');
    expect(cldLead?.tags).not.toContain('digitalocean');
    expect(cldLead?.title).toContain('CLOUDFLARE-R2');
  });

  it('isolates bucket origin and determines bucket scope independently from page scope', () => {
    const pageUrl = 'https://target.com/index.html';
    const content = '<a href="https://privatebucket.s3.amazonaws.com/data.json">Data</a>';
    const mockScopeResolver = (targetUrl: string) => {
      if (targetUrl.includes('target.com')) return 'in-scope';
      return 'out-of-scope';
    };

    const leads = detectReconLeads(content, pageUrl, 'in-scope', mockScopeResolver);
    const bucketLead = leads.find((l) => l.ruleId === 'CLD-001');

    expect(bucketLead).toBeDefined();
    expect(bucketLead?.origin).toBe('https://privatebucket.s3.amazonaws.com');
    expect(bucketLead?.url).toBe('https://privatebucket.s3.amazonaws.com');
    expect(bucketLead?.scopeStatus).toBe('out-of-scope');
    expect(bucketLead?.origin).not.toBe('https://target.com');
  });
});

describe('Sensor S3: Main-World Events (Untrusted Tagging & Bounds)', () => {
  it('marks all S3 sink events with [Page-Reported] prefix, page-reported tag, and capped tier', () => {
    const canary = 'CANARY_SECRET_TAINT_VALUE_9999';
    const res = handleMainWorldEvent({
      type: 'MAIN_WORLD_LEADS_EVENT',
      url: `https://example.com/test#access_token=${canary}`,
      origin: 'https://example.com',
      event: {
        eventType: 'sink',
        sinkName: 'Element.innerHTML',
        sourceCategory: 'location.hash',
        details: 'Sink Element.innerHTML received string containing data from location.hash',
      },
    }, DEFAULT_SETTINGS);

    const s3Lead = res.leads.find(l => l.sourceSensor === 'S3' && l.ruleId === 'PAR-004');
    expect(s3Lead).toBeDefined();
    expect(s3Lead?.title).toContain('[Page-Reported]');
    expect(s3Lead?.tags).toContain('page-reported');
    expect(['weak', 'whisper']).toContain(s3Lead?.tier);
    expect(s3Lead?.url).toBe('https://example.com/test');
    expect(s3Lead?.url).not.toContain('access_token');
    expect(s3Lead?.url).not.toContain(canary);
    expect(s3Lead?.evidence.preview).toContain('Controlled input from location.hash detected');
    expect(s3Lead?.evidence.preview).not.toContain(canary);
  });

  it('marks S3 postmessage calls with [Page-Reported] and clamps tier to weak', () => {
    const res = handleMainWorldEvent({
      type: 'MAIN_WORLD_LEADS_EVENT',
      url: 'https://example.com/dashboard',
      origin: 'https://example.com',
      event: {
        eventType: 'postmessage_call',
        targetOrigin: '*',
        details: 'postMessage dispatched with target origin *',
      },
    }, DEFAULT_SETTINGS);

    const postLead = res.leads.find(l => l.sourceSensor === 'S3' && l.ruleId === 'IFR-001');
    expect(postLead).toBeDefined();
    expect(postLead?.title).toContain('[Page-Reported]');
    expect(postLead?.tags).toContain('page-reported');
    expect(postLead?.tier).toBe('weak');
  });

  it('detects prefixed generic secrets like access_token and refresh_token while ignoring URLs and paths', () => {
    const code = `
      const config = {
        "access_token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4",
        "refresh_token": "x9y8z7w6v5u4t3s2r1q0p9o8n7m6",
        "token_endpoint": "https://auth.example.com/oauth/v2/token",
        "auth_url": "/api/v1/auth/callback",
        "password_hint": "this is a plain english sentence with spaces"
      };
    `;
    const leads = detectSecrets(code, 'https://example.com/bundle.js', 'in-scope');
    const secretLeads = leads.filter(l => l.ruleId === 'SEC-003');
    expect(secretLeads.some(l => l.title.includes('access_token'))).toBe(true);
    expect(secretLeads.some(l => l.title.includes('refresh_token'))).toBe(true);
    // Should NOT flag URLs, paths, or sentences
    expect(secretLeads.some(l => l.title.includes('token_endpoint'))).toBe(false);
    expect(secretLeads.some(l => l.title.includes('auth_url'))).toBe(false);
    expect(secretLeads.some(l => l.title.includes('password_hint'))).toBe(false);
  });

  it('does NOT flag same-origin ACAO echo as CORS exploit, but flags cross-origin reflection', () => {
    // Same-origin echo: page is https://example.com, requestOrigin is https://example.com
    const sameOriginHeaders = {
      'access-control-allow-origin': 'https://example.com',
      'access-control-allow-credentials': 'true',
    };
    const sameLeads = detectHeaderLeads(sameOriginHeaders, 'https://example.com/api', 'https://example.com', 'in-scope');
    expect(sameLeads.filter(l => l.ruleId === 'COR-001')).toHaveLength(0);

    // Cross-origin reflection: page is https://api.example.com, requestOrigin is https://attacker.com
    const crossOriginHeaders = {
      'access-control-allow-origin': 'https://attacker.com',
      'access-control-allow-credentials': 'true',
    };
    const crossLeads = detectHeaderLeads(crossOriginHeaders, 'https://api.example.com/data', 'https://attacker.com', 'in-scope');
    const corLead = crossLeads.find(l => l.ruleId === 'COR-001');
    expect(corLead).toBeDefined();
    expect(corLead?.potential).toBe('high');
  });

  it('detects insecure password submission when form action submits to cleartext HTTP', () => {
    const context = {
      url: 'https://example.com/login',
      forms: [
        {
          action: 'http://auth.example.com/api/login',
          method: 'POST',
          inputs: [{ name: 'password', type: 'password' }],
        },
      ],
    };
    const leads = detectAuthLeads(context, 'in-scope');
    const cleartextLead = leads.find(l => l.ruleId === 'AUTH-003' && l.tags.includes('cleartext-credentials'));
    expect(cleartextLead).toBeDefined();
    expect(cleartextLead?.title).toContain('Cleartext HTTP');
  });

  it('detects wildcard postMessage only when targetOrigin argument is wildcard', () => {
    // False positive test: postMessage used with same-origin, but '*' appears elsewhere in file
    const safeCode = `
      window.postMessage({ type: 'ready' }, window.location.origin);
      const star = '*';
      const multiply = 5 * 10;
    `;
    const safeLeads = detectReconLeads(safeCode, 'https://example.com/app.js', 'in-scope');
    expect(safeLeads.filter(l => l.tags.includes('wildcard-origin'))).toHaveLength(0);

    // True positive test: postMessage with '*' as target origin
    const vulnerableCode = `
      window.postMessage({ token: userToken }, '*');
    `;
    const vulnLeads = detectReconLeads(vulnerableCode, 'https://example.com/app.js', 'in-scope');
    expect(vulnLeads.some(l => l.tags.includes('wildcard-origin'))).toBe(true);
  });
});
