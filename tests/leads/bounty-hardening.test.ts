import { describe, it, expect } from 'vitest';
import { detectSecrets, isPlaceholder } from '../../src/leads/detectors/f1-secrets';
import { detectEndpoints } from '../../src/leads/detectors/f2-endpoints';
import { detectParamLeads } from '../../src/leads/detectors/f5-params';
import { detectHeaderLeads } from '../../src/leads/detectors/f6-headers';
import { detectBodyLeads } from '../../src/leads/detectors/f7-body';
import { detectReconLeads } from '../../src/leads/detectors/f8-recon';
import { checkCookies } from '../../src/rules/cookies/cookies';
import { calculateLeadPriority } from '../../src/leads/ranking/ranking';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import type { CookieRecord } from '../../src/shared/types';
import type { Lead } from '../../src/leads/types';

describe('Bounty Hardening: F1 Secrets', () => {
  it('rejects low-entropy Discord bot tokens and accepts high-entropy tokens', () => {
    // Low entropy HMAC segment: repeated chars
    const fakeToken = 'MTIzNDU2Nzg5MDEyMzQ1Njc4.abcdef.aaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const fakeLeads = detectSecrets(`const token = "${fakeToken}";`, 'https://example.com/app.js');
    expect(fakeLeads.filter(l => l.id.includes('SEC-DISCORD'))).toHaveLength(0);

    // High entropy HMAC segment
    const realLookingToken = 'MTEyMjMzNDQ1NTY2Nzc4ODk5.GxyzAb.k9_J2mPqR4tV8wX1zY3bC5dE7fG0hI2jL4nO6';
    const realLeads = detectSecrets(`const token = "${realLookingToken}";`, 'https://example.com/app.js');
    expect(realLeads.filter(l => l.title.includes('Discord Bot Token'))).toHaveLength(1);
  });

  it('enforces length >= 32 and high entropy on hard-coded Bearer tokens', () => {
    // Too short (24 chars)
    const shortBearer = 'Authorization = "Bearer short_token_1234567890"';
    expect(detectSecrets(shortBearer, 'https://example.com/app.js').filter(l => l.id.includes('SEC-BEARER'))).toHaveLength(0);

    // 32+ chars with sufficient entropy
    const realBearer = 'Authorization = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.s6z9_real_token"';
    expect(detectSecrets(realBearer, 'https://example.com/app.js').filter(l => l.title.includes('Bearer'))).toHaveLength(1);
  });

  it('marks values containing test/demo/staging/mock as placeholders', () => {
    expect(isPlaceholder('staging_api_key')).toBe(true);
    expect(isPlaceholder('demo-secret-key')).toBe(true);
    expect(isPlaceholder('mock_auth_token')).toBe(true);
    expect(isPlaceholder('test-credential')).toBe(true);
  });

  it('processes massive adversarial inputs with repeated underscores/hyphens in linear time without ReDoS', () => {
    // 100 KB and 1 MB adversarial test inputs
    const attackPayload100k = 'const ' + 'a_'.repeat(50_000) + 'secret = "some_secret_value_12345678";';
    const start100k = performance.now();
    detectSecrets(attackPayload100k, 'https://example.com/bundle.js');
    const elapsed100k = performance.now() - start100k;
    expect(elapsed100k).toBeLessThan(300);

    const attackPayload1mb = 'const ' + 'a-'.repeat(500_000) + 'token = "some_secret_token_12345678";';
    const start1mb = performance.now();
    detectSecrets(attackPayload1mb, 'https://example.com/bundle.js');
    const elapsed1mb = performance.now() - start1mb;
    expect(elapsed1mb).toBeLessThan(1500);
  });

  it('detects slash-leading high-entropy credentials while ignoring standard paths under path-like keys', () => {
    // 1. High-entropy credential starting with / under secret key: MUST be detected
    const slashSecret = 'const api_secret = "/7bX9qK2mP8vL4wZ1yC5dE0fG=";';
    const detected = detectSecrets(slashSecret, 'https://example.com/app.js');
    expect(detected.some(l => l.ruleId === 'SEC-003')).toBe(true);

    // 2. Normal path under path/endpoint key or standard multi-segment route: MUST NOT be detected
    const normalPath = 'const login_endpoint_path = "/auth/v1/oauth/token";';
    const notDetected = detectSecrets(normalPath, 'https://example.com/app.js');
    expect(notDetected.filter(l => l.ruleId === 'SEC-003')).toHaveLength(0);

    const assetPath = 'const token_icon_url = "/assets/icons/token-logo.png";';
    const notDetectedAsset = detectSecrets(assetPath, 'https://example.com/app.js');
    expect(notDetectedAsset.filter(l => l.ruleId === 'SEC-003')).toHaveLength(0);
  });
});

describe('Bounty Hardening: F2 Template Literal Endpoints', () => {
  it('discovers parameterized API paths from template literals and normalizes them', () => {
    const code = `
      fetch(\`/api/v1/users/\${userId}/profile\`);
      axios.get(\`/admin/settings/\${orgId}/billing\`);
    `;
    const leads = detectEndpoints(code, 'https://example.com/bundle.js');
    const titles = leads.map(l => l.title);
    expect(titles.some(t => t.includes('/api/v1/users/{param}/profile'))).toBe(true);
    expect(titles.some(t => t.includes('/admin/settings/{param}/billing'))).toBe(true);
  });
});

describe('Bounty Hardening: F5 Params Context & Fragment Routing', () => {
  it('parses sensitive parameters from URL hash fragments', () => {
    const url = 'https://example.com/oauth/callback#redirect_uri=https://evil.com&state=xyz';
    const leads = detectParamLeads(url);
    expect(leads.some(l => l.ruleId === 'PAR-002' && l.title.includes('redirect_uri'))).toBe(true);
  });

  it('adjusts IDOR parameter signal based on path context and action verbs', () => {
    // Public blog context -> retained as info whisper rather than silently dropped
    const publicUrl = 'https://example.com/blog/article?id=123';
    const publicLeads = detectParamLeads(publicUrl).filter(l => l.title.includes('IDOR'));
    expect(publicLeads).toHaveLength(1);
    expect(publicLeads[0]?.potential).toBe('info');
    expect(publicLeads[0]?.tags).toContain('public-context');

    // Action path on content route -> elevated to high potential with action-path tag
    const actionUrl = 'https://example.com/post/42/edit?id=42';
    const actionLeads = detectParamLeads(actionUrl).filter(l => l.title.includes('IDOR'));
    expect(actionLeads).toHaveLength(1);
    expect(actionLeads[0]?.potential).toBe('high');
    expect(actionLeads[0]?.tags).toContain('action-path');

    // Private account context -> high potential
    const accountUrl = 'https://example.com/account/settings?user_id=456';
    const accountLeads = detectParamLeads(accountUrl).filter(l => l.title.includes('IDOR'));
    expect(accountLeads).toHaveLength(1);
    expect(accountLeads[0]?.potential).toBe('high');
  });

  it('evaluates table-driven IDOR corpus distinguishing action verbs, public content, and benign routes', () => {
    const corpus = [
      {
        url: 'https://example.com/post/42/edit?id=42',
        shouldFire: true,
        actionPath: true,
        potential: 'high',
      },
      {
        url: 'https://example.com/doc/9?id=9',
        shouldFire: true,
        actionPath: false,
        potential: 'info',
      },
      {
        url: 'https://example.com/users/5?user_id=5',
        shouldFire: true,
        actionPath: false,
        potential: 'high',
      },
      {
        url: 'https://example.com/products?item=5',
        shouldFire: true,
        actionPath: false,
        potential: 'info',
      },
      {
        url: 'https://example.com/editors?id=42',
        shouldFire: true,
        actionPath: false,
        potential: 'medium',
      },
      {
        url: 'https://example.com/share-button?id=42',
        shouldFire: true,
        actionPath: false,
        potential: 'medium',
      },
      {
        url: 'https://example.com/static/docs/help.html?id=42',
        shouldFire: true,
        actionPath: false,
        potential: 'info',
      },
      {
        url: 'https://example.com/app/dashboard?theme=dark&sort=asc',
        shouldFire: false,
        actionPath: false,
        potential: null,
      },
    ];

    for (const testCase of corpus) {
      const leads = detectParamLeads(testCase.url).filter((l) => l.ruleId === 'PAR-002' && l.tags.includes('idor-param'));
      if (testCase.shouldFire) {
        expect(leads.length, `Expected IDOR lead for ${testCase.url}`).toBeGreaterThan(0);
        const lead = leads[0];
        expect(lead?.potential).toBe(testCase.potential);
        if (testCase.actionPath) {
          expect(lead?.tags).toContain('action-path');
        } else {
          expect(lead?.tags).not.toContain('action-path');
        }
        expect(lead?.doesNotProve).toContain('insecure direct object reference without access control validation');
      } else {
        expect(leads, `Expected NO IDOR lead for ${testCase.url}`).toHaveLength(0);
      }
    }
  });
});

describe('Bounty Hardening: F6 Infrastructure Disclosures', () => {
  it('ignores client IP headers like x-forwarded-for and flags real backend server disclosures', () => {
    const headers = {
      'x-forwarded-for': '192.168.1.50',
      'x-backend-server': '10.0.4.12',
    };
    const leads = detectHeaderLeads(headers, 'https://example.com/api');
    const inf001 = leads.filter(l => l.ruleId === 'INF-001');
    expect(inf001).toHaveLength(1);
    expect(inf001[0]?.title).toContain('x-backend-server');
    expect(inf001[0]?.confidence).toBe(0.7);
  });
});

describe('Bounty Hardening: F7 Body & GraphQL Introspection', () => {
  it('requires multiple stack frames to report Java stack trace', () => {
    const singleLine = 'Contact at support.team(Help.java:10)';
    expect(detectBodyLeads(singleLine, 'text/html', 'https://example.com')).toHaveLength(0);

    const realStackTrace = `
      Exception in thread "main" java.lang.NullPointerException
        at com.example.service.AuthService.login(AuthService.java:45)
        at com.example.controller.LoginController.handle(LoginController.java:88)
    `;
    const leads = detectBodyLeads(realStackTrace, 'text/html', 'https://example.com');
    expect(leads.some(l => l.ruleId === 'ERR-001')).toBe(true);
  });

  it('detects GraphQL introspection enabled in response bodies', () => {
    const gqlBody = JSON.stringify({
      data: {
        __schema: {
          queryType: { name: 'Query' },
          types: [{ name: 'User' }, { name: 'AdminMutation' }]
        }
      }
    });
    const leads = detectBodyLeads(gqlBody, 'application/json', 'https://example.com/graphql');
    expect(leads.some(l => l.ruleId === 'GQL-001')).toBe(true);
  });
});

describe('Bounty Hardening: F8 Recon Cloud Providers', () => {
  it('detects Cloudflare R2 and Alibaba OSS buckets', () => {
    const content = `
      const backup = "https://confidential-data.r2.cloudflarestorage.com/export.zip";
      const assets = "https://static-files.oss-cn-shanghai.aliyuncs.com/logo.png";
    `;
    const leads = detectReconLeads(content, 'https://example.com/app.js');
    expect(leads.some(l => l.title.includes('CLOUDFLARE-R2'))).toBe(true);
    expect(leads.some(l => l.title.includes('ALIBABA-OSS'))).toBe(true);
  });
});

describe('Bounty Hardening: Cookies SameSite and Triage Ranking', () => {
  it('flags sensitive session cookies missing SameSite with medium severity and fail outcome', () => {
    const cookies: CookieRecord[] = [{
      name: 'session_token',
      domain: 'example.com',
      domainAttributePresent: false,
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: '',
      session: true,
      expiresAt: null,
      partitioned: false,
      setByJs: false,
      isThirdParty: false,
    }];
    const findings = checkCookies(cookies, true);
    const cook004 = findings.find(f => f.ruleId === 'COOK-004');
    expect(cook004).toBeDefined();
    expect(cook004?.severity).toBe('medium');
    expect(cook004?.outcome).toBe('fail');
  });

  it('assigns zero priority to false_positive triaged leads', () => {
    const mockLead: Lead = {
      id: 'LD-TEST-1',
      ruleId: 'SEC-001',
      family: 'F1',
      tier: 'observed',
      potential: 'critical',
      confidence: 1.0,
      title: 'Dismissed Lead',
      needs: [],
      doesNotProve: [],
      evidence: { preview: maskSecret('test'), location: maskLocation('https://example.com') },
      tags: [],
      scopeStatus: 'in-scope',
      timestamp: Date.now(),
      origin: 'https://example.com',
      url: 'https://example.com',
      sourceSensor: 'S2',
      triageState: 'false_positive',
    };
    expect(calculateLeadPriority(mockLead)).toBe(0);
  });
});
