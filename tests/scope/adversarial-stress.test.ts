import { describe, it, expect } from 'vitest';
import {
  ScopeEngine,
  normalizeHostname,
  extractExplicitPort,
  parseScheme,
  normalizeScopeTarget,
  isSubdomainOf,
  matchTarget,
  evaluateScope,
  evaluateRedirectHop,
  evaluateThirdParty,
} from '../../src/shared/scope';
import type { ScopeProfile, ScopeRule } from '../../src/shared/scope/contracts';

describe('Challenger 1 Empirical Stress Test — Scope Engine Adversarial Harness', () => {
  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Wildcard Boundary Empirical Tests (*.example.com NEVER matches apex example.com)
  // ─────────────────────────────────────────────────────────────────────────────

  describe('1. Wildcard Boundary: *.example.com NEVER matches apex example.com', () => {
    const wildcardRule = normalizeScopeTarget('*.example.com');

    it('verifies pure apex host never matches wildcard rule', () => {
      expect(isSubdomainOf('example.com', 'example.com')).toBe(false);
      expect(matchTarget(normalizeScopeTarget('example.com'), wildcardRule)).toBe(false);
    });

    it('verifies apex with various schemes never matches wildcard rule', () => {
      const schemes = ['http://example.com', 'https://example.com', 'https://example.com/', 'ftp://example.com'];
      for (const uri of schemes) {
        const target = normalizeScopeTarget(uri);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies apex with full URL path, query params, and fragments never matches wildcard rule', () => {
      const fullUrls = [
        'https://example.com/login',
        'https://example.com/api/v1/auth?token=secret#section',
        'https://example.com:443/index.html',
        'http://example.com:80/home?user=admin',
        'https://example.com:8080/debug',
      ];
      for (const uri of fullUrls) {
        const target = normalizeScopeTarget(uri);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies apex with uppercase and mixed-case casing never matches wildcard rule', () => {
      const casings = ['EXAMPLE.COM', 'Example.Com', 'ExAmPlE.cOm', 'https://EXAMPLE.COM/'];
      for (const c of casings) {
        const target = normalizeScopeTarget(c);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies apex with trailing dots never matches wildcard rule', () => {
      const trailingDots = ['example.com.', 'example.com...', 'https://example.com./'];
      for (const td of trailingDots) {
        const target = normalizeScopeTarget(td);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies apex with embedded userinfo credentials never matches wildcard rule', () => {
      const userinfoUrls = [
        'https://user:password@example.com/',
        'https://admin:secret123@example.com:443/auth',
      ];
      for (const u of userinfoUrls) {
        const target = normalizeScopeTarget(u);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies lookalike and suffix collision attack domains never match wildcard rule', () => {
      const collisionAttacks = [
        'badexample.com',
        'notexample.com',
        'fake-example.com',
        'attackerexample.com',
        'myexample.com:8080',
        'theexample.com',
        'https://badexample.com/',
        'https://notexample.com/api',
      ];
      for (const attack of collisionAttacks) {
        const target = normalizeScopeTarget(attack);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies reversed domain and subdomain-as-domain attacks never match wildcard rule', () => {
      const attacks = [
        'example.com.evil.com',
        'example.com.attacker.net',
        'https://example.com.evil.com/phish',
        'https://attacker.com/example.com',
        'https://attacker.com/?redirect=example.com',
      ];
      for (const attack of attacks) {
        const target = normalizeScopeTarget(attack);
        expect(matchTarget(target, wildcardRule)).toBe(false);
      }
    });

    it('verifies legitimate subdomains DO match wildcard rule', () => {
      const validSubdomains = [
        'api.example.com',
        'auth.example.com',
        'dev.stage.example.com',
        'deeply.nested.sub.domain.example.com',
        'https://payments.example.com/checkout',
      ];
      for (const sub of validSubdomains) {
        const target = normalizeScopeTarget(sub);
        expect(matchTarget(target, wildcardRule)).toBe(true);
      }
    });

    it('verifies multi-level wildcard rules (*.sub.example.com) strictly protect sub.example.com apex', () => {
      const nestedRule = normalizeScopeTarget('*.sub.example.com');
      // Apex of wildcard must NOT match
      expect(matchTarget(normalizeScopeTarget('sub.example.com'), nestedRule)).toBe(false);
      expect(matchTarget(normalizeScopeTarget('example.com'), nestedRule)).toBe(false);
      // Children of sub.example.com MUST match
      expect(matchTarget(normalizeScopeTarget('api.sub.example.com'), nestedRule)).toBe(true);
      expect(matchTarget(normalizeScopeTarget('dev.api.sub.example.com'), nestedRule)).toBe(true);
    });

    it('verifies ScopeEngine behavior when wildcard rule exists alone vs with explicit apex rule', () => {
      // 1. Profile with ONLY wildcard: apex MUST evaluate to 'unknown'
      const wildcardOnlyEngine = new ScopeEngine({
        id: 'wildcard-only',
        name: 'Wildcard Only',
        rules: [{ pattern: '*.example.com', type: 'include' }],
      });
      const res1 = wildcardOnlyEngine.evaluate('https://example.com/');
      expect(res1.status).toBe('unknown');
      expect(res1.matchedPattern).toBeUndefined();

      // Subdomains must still be in-scope
      const subRes = wildcardOnlyEngine.evaluate('https://api.example.com/');
      expect(subRes.status).toBe('in-scope');
      expect(subRes.matchedPattern).toBe('*.example.com');

      // 2. Profile with BOTH wildcard and explicit apex: apex matches exact rule, NOT wildcard rule
      const dualEngine = new ScopeEngine({
        id: 'dual',
        name: 'Dual Scope',
        rules: [
          { pattern: '*.example.com', type: 'include' },
          { pattern: 'example.com', type: 'include' },
        ],
      });
      const res2 = dualEngine.evaluate('https://example.com/');
      expect(res2.status).toBe('in-scope');
      expect(res2.matchedPattern).toBe('example.com'); // Must match the explicit rule, NOT wildcard
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. Exclusion Precedence Empirical Tests (Exclusion ALWAYS overrides inclusion)
  // ─────────────────────────────────────────────────────────────────────────────

  describe('2. Exclusion Precedence: Exclusion ALWAYS overrides any inclusion pattern', () => {
    it('verifies exact exclusion overrides wildcard inclusion', () => {
      const engine = new ScopeEngine({
        id: 'prec-1',
        name: 'Precedence 1',
        rules: [
          { pattern: 'admin.example.com', type: 'exclude' },
          { pattern: '*.example.com', type: 'include' },
        ],
      });

      const res = engine.evaluate('https://admin.example.com/panel');
      expect(res.status).toBe('out-of-scope');
      expect(res.ruleType).toBe('exclude');
      expect(res.matchedPattern).toBe('admin.example.com');

      // Unexcluded subdomain remains in-scope
      const normalRes = engine.evaluate('https://api.example.com/data');
      expect(normalRes.status).toBe('in-scope');
      expect(normalRes.ruleType).toBe('include');
    });

    it('verifies array order independence: inclusion before exclusion still yields exclusion precedence', () => {
      const engineReversed = new ScopeEngine({
        id: 'prec-reversed',
        name: 'Precedence Reversed',
        rules: [
          // Inclusion declared FIRST in the array
          { pattern: '*.example.com', type: 'include' },
          // Exclusion declared SECOND in the array
          { pattern: 'admin.example.com', type: 'exclude' },
        ],
      });

      const res = engineReversed.evaluate('https://admin.example.com/secret');
      expect(res.status).toBe('out-of-scope');
      expect(res.ruleType).toBe('exclude');
      expect(res.matchedPattern).toBe('admin.example.com');
    });

    it('verifies identical pattern collision: exclude wins regardless of declaration order', () => {
      // Case A: Include first, Exclude second
      const engineA = new ScopeEngine([
        { pattern: 'api.target.com', type: 'include' },
        { pattern: 'api.target.com', type: 'exclude' },
      ]);
      expect(engineA.evaluate('https://api.target.com/').status).toBe('out-of-scope');

      // Case B: Exclude first, Include second
      const engineB = new ScopeEngine([
        { pattern: 'api.target.com', type: 'exclude' },
        { pattern: 'api.target.com', type: 'include' },
      ]);
      expect(engineB.evaluate('https://api.target.com/').status).toBe('out-of-scope');
    });

    it('verifies wildcard exclusion overrides exact inclusion', () => {
      const engine = new ScopeEngine([
        { pattern: '*.bounty.io', type: 'exclude' },
        { pattern: 'api.bounty.io', type: 'include' },
        { pattern: 'auth.bounty.io', type: 'include' },
      ]);

      expect(engine.evaluate('https://api.bounty.io/').status).toBe('out-of-scope');
      expect(engine.evaluate('https://auth.bounty.io/').status).toBe('out-of-scope');
      // Apex is not covered by wildcard exclusion or exact inclusion for subdomains
      expect(engine.evaluate('https://bounty.io/').status).toBe('unknown');
    });

    it('verifies port-specific exclusion overrides broad wildcard inclusion', () => {
      const engine = new ScopeEngine([
        { pattern: '*.example.com', type: 'include' },
        { pattern: 'api.example.com:8443', type: 'exclude' },
      ]);

      // Target with excluded port -> out-of-scope
      const resExcluded = engine.evaluate('https://api.example.com:8443/debug');
      expect(resExcluded.status).toBe('out-of-scope');
      expect(resExcluded.matchedPattern).toBe('api.example.com:8443');

      // Target with different port -> in-scope via *.example.com
      const resAllowedPort = engine.evaluate('https://api.example.com:443/production');
      expect(resAllowedPort.status).toBe('in-scope');

      // Another subdomain on port 8443 -> in-scope via *.example.com (only api on 8443 is excluded)
      const resOtherSub = engine.evaluate('https://auth.example.com:8443/login');
      expect(resOtherSub.status).toBe('in-scope');
    });

    it('runs high-volume randomized stress harness: exclusion precedence holds across 200 mixed rules', () => {
      const rules: ScopeRule[] = [];
      const excludedHosts: string[] = [];
      const includedHosts: string[] = [];

      for (let i = 0; i < 100; i++) {
        const incHost = `node-${i}.cluster.corp`;
        const excHost = `blacklisted-${i}.cluster.corp`;
        includedHosts.push(incHost);
        excludedHosts.push(excHost);

        // Interleave includes and excludes in arbitrary order
        if (i % 2 === 0) {
          rules.push({ pattern: incHost, type: 'include' });
          rules.push({ pattern: excHost, type: 'exclude' });
        } else {
          rules.push({ pattern: excHost, type: 'exclude' });
          rules.push({ pattern: incHost, type: 'include' });
        }
      }

      // Add a broad wildcard include for the entire cluster
      rules.push({ pattern: '*.cluster.corp', type: 'include' });

      const stressEngine = new ScopeEngine(rules);

      // Verify oracle: 100% of excluded hosts evaluate to 'out-of-scope'
      for (const exc of excludedHosts) {
        const evalRes = stressEngine.evaluate(`https://${exc}/api`);
        expect(evalRes.status).toBe('out-of-scope');
        expect(evalRes.ruleType).toBe('exclude');
      }

      // Verify included hosts evaluate to 'in-scope'
      for (const inc of includedHosts) {
        const evalRes = stressEngine.evaluate(`https://${inc}/api`);
        expect(evalRes.status).toBe('in-scope');
        expect(evalRes.ruleType).toBe('include');
      }
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Explicit Port Preservation & Matching Empirical Tests
  // ─────────────────────────────────────────────────────────────────────────────

  describe('3. Explicit Port Preservation: Ports preserved and matched accurately', () => {
    describe('Port preservation during normalization', () => {
      it('preserves non-standard explicit ports on hostnames and URLs', () => {
        expect(parseScheme('https://example.com:8443')).toBe('https');
        expect(parseScheme('http://api.local:3000')).toBe('http');
        expect(normalizeScopeTarget('example.com:8080').port).toBe(8080);
        expect(normalizeScopeTarget('https://example.com:8443').port).toBe(8443);
        expect(normalizeScopeTarget('https://example.com:8443/login?q=1').port).toBe(8443);
        expect(normalizeScopeTarget('http://api.local:3000').port).toBe(3000);
        expect(normalizeScopeTarget('*.target.io:9000').port).toBe(9000);
      });

      it('preserves standard ports 80 and 443 without silent discarding', () => {
        // Standard ports 80/443 are stripped by native URL parser, but ACULYX must preserve them
        expect(extractExplicitPort('http://example.com:80')).toBe(80);
        expect(extractExplicitPort('https://example.com:443')).toBe(443);
        expect(extractExplicitPort('example.com:80')).toBe(80);
        expect(extractExplicitPort('example.com:443')).toBe(443);

        const target80 = normalizeScopeTarget('http://example.com:80');
        expect(target80.port).toBe(80);
        expect(target80.scheme).toBe('http');

        const target443 = normalizeScopeTarget('https://example.com:443');
        expect(target443.port).toBe(443);
        expect(target443.scheme).toBe('https');
      });

      it('leaves port undefined when omitted in raw target', () => {
        expect(normalizeScopeTarget('https://example.com').port).toBeUndefined();
        expect(normalizeScopeTarget('http://example.com').port).toBeUndefined();
        expect(normalizeScopeTarget('example.com').port).toBeUndefined();
      });

      it('preserves explicit ports on IPv6 bracketed hosts', () => {
        expect(normalizeScopeTarget('[::1]:8080').port).toBe(8080);
        expect(normalizeScopeTarget('[::1]:8080').hostname).toBe('[::1]');
        expect(normalizeScopeTarget('https://[2001:db8::1]:8443/path').port).toBe(8443);
        expect(normalizeScopeTarget('https://[2001:db8::1]:8443/path').hostname).toBe('[2001:db8::1]');
      });

      it('strictly enforces port boundary range [1, 65535]', () => {
        expect(normalizeScopeTarget('example.com:1').port).toBe(1);
        expect(normalizeScopeTarget('example.com:65535').port).toBe(65535);

        expect(() => normalizeScopeTarget('example.com:0')).toThrow(/Invalid port number/);
        expect(() => normalizeScopeTarget('example.com:65536')).toThrow(/Invalid port number/);
        expect(() => normalizeScopeTarget('example.com:-1')).toThrow(/Invalid port number/);
        expect(() => normalizeScopeTarget('example.com:999999')).toThrow(/Invalid port number/);
        expect(() => normalizeScopeTarget('example.com:80.5')).toThrow(/Invalid port number/);
        expect(() => normalizeScopeTarget('example.com:port')).toThrow(/Invalid port number/);
      });
    });

    describe('Port matching accuracy in ScopeEngine', () => {
      it('evaluates explicit port rule example.com:8080 accurately', () => {
        const engine = new ScopeEngine([
          { pattern: 'example.com:8080', type: 'include' },
        ]);

        // Exact match
        expect(engine.evaluate('example.com:8080').status).toBe('in-scope');
        expect(engine.evaluate('https://example.com:8080/').status).toBe('in-scope');
        expect(engine.evaluate('http://example.com:8080/api').status).toBe('in-scope');

        // Mismatched port
        expect(engine.evaluate('example.com:8081').status).toBe('unknown');
        expect(engine.evaluate('https://example.com:8081/').status).toBe('unknown');

        // Omitted port
        expect(engine.evaluate('example.com').status).toBe('unknown');
        expect(engine.evaluate('https://example.com/').status).toBe('unknown');
      });

      it('evaluates explicit https port rule https://example.com:8443 accurately', () => {
        const engine = new ScopeEngine([
          { pattern: 'https://example.com:8443', type: 'include' },
        ]);

        // Matches https with 8443
        expect(engine.evaluate('https://example.com:8443/checkout').status).toBe('in-scope');

        // Rejects http with 8443 (scheme mismatch)
        expect(engine.evaluate('http://example.com:8443/checkout').status).toBe('unknown');

        // Rejects https with 443 (port mismatch)
        expect(engine.evaluate('https://example.com:443/checkout').status).toBe('unknown');
      });

      it('evaluates explicit standard port rules example.com:443 and example.com:80 accurately', () => {
        const engine = new ScopeEngine([
          { pattern: 'example.com:443', type: 'include' },
          { pattern: 'example.com:80', type: 'include' },
        ]);

        expect(engine.evaluate('https://example.com:443/').status).toBe('in-scope');
        expect(engine.evaluate('http://example.com:80/').status).toBe('in-scope');
        expect(engine.evaluate('example.com:443').status).toBe('in-scope');
        expect(engine.evaluate('example.com:80').status).toBe('in-scope');

        // Target with custom port does NOT match standard port rules
        expect(engine.evaluate('example.com:8080').status).toBe('unknown');
      });

      it('evaluates wildcard rule with explicit port (*.example.com:9443)', () => {
        const engine = new ScopeEngine([
          { pattern: '*.example.com:9443', type: 'include' },
        ]);

        // Subdomain with port 9443 matches
        expect(engine.evaluate('https://api.example.com:9443/').status).toBe('in-scope');
        expect(engine.evaluate('https://dev.v1.example.com:9443/').status).toBe('in-scope');

        // Subdomain with different port does NOT match
        expect(engine.evaluate('https://api.example.com:443/').status).toBe('unknown');

        // Apex with port 9443 does NOT match (wildcard boundary!)
        expect(engine.evaluate('https://example.com:9443/').status).toBe('unknown');
      });
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Punycode IDNA Normalization Empirical Tests
  // ─────────────────────────────────────────────────────────────────────────────

  describe('4. Punycode IDNA Normalization: Unicode domains & punycode resolution', () => {
    it('normalizes internationalized unicode domains to correct ASCII punycode', () => {
      // German umlaut
      expect(normalizeHostname('münchen.de')).toBe('xn--mnchen-3ya.de');
      expect(normalizeHostname('MÜNCHEN.DE')).toBe('xn--mnchen-3ya.de');
      expect(normalizeHostname('München.De.')).toBe('xn--mnchen-3ya.de');
      expect(normalizeHostname('bücher.de')).toBe('xn--bcher-kva.de');
      expect(normalizeHostname('österreich.at')).toBe('xn--sterreich-z7a.at');

      // Cyrillic
      expect(normalizeHostname('президент.рф')).toBe('xn--d1abbgf6aiiy.xn--p1ai');

      // Japanese
      expect(normalizeHostname('日本語.jp')).toBe('xn--wgv71a119e.jp');

      // Chinese
      expect(normalizeHostname('测试.cn')).toBe('xn--0zwm56d.cn');

      // Arabic
      expect(normalizeHostname('موقع.مصر')).toBe('xn--4gbrim.xn--wgbh1c');
    });

    it('idempotently normalizes punycode inputs', () => {
      expect(normalizeHostname('xn--mnchen-3ya.de')).toBe('xn--mnchen-3ya.de');
      expect(normalizeHostname('XN--MNCHEN-3YA.DE')).toBe('xn--mnchen-3ya.de');
      expect(normalizeHostname('xn--d1abbgf6aiiy.xn--p1ai')).toBe('xn--d1abbgf6aiiy.xn--p1ai');
    });

    it('matches unicode target when rule is configured in unicode', () => {
      const engine = new ScopeEngine([
        { pattern: 'münchen.de', type: 'include' },
      ]);

      // Evaluates unicode target
      const resUnicode = engine.evaluate('https://münchen.de/rathaus');
      expect(resUnicode.status).toBe('in-scope');

      // Evaluates punycode target
      const resPunycode = engine.evaluate('https://xn--mnchen-3ya.de/rathaus');
      expect(resPunycode.status).toBe('in-scope');

      // Evaluates uppercase unicode target
      const resUpper = engine.evaluate('https://MÜNCHEN.DE/');
      expect(resUpper.status).toBe('in-scope');
    });

    it('matches unicode target when rule is configured in punycode', () => {
      const engine = new ScopeEngine([
        { pattern: 'xn--mnchen-3ya.de', type: 'include' },
      ]);

      // Evaluates unicode target
      const resUnicode = engine.evaluate('https://münchen.de/service');
      expect(resUnicode.status).toBe('in-scope');

      // Evaluates punycode target
      const resPunycode = engine.evaluate('https://xn--mnchen-3ya.de/service');
      expect(resPunycode.status).toBe('in-scope');
    });

    it('enforces wildcard boundaries on IDNA domains (*.münchen.de)', () => {
      const engine = new ScopeEngine([
        { pattern: '*.münchen.de', type: 'include' },
      ]);

      // Subdomains in unicode and punycode are in-scope
      expect(engine.evaluate('https://stadt.münchen.de/').status).toBe('in-scope');
      expect(engine.evaluate('https://stadt.xn--mnchen-3ya.de/').status).toBe('in-scope');
      expect(engine.evaluate('https://portal.stadt.münchen.de/').status).toBe('in-scope');

      // Apex in unicode and punycode NEVER matches wildcard
      expect(engine.evaluate('https://münchen.de/').status).toBe('unknown');
      expect(engine.evaluate('https://xn--mnchen-3ya.de/').status).toBe('unknown');
    });

    it('enforces exclusion precedence across IDNA unicode and punycode representations', () => {
      const engine = new ScopeEngine([
        { pattern: '*.münchen.de', type: 'include' },
        // Exclusion rule defined in punycode
        { pattern: 'geheim.xn--mnchen-3ya.de', type: 'exclude' },
      ]);

      // Target in unicode matches exclusion
      const resUnicode = engine.evaluate('https://geheim.münchen.de/intern');
      expect(resUnicode.status).toBe('out-of-scope');
      expect(resUnicode.ruleType).toBe('exclude');

      // Target in punycode matches exclusion
      const resPunycode = engine.evaluate('https://geheim.xn--mnchen-3ya.de/intern');
      expect(resPunycode.status).toBe('out-of-scope');
      expect(resPunycode.ruleType).toBe('exclude');

      // Unexcluded IDNA subdomain remains in-scope
      const resOther = engine.evaluate('https://kultur.münchen.de/');
      expect(resOther.status).toBe('in-scope');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. Independent Evaluation of Redirect Hops & Third-Party APIs
  // ─────────────────────────────────────────────────────────────────────────────

  describe('5. Independent Evaluation: Redirect hops & third-party APIs evaluated independently', () => {
    const profile: ScopeProfile = {
      id: 'independent-test',
      name: 'Independent Evaluation Test Profile',
      rules: [
        { pattern: '*.acme.com', type: 'include', description: 'Acme subdomains' },
        { pattern: 'acme.com', type: 'include', description: 'Acme apex' },
        { pattern: 'admin.acme.com', type: 'exclude', description: 'Admin panel excluded' },
      ],
    };

    const engine = new ScopeEngine(profile);

    describe('Redirect hops independent evaluation', () => {
      it('evaluates redirect chain where intermediate hop is unconfigured third party', () => {
        // Step 0: In-scope login page
        const hop0 = 'https://acme.com/login';
        expect(engine.evaluate(hop0).status).toBe('in-scope');

        // Step 1: Redirect hop to third-party OAuth provider
        const hop1 = 'https://accounts.google.com/o/oauth2/auth';
        const resHop1 = engine.evaluateRedirectHop(hop1, hop0);

        // MUST NOT inherit 'in-scope' status from hop 0
        expect(resHop1.status).toBe('unknown');
        expect(resHop1.reason).toContain('Redirect hop (redirected from https://acme.com/login) evaluated independently');
        expect(resHop1.reason).toContain('accounts.google.com is not covered');
      });

      it('evaluates redirect hop to explicitly excluded internal host', () => {
        // Redirect hop to excluded admin endpoint
        const hop = 'https://admin.acme.com/callback';
        const res = engine.evaluateRedirectHop(hop, 'https://acme.com/login');

        // MUST be out-of-scope due to exclusion precedence
        expect(res.status).toBe('out-of-scope');
        expect(res.ruleType).toBe('exclude');
        expect(res.reason).toContain('Redirect hop (redirected from https://acme.com/login) evaluated independently');
      });

      it('evaluates redirect hop back to authorized in-scope subdomain', () => {
        // Redirect hop back to portal.acme.com
        const hop = 'https://portal.acme.com/dashboard';
        const res = engine.evaluateRedirectHop(hop, 'https://accounts.google.com/o/oauth2/auth');

        // MUST be in-scope independently
        expect(res.status).toBe('in-scope');
        expect(res.ruleType).toBe('include');
        expect(res.reason).toContain('Redirect hop (redirected from https://accounts.google.com/o/oauth2/auth) evaluated independently');
      });
    });

    describe('Third-party APIs & subresources independent evaluation', () => {
      it('never marks unconfigured third-party scripts as in-scope even when loaded on in-scope page', () => {
        const firstParty = 'https://acme.com/index.html';
        const cdnScript = 'https://cdn.thirdparty-analytics.com/tracker.js';

        const res = engine.evaluateThirdParty(cdnScript, firstParty);
        expect(res.status).toBe('unknown');
        expect(res.reason).toContain('Subresource evaluated independently from page https://acme.com/index.html');
        expect(res.reason).toContain('cdn.thirdparty-analytics.com is not covered');
      });

      it('correctly marks excluded subresource as out-of-scope even when embedded on in-scope page', () => {
        const firstParty = 'https://acme.com/portal';
        const excludedTelemetry = 'https://admin.acme.com/api/telemetry';

        const res = engine.evaluateThirdParty(excludedTelemetry, firstParty);
        expect(res.status).toBe('out-of-scope');
        expect(res.ruleType).toBe('exclude');
        expect(res.matchedPattern).toBe('admin.acme.com');
      });

      it('correctly marks in-scope API as in-scope even when requested from an unconfigured origin', () => {
        const externalPage = 'https://partner-portal.net/embed';
        const inScopeApi = 'https://api.acme.com/v1/customer';

        const res = engine.evaluateThirdParty(inScopeApi, externalPage);
        expect(res.status).toBe('in-scope');
        expect(res.ruleType).toBe('include');
        expect(res.matchedPattern).toBe('*.acme.com');
      });

      it('correctly marks in-scope API as in-scope even when requested from an excluded origin', () => {
        const excludedPage = 'https://admin.acme.com/internal-app';
        const inScopeApi = 'https://public.acme.com/v1/meta';

        const res = engine.evaluateThirdParty(inScopeApi, excludedPage);
        expect(res.status).toBe('in-scope');
        expect(res.ruleType).toBe('include');
      });
    });

    describe('Functional helpers evaluateScope, evaluateRedirectHop, evaluateThirdParty', () => {
      it('evaluates standalone functional helpers consistently', () => {
        expect(evaluateScope('https://acme.com', profile).status).toBe('in-scope');
        expect(evaluateScope('https://admin.acme.com', profile).status).toBe('out-of-scope');
        expect(evaluateScope('https://unknown.org', profile).status).toBe('unknown');

        const hopRes = evaluateRedirectHop('https://google.com', profile);
        expect(hopRes.status).toBe('unknown');

        const subRes = evaluateThirdParty('https://api.acme.com/data', 'https://acme.com', profile);
        expect(subRes.status).toBe('in-scope');
      });
    });
  });
});
