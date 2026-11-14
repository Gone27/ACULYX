import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  executeCredentialLivenessCheck,
  getLivenessProbeTarget,
  classifyGitHubResponse,
  classifyStripeResponse,
  classifySlackResponse,
} from '../../src/leads/verify/credential-liveness';
import type { SecretCandidate } from '../../src/background/secret-candidate-store';

describe('Credential Liveness Phase 2: Provider Adapters & Pure Classifiers', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe('Probe Target Definitions (fixed, hardcoded targets)', () => {
    it('defines fixed GitHub user target for ghp / gho / ghu / github_pat', () => {
      const target = getLivenessProbeTarget('github', 'ghp');
      expect(target).toBeDefined();
      expect(target?.url).toBe('https://api.github.com/user');
      expect(target?.method).toBe('GET');

      const patTarget = getLivenessProbeTarget('github', 'github_pat');
      expect(patTarget?.url).toBe('https://api.github.com/user');
      expect(patTarget?.method).toBe('GET');
    });

    it('defines fixed Stripe balance target for sk_live, rk_live, sk_test, and rk_test', () => {
      const skTarget = getLivenessProbeTarget('stripe', 'sk_live');
      expect(skTarget).toBeDefined();
      expect(skTarget?.url).toBe('https://api.stripe.com/v1/balance');
      expect(skTarget?.method).toBe('GET');

      const rkTarget = getLivenessProbeTarget('stripe', 'rk_live');
      expect(rkTarget?.url).toBe('https://api.stripe.com/v1/balance');
      expect(rkTarget?.method).toBe('GET');

      const skTestTarget = getLivenessProbeTarget('stripe', 'sk_test');
      expect(skTestTarget).toBeDefined();
      expect(skTestTarget?.url).toBe('https://api.stripe.com/v1/balance');
      expect(skTestTarget?.method).toBe('GET');

      const rkTestTarget = getLivenessProbeTarget('stripe', 'rk_test');
      expect(rkTestTarget).toBeDefined();
      expect(rkTestTarget?.url).toBe('https://api.stripe.com/v1/balance');
      expect(rkTestTarget?.method).toBe('GET');
    });

    it('defines fixed Slack auth.test target for xoxb and xoxp', () => {
      const botTarget = getLivenessProbeTarget('slack', 'xoxb');
      expect(botTarget).toBeDefined();
      expect(botTarget?.url).toBe('https://slack.com/api/auth.test');
      expect(botTarget?.method).toBe('POST');

      const userTarget = getLivenessProbeTarget('slack', 'xoxp');
      expect(userTarget?.url).toBe('https://slack.com/api/auth.test');
      expect(userTarget?.method).toBe('POST');
    });

    it('returns undefined for unsupported token families', () => {
      expect(getLivenessProbeTarget('github', 'ghs')).toBeUndefined();
      expect(getLivenessProbeTarget('slack', 'xoxs')).toBeUndefined();
      expect(getLivenessProbeTarget('stripe', 'pk_live')).toBeUndefined();
    });
  });

  describe('Pure Response Classifiers', () => {
    describe('classifyGitHubResponse', () => {
      it('classifies 200 as active_at_check', () => {
        const res = classifyGitHubResponse(200);
        expect(res.status).toBe('active_at_check');
        expect(res.details).toContain('GitHub accepted');
      });

      it('classifies 401 as inactive_at_check', () => {
        const res = classifyGitHubResponse(401);
        expect(res.status).toBe('inactive_at_check');
        expect(res.details).toContain('rejected');
      });

      it('classifies 403 as permission_limited (never called invalid)', () => {
        const res = classifyGitHubResponse(403);
        expect(res.status).toBe('permission_limited');
        expect(res.details).toContain('permission or rate limit');
      });

      it('classifies 404 as permission_limited', () => {
        const res = classifyGitHubResponse(404);
        expect(res.status).toBe('permission_limited');
      });

      it('classifies 429 and 5xx as unknown (throttled / error)', () => {
        expect(classifyGitHubResponse(429).status).toBe('unknown');
        expect(classifyGitHubResponse(500).status).toBe('unknown');
      });
    });

    describe('classifyStripeResponse', () => {
      it('classifies 200 as active_at_check and extracts livemode safely without balances', () => {
        const res = classifyStripeResponse(200, {
          object: 'balance',
          available: [{ amount: 100000, currency: 'usd' }], // must be ignored
          livemode: true,
        }, 'sk_live');
        expect(res.status).toBe('active_at_check');
        expect(res.livemode).toBe(true);
        expect(res.details).toContain('Stripe accepted');
      });

      it('classifies 200 with test key and livemode false as active_at_check', () => {
        const res = classifyStripeResponse(200, {
          object: 'balance',
          livemode: false,
        }, 'sk_test');
        expect(res.status).toBe('active_at_check');
        expect(res.livemode).toBe(false);
        expect(res.details).toContain('Stripe accepted');
      });

      it('rejects 200 when object is not balance or livemode is not boolean', () => {
        expect(classifyStripeResponse(200, { object: 'account', livemode: true }, 'sk_live').status).toBe('unknown');
        expect(classifyStripeResponse(200, { object: 'balance' }, 'sk_live').status).toBe('unknown');
        expect(classifyStripeResponse(200, { object: 'balance', livemode: 'true' as unknown as boolean }, 'sk_live').status).toBe('unknown');
        expect(classifyStripeResponse(200, undefined, 'sk_live').status).toBe('unknown');
      });

      it('rejects 200 when livemode does not agree with tokenFamily', () => {
        const liveMismatch = classifyStripeResponse(200, { object: 'balance', livemode: false }, 'sk_live');
        expect(liveMismatch.status).toBe('unknown');
        expect(liveMismatch.details).toContain('livemode (false) does not match');

        const testMismatch = classifyStripeResponse(200, { object: 'balance', livemode: true }, 'sk_test');
        expect(testMismatch.status).toBe('unknown');
        expect(testMismatch.details).toContain('livemode (true) does not match');

        const rkLiveMismatch = classifyStripeResponse(200, { object: 'balance', livemode: false }, 'rk_live');
        expect(rkLiveMismatch.status).toBe('unknown');

        const rkTestMismatch = classifyStripeResponse(200, { object: 'balance', livemode: true }, 'rk_test');
        expect(rkTestMismatch.status).toBe('unknown');
      });

      it('classifies 401 as inactive_at_check', () => {
        const res = classifyStripeResponse(401, { error: { message: 'Invalid API Key' } });
        expect(res.status).toBe('inactive_at_check');
      });

      it('classifies 403 as permission_limited (restricted key lack of balance permissions)', () => {
        const res = classifyStripeResponse(403);
        expect(res.status).toBe('permission_limited');
        expect(res.details).toContain('permission');
      });

      it('classifies 429 and 500 as unknown', () => {
        expect(classifyStripeResponse(429).status).toBe('unknown');
        expect(classifyStripeResponse(502).status).toBe('unknown');
      });
    });

    describe('classifySlackResponse', () => {
      it('classifies ok:true as active_at_check and ignores workspace/user identifiers', () => {
        const res = classifySlackResponse(200, {
          ok: true,
          url: 'https://secret-corp.slack.com/',
          team: 'Secret Corp',
          user: 'CEO',
        });
        expect(res.status).toBe('active_at_check');
        expect(res.details).not.toContain('Secret Corp');
      });

      it('classifies explicit token_revoked or token_expired as inactive_at_check', () => {
        expect(classifySlackResponse(200, { ok: false, error: 'token_revoked' }).status).toBe('inactive_at_check');
        expect(classifySlackResponse(200, { ok: false, error: 'token_expired' }).status).toBe('inactive_at_check');
      });

      it('classifies invalid_auth as permission_limited (may be IP-blocked / conditional)', () => {
        const res = classifySlackResponse(200, { ok: false, error: 'invalid_auth' });
        expect(res.status).toBe('permission_limited');
        expect(res.details).toContain('not authenticated or IP restricted');
      });

      it('classifies missing_scope and not_allowed_token_type as permission_limited', () => {
        expect(classifySlackResponse(200, { ok: false, error: 'missing_scope' }).status).toBe('permission_limited');
        expect(classifySlackResponse(200, { ok: false, error: 'not_allowed_token_type' }).status).toBe('permission_limited');
      });

      it('classifies ratelimited and non-200 HTTP as unknown', () => {
        expect(classifySlackResponse(200, { ok: false, error: 'ratelimited' }).status).toBe('unknown');
        expect(classifySlackResponse(500, {}).status).toBe('unknown');
      });
    });
  });

  describe('executeCredentialLivenessCheck Invariant Safety Checks', () => {
    it('executes GitHub GET request with exact pinned API version and omit credentials', async () => {
      let capturedUrl = '';
      let capturedInit: RequestInit | undefined;

      const mockFetch = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
        capturedUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        capturedInit = init;
        return Promise.resolve(new Response(JSON.stringify({ login: 'octocat' }), { status: 200 }));
      });

      const candidate: SecretCandidate = {
        leadId: 'LD-1',
        provider: 'github',
        tokenFamily: 'ghp',
        rawToken: 'ghp_TESTTOKEN123456789012345678901234',
        expiresAt: Date.now() + 60000,
        attempted: false,
      };

      const result = await executeCredentialLivenessCheck(candidate, { fetchFn: mockFetch });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(capturedUrl).toBe('https://api.github.com/user');
      expect(capturedInit?.method).toBe('GET');
      expect(capturedInit?.credentials).toBe('omit');
      expect(capturedInit?.redirect).toBe('manual');
      expect(capturedInit?.cache).toBe('no-store');
      expect(capturedInit?.referrerPolicy).toBe('no-referrer');

      const headers = capturedInit?.headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer ghp_TESTTOKEN123456789012345678901234');
      expect(headers['Accept']).toBe('application/vnd.github+json');
      expect(headers['X-GitHub-Api-Version']).toBe('2026-03-10');

      expect(result.status).toBe('active_at_check');
      expect(result.provider).toBe('github');
      expect(result.tokenFamily).toBe('ghp');
      // Must not leak private bodies or raw tokens in details
      expect(result.details).not.toContain('octocat');
      expect(result.details).not.toContain('ghp_TESTTOKEN');
    });

    it('executes Stripe GET request to /v1/balance with credentials: omit and livemode extraction', async () => {
      let capturedInit: RequestInit | undefined;
      const mockFetch = vi.fn().mockImplementation((_url: RequestInfo | URL, init?: RequestInit) => {
        capturedInit = init;
        return Promise.resolve(new Response(JSON.stringify({ object: 'balance', livemode: true }), { status: 200 }));
      });

      const candidate: SecretCandidate = {
        leadId: 'LD-2',
        provider: 'stripe',
        tokenFamily: 'sk_live',
        rawToken: 'sk_live_123456789012345678901234',
        expiresAt: Date.now() + 60000,
        attempted: false,
      };

      const result = await executeCredentialLivenessCheck(candidate, { fetchFn: mockFetch });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(capturedInit?.credentials).toBe('omit');
      expect(capturedInit?.redirect).toBe('manual');
      expect(result.status).toBe('active_at_check');
      expect(result.livemode).toBe(true);
    });

    it('executes Slack POST request to auth.test with empty body and Content-Type', async () => {
      let capturedUrl = '';
      let capturedInit: RequestInit | undefined;
      const mockFetch = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
        capturedUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        capturedInit = init;
        return Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 }));
      });

      const candidate: SecretCandidate = {
        leadId: 'LD-3',
        provider: 'slack',
        tokenFamily: 'xoxb',
        rawToken: 'xoxb-123456-123456-abcdef',
        expiresAt: Date.now() + 60000,
        attempted: false,
      };

      const result = await executeCredentialLivenessCheck(candidate, { fetchFn: mockFetch });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(capturedUrl).toBe('https://slack.com/api/auth.test');
      expect(capturedInit?.method).toBe('POST');
      expect(capturedInit?.body).toBe('{}');
      expect(result.status).toBe('active_at_check');
    });

    it('returns unsupported for unknown token family without sending any request', async () => {
      const mockFetch = vi.fn();
      const candidate: SecretCandidate = {
        leadId: 'LD-4',
        provider: 'slack',
        tokenFamily: 'xoxs', // unsupported in v1
        rawToken: 'xoxs-123456',
        expiresAt: Date.now() + 60000,
        attempted: false,
      };

      const result = await executeCredentialLivenessCheck(candidate, { fetchFn: mockFetch });
      expect(mockFetch).not.toHaveBeenCalled();
      expect(result.status).toBe('unsupported');
    });

    it('handles network failure fail-closed returning unknown without throwing', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
      const candidate: SecretCandidate = {
        leadId: 'LD-5',
        provider: 'github',
        tokenFamily: 'ghp',
        rawToken: 'ghp_abc',
        expiresAt: Date.now() + 60000,
        attempted: false,
      };

      const result = await executeCredentialLivenessCheck(candidate, { fetchFn: mockFetch });
      expect(result.status).toBe('unknown');
      expect(result.details).toContain('Network error');
    });
  });

  describe('readBoundedJson streaming reader bounds and error reflection safety', () => {
    it('cancels reader and caps stream accumulation at 8 KiB on oversized responses', async () => {
      const { readBoundedJson } = await import('../../src/leads/verify/credential-liveness');
      let cancelled = false;
      const totalChunks = 10;
      const chunkSize = 2048; // 20 KiB total
      let chunkIdx = 0;

      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (chunkIdx < totalChunks) {
            const chunk = new Uint8Array(chunkSize);
            chunk.fill(65); // 'A'
            controller.enqueue(chunk);
            chunkIdx++;
          } else {
            controller.close();
          }
        },
        cancel() {
          cancelled = true;
        },
      });

      const response = new Response(stream);
      const parsed = await readBoundedJson(response);

      // Oversized stream of 'A's is not valid JSON
      expect(parsed).toBeUndefined();
      // Must have invoked cancel() once the 8 KiB threshold was reached
      expect(cancelled).toBe(true);
      expect(chunkIdx).toBeLessThanOrEqual(5); // At most 5 chunks of 2048 bytes (capped at 8192)
    });

    it('rejects incomplete truncated JSON and non-object responses safely', async () => {
      const { readBoundedJson } = await import('../../src/leads/verify/credential-liveness');
      // Incomplete JSON cut off
      const res1 = new Response('{"ok": true, "user":');
      expect(await readBoundedJson(res1)).toBeUndefined();

      // Array instead of object
      const res2 = new Response('[1, 2, 3]');
      expect(await readBoundedJson(res2)).toBeUndefined();

      // Primitive instead of object
      const res3 = new Response('"string"');
      expect(await readBoundedJson(res3)).toBeUndefined();
    });

    it('never reflects unexpected Slack error text or synthetic secrets into details or storage', () => {
      const adversarialError = 'ghp_adversarial_token_12345678901234567890 <script>alert(1)</script> \x00\x1f';
      const classified = classifySlackResponse(200, { ok: false, error: adversarialError });

      expect(classified.status).toBe('unknown');
      expect(classified.details).toBe('Slack returned an unrecognized response.');
      expect(classified.details).not.toContain('ghp_');
      expect(classified.details).not.toContain('<script>');
      expect(classified.details).not.toContain('\x00');
    });
  });
});
