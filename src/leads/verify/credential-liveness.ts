import type { CredentialCheckResult, CredentialCheckStatus, CredentialProvider } from '../types';
import type { SecretCandidate } from '../../background/secret-candidate-store';

export interface LivenessProbeTarget {
  provider: CredentialProvider;
  url: string;
  method: 'GET' | 'POST';
  tokenFamily: string;
}

const GITHUB_SUPPORTED_FAMILIES = new Set(['ghp', 'gho', 'ghu', 'github_pat']);
const STRIPE_SUPPORTED_FAMILIES = new Set(['sk_live', 'rk_live', 'sk_test', 'rk_test']);
const SLACK_SUPPORTED_FAMILIES = new Set(['xoxb', 'xoxp']);

const GITHUB_PINNED_API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 8192; // 8 KiB limit per behavior contract
const REQUEST_TIMEOUT_MS = 5000;

/**
 * Returns the fixed, hardcoded probe target for a given provider and token family.
 * Returns undefined for unsupported token families.
 * Callers cannot supply or modify URL, method, headers, or body.
 */
export function getLivenessProbeTarget(
  provider: CredentialProvider,
  tokenFamily: string
): LivenessProbeTarget | undefined {
  if (provider === 'github' && GITHUB_SUPPORTED_FAMILIES.has(tokenFamily)) {
    return {
      provider: 'github',
      url: 'https://api.github.com/user',
      method: 'GET',
      tokenFamily,
    };
  }

  if (provider === 'stripe' && STRIPE_SUPPORTED_FAMILIES.has(tokenFamily)) {
    return {
      provider: 'stripe',
      url: 'https://api.stripe.com/v1/balance',
      method: 'GET',
      tokenFamily,
    };
  }

  if (provider === 'slack' && SLACK_SUPPORTED_FAMILIES.has(tokenFamily)) {
    return {
      provider: 'slack',
      url: 'https://slack.com/api/auth.test',
      method: 'POST',
      tokenFamily,
    };
  }

  return undefined;
}

/**
 * Pure response classifier for GitHub GET /user.
 */
export function classifyGitHubResponse(
  status: number
): { status: CredentialCheckStatus; details: string } {
  if (status === 200) {
    return {
      status: 'active_at_check',
      details: 'GitHub accepted this credential at check time.',
    };
  }
  if (status === 401) {
    return {
      status: 'inactive_at_check',
      details: 'GitHub rejected this credential as invalid, expired, or revoked.',
    };
  }
  if (status === 403 || status === 404) {
    return {
      status: 'permission_limited',
      details: 'Credential reached GitHub but endpoint permission or rate limit prevented verification.',
    };
  }
  if (status === 429) {
    return {
      status: 'unknown',
      details: 'GitHub rate limited this check. Do not retry automatically.',
    };
  }
  return {
    status: 'unknown',
    details: `GitHub responded with unexpected HTTP status ${status}.`,
  };
}

/**
 * Pure response classifier for Stripe GET /v1/balance.
 * Validates the balance object structure, verifies livemode boolean,
 * and checks key-prefix mode agreement against tokenFamily.
 */
export function classifyStripeResponse(
  status: number,
  bodyJson?: Record<string, unknown>,
  tokenFamily?: string
): { status: CredentialCheckStatus; details: string; livemode?: boolean } {
  if (status === 200) {
    if (
      !bodyJson ||
      typeof bodyJson !== 'object' ||
      bodyJson.object !== 'balance' ||
      typeof bodyJson.livemode !== 'boolean'
    ) {
      return {
        status: 'unknown',
        details: 'Stripe responded with HTTP 200 but response body did not match expected balance object format.',
      };
    }

    const livemode = bodyJson.livemode;

    if (tokenFamily === 'sk_live' || tokenFamily === 'rk_live') {
      if (!livemode) {
        return {
          status: 'unknown',
          details: 'Stripe response livemode (false) does not match expected live key token family.',
          livemode,
        };
      }
    } else if (tokenFamily === 'sk_test' || tokenFamily === 'rk_test') {
      if (livemode) {
        return {
          status: 'unknown',
          details: 'Stripe response livemode (true) does not match expected test key token family.',
          livemode,
        };
      }
    }

    return {
      status: 'active_at_check',
      details: 'Stripe accepted this credential at check time.',
      livemode,
    };
  }
  if (status === 401) {
    return {
      status: 'inactive_at_check',
      details: 'Stripe rejected this credential as invalid or revoked.',
    };
  }
  if (status === 403) {
    return {
      status: 'permission_limited',
      details: 'Stripe rejected balance retrieval due to restricted key permissions; validity unresolved.',
    };
  }
  if (status === 429) {
    return {
      status: 'unknown',
      details: 'Stripe rate limit encountered. Do not retry automatically.',
    };
  }
  return {
    status: 'unknown',
    details: `Stripe responded with unexpected HTTP status ${status}.`,
  };
}

/**
 * Pure response classifier for Slack POST /api/auth.test.
 */
export function classifySlackResponse(
  status: number,
  bodyJson?: Record<string, unknown>
): { status: CredentialCheckStatus; details: string } {
  if (status !== 200) {
    return {
      status: 'unknown',
      details: `Slack responded with HTTP status ${status}.`,
    };
  }

  if (bodyJson?.ok === true) {
    return {
      status: 'active_at_check',
      details: 'Slack accepted this credential at check time.',
    };
  }

  const error = typeof bodyJson?.error === 'string' ? bodyJson.error : '';

  if (error === 'token_revoked' || error === 'token_expired') {
    return {
      status: 'inactive_at_check',
      details: `Slack reported credential is ${error}.`,
    };
  }

  if (error === 'invalid_auth') {
    return {
      status: 'permission_limited',
      details: 'Slack reported credential was not authenticated or IP restricted at check time.',
    };
  }

  if (error === 'missing_scope') {
    return {
      status: 'permission_limited',
      details: 'Slack reported credential check is limited: missing scope.',
    };
  }

  if (error === 'not_allowed_token_type') {
    return {
      status: 'permission_limited',
      details: 'Slack reported token type is not permitted for this check.',
    };
  }

  if (error === 'account_inactive') {
    return {
      status: 'permission_limited',
      details: 'Slack reported the associated account is inactive.',
    };
  }

  if (error === 'ratelimited') {
    return {
      status: 'unknown',
      details: 'Slack rate limit encountered. Do not retry automatically.',
    };
  }

  // Any unrecognized or missing error value maps strictly to fixed string — NEVER interpolate vendor response text
  return {
    status: 'unknown',
    details: 'Slack returned an unrecognized response.',
  };
}

/**
 * Bounded JSON response reader that streams up to MAX_RESPONSE_BYTES (8 KiB),
 * promptly cancels the stream reader upon reaching the cap, and parses safely.
 */
export async function readBoundedJson(response: Response): Promise<Record<string, unknown> | undefined> {
  try {
    let rawText = '';
    const body = response.body;

    if (body !== null && typeof body === 'object' && typeof body.getReader === 'function') {
      const reader = body.getReader();
      const decoder = new TextDecoder('utf-8');
      let bytesAccumulated = 0;
      try {
        while (bytesAccumulated < MAX_RESPONSE_BYTES) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value !== undefined && value.byteLength > 0) {
            const needed = MAX_RESPONSE_BYTES - bytesAccumulated;
            const slice = value.byteLength > needed ? value.subarray(0, needed) : value;
            rawText += decoder.decode(slice, { stream: true });
            bytesAccumulated += slice.byteLength;
            if (bytesAccumulated >= MAX_RESPONSE_BYTES) {
              await reader.cancel().catch(() => undefined);
              break;
            }
          }
        }
        rawText += decoder.decode();
      } finally {
        reader.releaseLock?.();
      }
    } else {
      // Fallback for mock environments lacking ReadableStream getReader
      const text = await response.text();
      rawText = text.slice(0, MAX_RESPONSE_BYTES);
    }

    if (rawText.length === 0) return undefined;
    const parsed = JSON.parse(rawText) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return undefined;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/**
 * Executes a single, strictly bounded credential liveness check.
 * Strictly adheres to:
 * - credentials: 'omit'
 * - redirect: 'manual'
 * - cache: 'no-store'
 * - referrerPolicy: 'no-referrer'
 * - 5-second timeout
 * - Zero retention of private payloads (amounts, names, user IDs)
 */
export async function executeCredentialLivenessCheck(
  candidate: SecretCandidate,
  deps: { fetchFn?: typeof fetch } = {}
): Promise<CredentialCheckResult> {
  const fetchImpl = deps.fetchFn ?? globalThis.fetch;
  const now = Date.now();

  const target = getLivenessProbeTarget(candidate.provider, candidate.tokenFamily);
  if (!target) {
    return {
      status: 'unsupported',
      provider: candidate.provider,
      tokenFamily: candidate.tokenFamily,
      checkedAt: now,
      details: `Token family "${candidate.tokenFamily}" is not supported for automated provider liveness verification in v1.`,
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => { controller.abort(); }, REQUEST_TIMEOUT_MS);

  try {
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${candidate.rawToken}`,
    };

    if (candidate.provider === 'github') {
      headers['Accept'] = 'application/vnd.github+json';
      headers['X-GitHub-Api-Version'] = GITHUB_PINNED_API_VERSION;
    } else if (candidate.provider === 'slack') {
      headers['Content-Type'] = 'application/json; charset=utf-8';
    }

    const init: RequestInit = {
      method: target.method,
      headers,
      credentials: 'omit',
      redirect: 'manual',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
      ...(target.method === 'POST' ? { body: '{}' } : {}),
    };

    const res = await fetchImpl(target.url, init);

    let classified: { status: CredentialCheckStatus; details: string; livemode?: boolean };

    if (candidate.provider === 'github') {
      classified = classifyGitHubResponse(res.status);
    } else if (candidate.provider === 'stripe') {
      const bodyJson = await readBoundedJson(res);
      classified = classifyStripeResponse(res.status, bodyJson, candidate.tokenFamily);
    } else {
      const bodyJson = await readBoundedJson(res);
      classified = classifySlackResponse(res.status, bodyJson);
    }

    return {
      status: classified.status,
      provider: candidate.provider,
      tokenFamily: candidate.tokenFamily,
      checkedAt: Date.now(),
      details: classified.details,
      ...(classified.livemode !== undefined ? { livemode: classified.livemode } : {}),
    };
  } catch (err) {
    const isAbort = err instanceof Error && err.name === 'AbortError';
    const message = isAbort
      ? 'Request timed out after 5 seconds.'
      : (err instanceof Error ? err.message : 'Unknown network failure');

    return {
      status: 'unknown',
      provider: candidate.provider,
      tokenFamily: candidate.tokenFamily,
      checkedAt: Date.now(),
      details: `Provider check could not be completed: ${message}`,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
