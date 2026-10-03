/**
 * auth-diff.ts
 *
 * Implements pre-login vs. post-login security posture diffing.
 * Detects transition when a sensitive session/auth cookie appears, rotates, or changes on an origin/tab,
 * and snapshots the delta between findings, scores, and grades.
 */

import type {
  CookieRecord,
  Finding,
  Grade,
  AuthDiffRecord,
  AuthDiffFindingChange,
  AuthBaseline,
  CompactFinding,
} from '../shared/types';
import { isSensitiveCookie } from './utils';

export type { AuthBaseline, CompactFinding };

export function toCompactFinding(f: Finding | CompactFinding): CompactFinding {
  return {
    ruleId: f.ruleId,
    severity: f.severity,
    title: f.title,
  };
}

/**
 * Checks if a cookie list contains an authentication or session token.
 * Requires both a sensitive naming pattern and either the session or httpOnly flag
 * to prevent false positives from client-side consent or tracking cookies.
 */
export function detectSensitiveAuthCookie(
  cookies: CookieRecord[],
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): CookieRecord | null {
  for (const c of cookies) {
    const { isSensitive } = isSensitiveCookie(c.name, alwaysSensitive, alwaysIgnore);
    if (isSensitive && (c.session || c.httpOnly)) {
      return c;
    }
  }
  return null;
}

/**
 * Returns all sensitive authentication/session cookies in the list.
 */
export function getSensitiveAuthCookies(
  cookies: CookieRecord[],
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): CookieRecord[] {
  return cookies.filter((c) => {
    const { isSensitive } = isSensitiveCookie(c.name, alwaysSensitive, alwaysIgnore);
    return isSensitive && (c.session || c.httpOnly);
  });
}

/**
 * Computes a deterministic signature of sensitive cookie metadata (names, flags, expiry).
 * Allows detecting token rotation, flag upgrades/downgrades, or new tokens even when
 * a session cookie was already present.
 */
export function computeSensitiveCookiesSignature(
  cookies: CookieRecord[],
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): string {
  const sensitiveCookies = getSensitiveAuthCookies(cookies, alwaysSensitive, alwaysIgnore);
  return sensitiveCookies
    .map((c) => `${c.name}|${c.httpOnly}|${c.secure}|${c.sameSite}|${c.partitioned}|${c.expiresAt ?? 'session'}`)
    .sort()
    .join(';;');
}

/**
 * Computes which findings were added, removed, or modified between pre-auth and post-auth states.
 */
export function computeFindingChanges(
  pre: (Finding | CompactFinding)[],
  post: (Finding | CompactFinding)[]
): AuthDiffFindingChange[] {
  const preMap = new Map(pre.map((f) => [f.ruleId, f]));
  const postMap = new Map(post.map((f) => [f.ruleId, f]));
  const changes: AuthDiffFindingChange[] = [];

  // Findings introduced or modified post-login
  for (const [ruleId, postFinding] of postMap.entries()) {
    const preFinding = preMap.get(ruleId);
    if (!preFinding) {
      changes.push({
        ruleId,
        title: postFinding.title,
        severity: postFinding.severity,
        type: 'added',
      });
    } else if (preFinding.severity !== postFinding.severity || preFinding.title !== postFinding.title) {
      changes.push({
        ruleId,
        title: postFinding.title,
        severity: postFinding.severity,
        type: 'modified',
        oldSeverity: preFinding.severity,
      });
    }
  }

  // Findings resolved post-login
  for (const [ruleId, preFinding] of preMap.entries()) {
    if (!postMap.has(ruleId)) {
      changes.push({
        ruleId,
        title: preFinding.title,
        severity: preFinding.severity,
        type: 'removed',
      });
    }
  }

  return changes;
}

export interface AuthTransitionContext {
  tabId?: number;
  url?: string;
  hasNonGetSetCookie?: boolean;
}

/**
 * Evaluates whether an origin/tab transition represents a login event.
 * Detects:
 * 1. Transition from pre-auth (no sensitive session cookie) to post-auth (sensitive session cookie).
 * 2. Sensitive cookie reissued via Set-Cookie on main-frame hop after non-GET request.
 * 3. Sensitive cookie rotation or flag/expiry changes when already in session.
 */
export function checkAuthTransition(
  origin: string,
  baseline: AuthBaseline | undefined,
  currentCookies: CookieRecord[],
  currentFindings: (Finding | CompactFinding)[],
  currentScore: number,
  currentGrade: Grade,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = [],
  context?: AuthTransitionContext,
): { isAuthEvent: boolean; record: AuthDiffRecord | null; newBaseline: AuthBaseline } {
  const authCookie = detectSensitiveAuthCookie(currentCookies, alwaysSensitive, alwaysIgnore);
  const hasAuthNow = authCookie !== null;
  const currentSig = computeSensitiveCookiesSignature(currentCookies, alwaysSensitive, alwaysIgnore);
  const compactCurrentFindings = currentFindings.map(toCompactFinding);

  const currentBaseline: AuthBaseline = {
    origin,
    tabId: context?.tabId ?? baseline?.tabId,
    url: context?.url ?? baseline?.url,
    cookies: currentCookies,
    findings: compactCurrentFindings,
    score: currentScore,
    grade: currentGrade,
    timestamp: Date.now(),
    hasSensitiveCookie: hasAuthNow,
    sensitiveCookieSignature: currentSig,
  };

  // If there was no previous baseline, establish this state as the initial baseline.
  if (!baseline) {
    return { isAuthEvent: false, record: null, newBaseline: currentBaseline };
  }

  let isAuthEvent = false;
  let triggerReason: string | undefined;

  // Case 1: Transition from pre-auth to post-auth
  if (!baseline.hasSensitiveCookie && hasAuthNow) {
    isAuthEvent = true;
    triggerReason = 'new_session_cookie';
  } else if (baseline.hasSensitiveCookie && hasAuthNow) {
    // Case 2: Post-login re-authentication via non-GET Set-Cookie (e.g. POST form submission login)
    if (context?.hasNonGetSetCookie === true) {
      isAuthEvent = true;
      triggerReason = 'post_request_session_cookie_issued';
    } else if (
      baseline.sensitiveCookieSignature !== undefined &&
      currentSig !== '' &&
      baseline.sensitiveCookieSignature !== currentSig
    ) {
      // Case 3: Sensitive cookie name, expiry or flags rotated/changed
      isAuthEvent = true;
      triggerReason = 'session_cookie_rotated_or_modified';
    }
  }

  if (isAuthEvent && authCookie !== null) {
    const preScore = baseline.score;
    const postScore = currentScore;
    const scoreDelta = postScore - preScore;
    const changes = computeFindingChanges(baseline.findings, compactCurrentFindings);

    const record: AuthDiffRecord = {
      origin,
      tabId: context?.tabId ?? baseline.tabId,
      timestamp: Date.now(),
      triggeredByCookie: authCookie.name,
      triggerReason,
      preAuthScore: preScore,
      postAuthScore: postScore,
      scoreDelta,
      preAuthGrade: baseline.grade,
      postAuthGrade: currentGrade,
      preAuthUrl: baseline.url,
      postAuthUrl: context?.url,
      scope: 'page',
      preAuthFindings: baseline.findings.map(toCompactFinding),
      postAuthFindings: compactCurrentFindings,
      changes,
    };

    return { isAuthEvent: true, record, newBaseline: currentBaseline };
  }

  // If user logged out (had auth cookie, now does not), reset baseline to pre-auth.
  if (baseline.hasSensitiveCookie && !hasAuthNow) {
    return { isAuthEvent: false, record: null, newBaseline: currentBaseline };
  }

  // In all other cases (e.g. repeated hops while logged in, or repeated hops while logged out),
  // update the existing baseline findings/score if still in the same auth state without triggering a diff.
  return {
    isAuthEvent: false,
    record: null,
    newBaseline: {
      ...baseline,
      tabId: context?.tabId ?? baseline.tabId,
      url: context?.url ?? baseline.url,
      cookies: currentCookies,
      findings: compactCurrentFindings,
      score: currentScore,
      grade: currentGrade,
      timestamp: Date.now(),
      sensitiveCookieSignature: currentSig,
    },
  };
}
