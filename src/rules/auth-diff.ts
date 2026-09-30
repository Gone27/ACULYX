/**
 * auth-diff.ts
 *
 * Implements pre-login vs. post-login security posture diffing.
 * Detects transition when a sensitive session/auth cookie appears on an origin
 * where previous requests had no active session, and snapshots the delta between
 * findings, scores, and grades.
 */

import type {
  CookieRecord,
  Finding,
  Grade,
  AuthDiffRecord,
  AuthDiffFindingChange,
  AuthBaseline,
} from '../shared/types';
import { isSensitiveCookie } from './utils';

export type { AuthBaseline };

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
 * Computes which findings were added or removed between pre-auth and post-auth states.
 */
export function computeFindingChanges(pre: Finding[], post: Finding[]): AuthDiffFindingChange[] {
  const preMap = new Map(pre.map((f) => [f.ruleId, f]));
  const postMap = new Map(post.map((f) => [f.ruleId, f]));
  const changes: AuthDiffFindingChange[] = [];

  // Findings introduced post-login (e.g. looser cookie flags or missing headers on authenticated view)
  for (const [ruleId, postFinding] of postMap.entries()) {
    if (!preMap.has(ruleId)) {
      changes.push({
        ruleId,
        title: postFinding.title,
        severity: postFinding.severity,
        type: 'added',
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

/**
 * Evaluates whether an origin transition represents a login event.
 * If transitioning from pre-auth (no sensitive session cookie) to post-auth (sensitive session cookie),
 * emits an AuthDiffRecord and updates the baseline.
 */
export function checkAuthTransition(
  origin: string,
  baseline: AuthBaseline | undefined,
  currentCookies: CookieRecord[],
  currentFindings: Finding[],
  currentScore: number,
  currentGrade: Grade,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): { isAuthEvent: boolean; record: AuthDiffRecord | null; newBaseline: AuthBaseline } {
  const authCookie = detectSensitiveAuthCookie(currentCookies, alwaysSensitive, alwaysIgnore);
  const hasAuthNow = authCookie !== null;

  const currentBaseline: AuthBaseline = {
    origin,
    cookies: currentCookies,
    findings: currentFindings,
    score: currentScore,
    grade: currentGrade,
    timestamp: Date.now(),
    hasSensitiveCookie: hasAuthNow,
  };

  // If there was no previous baseline, establish this state as the initial baseline.
  if (!baseline) {
    return { isAuthEvent: false, record: null, newBaseline: currentBaseline };
  }

  // Transition from pre-auth to post-auth detected:
  if (!baseline.hasSensitiveCookie && hasAuthNow) {
    const preScore = baseline.score;
    const postScore = currentScore;
    const scoreDelta = postScore - preScore;
    const changes = computeFindingChanges(baseline.findings, currentFindings);

    const record: AuthDiffRecord = {
      origin,
      timestamp: Date.now(),
      triggeredByCookie: authCookie.name,
      preAuthScore: preScore,
      postAuthScore: postScore,
      scoreDelta,
      preAuthGrade: baseline.grade,
      postAuthGrade: currentGrade,
      preAuthFindings: baseline.findings,
      postAuthFindings: currentFindings,
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
      cookies: currentCookies,
      findings: currentFindings,
      score: currentScore,
      grade: currentGrade,
      timestamp: Date.now(),
    },
  };
}
