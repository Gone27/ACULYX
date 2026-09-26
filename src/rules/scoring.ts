/**
 * Scoring module.
 *
 * Converts a flat list of findings into a numeric score (0–100), a letter
 * grade (A–F), and a per-rule breakdown suitable for display in the popup.
 *
 * Penalties are read from weights.json so they can be updated without
 * touching any TypeScript source.
 */

import type { Finding, Grade, ScoreBreakdown } from '../shared/types';
import { GRADE_THRESHOLDS, SCORE_VERSION } from '../shared/constants';
import weights from './weights.json';

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/**
 * Shape of the weights.json file as imported via resolveJsonModule.
 * We keep this local so the shared types package stays free of build-tool
 * assumptions.
 */
interface WeightsFile {
  version: string;
  rules: Record<string, { penalty: number }>;
}

// Cast the imported JSON to the typed shape.
const WEIGHTS = weights as WeightsFile;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ScoreResult {
  score: number;
  grade: Grade;
  breakdown: ScoreBreakdown[];
  scoreVersion: string;
}

// Category caps prevent any single weak category (e.g. cookies) from completely destroying a score.
const CATEGORY_CAPS: Record<string, number> = {
  cookie: 25,     // A site can never lose more than 25 points solely from cookie issues
  transport: 25,  // Transport issues (HSTS, etc.) capped at 25 points
  header: 55,     // Header issues capped at 55 points
  cors: 20,       // CORS issues capped at 20 points
};

/**
 * Compute a 0–100 security score from a list of findings.
 *
 * Improvements:
 *  - Findings with severity 'pass' or 'info' do not affect the score.
 *  - Deduplicates by ruleId: multiple occurrences of the same rule (e.g. 10 cookies)
 *    do not stack multiplicatively (prevents score crash on normal multi-cookie sites).
 *  - Enforces category caps so one category doesn't push a site to an F grade.
 *  - Accounts for `fromCache`: missing-header penalties on cached responses are discounted
 *    since browser caches often omit response headers.
 *
 * @param findings - All findings produced by the rule engine.
 * @param fromCache - Whether the response was served from cache (unverified headers).
 * @returns Score result including numeric score, grade, per-rule breakdown,
 *          and the version string of the scoring algorithm.
 */
export function computeScore(findings: Finding[], fromCache = false): ScoreResult {
  let score = 100;
  const breakdown: ScoreBreakdown[] = [];

  // Group non-pass/info findings by ruleId to prevent runaway stacking
  const findingsByRule = new Map<string, Finding[]>();

  for (const finding of findings) {
    // Info and pass severities are informational only — they do not penalise.
    if (finding.severity === 'pass' || finding.severity === 'info') {
      continue;
    }
    const list = findingsByRule.get(finding.ruleId) ?? [];
    list.push(finding);
    findingsByRule.set(finding.ruleId, list);
  }

  // Track applied deductions by category to enforce category caps
  const deductionsByCategory = new Map<string, number>();

  for (const [ruleId, ruleFindings] of findingsByRule.entries()) {
    const first = ruleFindings[0];
    if (!first) continue;

    const weightConfig = WEIGHTS.rules[ruleId];
    let basePenalty = weightConfig?.penalty ?? 0;

    // Cache-discount: missing headers on a cached response are unverified
    if (fromCache && (ruleId.startsWith('CSP-001') || ruleId.startsWith('HSTS-001') || ruleId.startsWith('XFO-001') || ruleId.startsWith('CACHE-001'))) {
      basePenalty = Math.round(basePenalty * 0.5);
    }

    // Multiple occurrences (e.g. multiple cookies) scale minimally rather than N*penalty
    let appliedPenalty = basePenalty;
    if (ruleFindings.length > 1 && basePenalty > 0) {
      appliedPenalty = Math.min(Math.round(basePenalty * 1.25), basePenalty + 5);
    }

    const category = first.category ?? 'header';
    const currentCatDeduction = deductionsByCategory.get(category) ?? 0;
    const catCap = CATEGORY_CAPS[category] ?? 100;

    // Enforce category ceiling
    const allowableDeduction = Math.max(0, Math.min(appliedPenalty, catCap - currentCatDeduction));
    deductionsByCategory.set(category, currentCatDeduction + allowableDeduction);

    score -= allowableDeduction;

    const countSuffix = ruleFindings.length > 1 ? ` (${ruleFindings.length} items affected)` : '';
    const cacheSuffix = fromCache && basePenalty !== (weightConfig?.penalty ?? 0) ? ' [cached — unverified]' : '';

    breakdown.push({
      ruleId,
      title: `${first.title}${countSuffix}${cacheSuffix}`,
      severity: first.severity,
      weight: weightConfig?.penalty ?? 0,
      penalty: allowableDeduction,
    });
  }

  // Clamp score to valid range.
  const clampedScore = Math.max(0, Math.min(100, score));

  // Map to grade using thresholds (first entry where score >= min wins).
  const gradeEntry = GRADE_THRESHOLDS.find(
    (entry) => clampedScore >= entry.min,
  );
  const grade: Grade = gradeEntry?.grade ?? 'F';

  return {
    score: clampedScore,
    grade,
    breakdown,
    scoreVersion: SCORE_VERSION,
  };
}

