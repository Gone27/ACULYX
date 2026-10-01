/**
 * filters.ts
 *
 * Presentation-only selectors and view filtering helpers.
 *
 * Invariant: Filter operations NEVER alter computed scores, grades,
 * or breakdown penalty points. They only control what is rendered in the UI.
 */

import type { Finding, Severity } from './types';

export interface VisibleFindingsResult {
  visibleFindings: Finding[];
  hiddenCount: number;
}

/**
 * Pure presentation selector to filter findings by allowed severity levels.
 *
 * @param findings - Full list of findings computed by the rules engine
 * @param severityFilter - Severities allowed for display (from user settings)
 * @param showAllOverride - Whether the user has temporarily opted to show all findings
 */
export function selectVisibleFindings(
  findings: readonly Finding[],
  severityFilter: readonly Severity[],
  showAllOverride: boolean = false,
): VisibleFindingsResult {
  if (showAllOverride || severityFilter.length === 0) {
    return {
      visibleFindings: [...findings],
      hiddenCount: 0,
    };
  }

  const allowed = new Set<Severity>(severityFilter);
  const visibleFindings: Finding[] = [];
  let hiddenCount = 0;

  for (const finding of findings) {
    if (allowed.has(finding.severity)) {
      visibleFindings.push(finding);
    } else {
      hiddenCount++;
    }
  }

  return { visibleFindings, hiddenCount };
}
