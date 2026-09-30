import type { Grade, Settings, Severity } from './types';

// ─── Versioning ───────────────────────────────────────────────────────────────

/** Bump when either score model changes so persisted history remains comparable. */
export const SCORE_VERSION = '1.7.0';

// ─── Restricted schemes ───────────────────────────────────────────────────────

/** URL schemes the extension cannot inspect. Show explicit "restricted" state. */
export const RESTRICTED_SCHEMES: readonly string[] = [
  'chrome://',
  'chrome-extension://',
  'devtools://',
  'about:',
  'data:',
  'blob:',
];

// ─── Badge ────────────────────────────────────────────────────────────────────

export const BADGE_COLORS: Record<Grade | '?', string> = {
  A: '#27ae60',
  B: '#2980b9',
  C: '#f39c12',
  D: '#e67e22',
  F: '#c0392b',
  '?': '#7f8c8d',
};

// ─── Severity ─────────────────────────────────────────────────────────────────

export const SEVERITY_ORDER: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
  'pass',
];

// ─── Grade thresholds (inclusive lower bound) ─────────────────────────────────

export const GRADE_THRESHOLDS: Array<{ min: number; grade: Grade }> = [
  { min: 90, grade: 'A' },
  { min: 70, grade: 'B' },
  { min: 50, grade: 'C' },
  { min: 30, grade: 'D' },
  { min: 0,  grade: 'F' },
];

// ─── Evidence safety ─────────────────────────────────────────────────────────

/** Maximum characters in any evidence string before truncation. */
export const MAX_EVIDENCE_LENGTH = 500;

// ─── HSTS ─────────────────────────────────────────────────────────────────────

/** Minimum recommended HSTS max-age in seconds (1 year). */
export const HSTS_MIN_MAX_AGE = 31_536_000;

// ─── Storage keys ─────────────────────────────────────────────────────────────

export const STORAGE_KEYS = {
  SETTINGS: 'settings',
  TAB_PREFIX: 'tab:',
  HISTORY_PREFIX: 'hist:',
  AUTH_DIFF_PREFIX: 'authdiff:',
  GRAPH_PREFIX: 'graph:',
  ONBOARDING_DISMISSED: 'onboarding_dismissed',
} as const;

// ─── Port / messaging ─────────────────────────────────────────────────────────

/** Runtime port name for popup ↔ service worker connection. */
export const POPUP_PORT_NAME = 'popup';

/**
 * Runtime port name for side panel ↔ service worker connection.
 * Channel is registered now; the panel UI ships in Phase 3.
 */
export const SIDEPANEL_PORT_NAME = 'sidepanel';

// ─── MV3 service worker keepalive ─────────────────────────────────────────────

export const KEEPALIVE_ALARM = 'keepalive';
/** Period in minutes — must stay under the ~30 s Chrome idle threshold. */
export const KEEPALIVE_PERIOD_MINUTES = 0.4;

// ─── Default settings ─────────────────────────────────────────────────────────

export const DEFAULT_SETTINGS: Settings = {
  monitoringMode: 'per-site',
  allowedOrigins: [],
  severityFilter: ['critical', 'high', 'medium', 'low', 'info'],
  retainHistoryDays: 7,
  alwaysSensitiveCookies: [],
  alwaysIgnoreCookies: [],
  isPro: false,
};

