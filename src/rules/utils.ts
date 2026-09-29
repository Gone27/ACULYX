import { MAX_EVIDENCE_LENGTH } from '../shared/constants';
import type { Finding, Hop } from '../shared/types';

// ─── Evidence sanitisation ────────────────────────────────────────────────────
//
// All header and cookie attribute values are attacker-controlled strings.
// Before they touch any UI or storage, they must be:
//   1. Length-capped (prevents giant values from breaking layout)
//   2. Control-character escaped (prevents terminal injection)
//   3. BiDi-override escaped (prevents visual spoofing of security values)
//
// This function is pure: no browser APIs, fully unit-testable.

const CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
// BiDi override characters that can spoof the visual order of text
const BIDI_OVERRIDE_RE = /[\u200B-\u200D\u202A-\u202E\u2066-\u2069\uFEFF]/g;

/**
 * Sanitise an evidence string for safe storage and display.
 * Uses only textContent-safe characters — no HTML escaping needed,
 * but we still escape the dangerous control/BiDi chars.
 */
export function sanitizeEvidence(raw: string): string {
  let s = raw
    .slice(0, MAX_EVIDENCE_LENGTH)
    .replace(CONTROL_CHAR_RE, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
    .replace(BIDI_OVERRIDE_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

  if (raw.length > MAX_EVIDENCE_LENGTH) {
    s += ` … [${raw.length - MAX_EVIDENCE_LENGTH} chars truncated]`;
  }
  return s;
}

/** Find conflicting repeated values among security-sensitive response headers. */
export function checkDuplicateHeaders(hop: Hop): Finding[] {
  const names = ['strict-transport-security', 'x-frame-options', 'referrer-policy', 'x-content-type-options', 'x-xss-protection'];
  const findings: Finding[] = [];
  for (const name of names) {
    const values = hop.rawHeaders
      .filter((header) => header.name.toLowerCase() === name)
      .map((header) => header.value.trim());
    if (values.length < 2 || new Set(values).size < 2) continue;
    findings.push({
      ruleId: 'DUP-001', category: 'header', severity: 'info',
      title: `Conflicting duplicate ${name} headers`,
      impact: 'Browsers and intermediaries may interpret conflicting repeated policy values differently.',
      evidence: sanitizeEvidence(`${name}: ${values.join(' | ')}`),
      recommendation: 'Configure the server or proxy to emit one authoritative value for this header.',
      reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers',
    });
  }
  return findings;
}

// ─── Header normalisation ─────────────────────────────────────────────────────

/**
 * Build a lowercase-keyed header map from the raw WebRequest header array.
 * For most headers last-value-wins; Set-Cookie is handled separately by the
 * correlate module since it's always multi-valued.
 */
export function normalizeHeaders(
  raw: chrome.webRequest.HttpHeader[]
): Record<string, string> {
  const map: Record<string, string> = {};
  for (const { name, value } of raw) {
    if (value != null) {
      map[name.toLowerCase()] = value;
    }
  }
  return map;
}

/**
 * Collect every Set-Cookie header value as a raw string array.
 * The webRequest API may present them as a single joined header or
 * as multiple entries depending on Chrome version.
 */
export function extractSetCookieHeaders(
  raw: chrome.webRequest.HttpHeader[]
): string[] {
  return raw
    .filter((h) => h.name.toLowerCase() === 'set-cookie' && h.value != null)
    .map((h) => h.value as string);
}

// ─── Two-capture-point diff ───────────────────────────────────────────────────

/**
 * Compare two header maps and return true if they differ in any key or value.
 * Used to detect modifications made by other extensions between
 * onHeadersReceived and onResponseStarted.
 */
export function headersDiffer(
  a: Record<string, string>,
  b: Record<string, string>
): boolean {
  const keysA = Object.keys(a).sort();
  const keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return true;
  for (let i = 0; i < keysA.length; i++) {
    const k = keysA[i] as string;
    if (k !== (keysB[i] as string)) return true;
    if (a[k] !== b[k]) return true;
  }
  return false;
}

// ─── CSP directive helpers ────────────────────────────────────────────────────

/**
 * Parse a raw CSP string into a directive map.
 * Keys are directive names (lowercase), values are the raw source-list string.
 * This is a best-effort linear-time parser — not a full evaluator.
 * For thorough analysis, use csp-evaluator on top of this.
 */
export function parseCspDirectives(csp: string): Map<string, string> {
  const directives = new Map<string, string>();
  // Split on ; but handle edge cases with trailing whitespace
  for (const part of csp.split(';')) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx === -1) {
      directives.set(trimmed.toLowerCase(), '');
    } else {
      const name = trimmed.slice(0, spaceIdx).toLowerCase();
      const value = trimmed.slice(spaceIdx + 1).trim();
      directives.set(name, value);
    }
  }
  return directives;
}

// ─── Origin helpers ───────────────────────────────────────────────────────────

/** Extract the scheme+host+port origin from a URL string, or null on failure. */
export function originFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    return u.origin === 'null' ? null : u.origin;
  } catch {
    return null;
  }
}

// ─── Sensitive Cookie Heuristics ──────────────────────────────────────────────

const SENSITIVE_COOKIE_RE =
  /(^|[-_])(session|sess|auth|token|jwt|sid|login|sso|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|credential|secret|password|access[-_]?token|id[-_]?token)([-_]|$)/i;

const NON_SENSITIVE_COOKIE_RE =
  /(^|[-_])(ga|gid|gat|gcl|fbp|fbc|theme|dark|light|lang|locale|country|currency|timezone|tz|sidebar|banner|notice|consent|cookie_consent|optout|optimizely|amplitude|intercom|csrf|xsrf|csrftoken)([-_]|$)/i;

/**
 * Returns true when a cookie's name indicates it is likely an authentication,
 * session, or authorization token that requires strict security flags (HttpOnly, Secure).
 *
 * Harmless client-side cookies (analytics, UI preferences, language, CSRF tokens that
 * need JS reading in double-submit patterns) return false.
 */
export function isSensitiveCookie(
  name: string,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): { isSensitive: boolean; reason: 'override' | 'prefix' | 'regex' } {
  // Cookie names are case-sensitive.
  if (alwaysIgnore.includes(name)) return { isSensitive: false, reason: 'override' };
  if (alwaysSensitive.includes(name)) return { isSensitive: true, reason: 'override' };

  if (name.startsWith('__Host-') || name.startsWith('__Secure-')) return { isSensitive: true, reason: 'prefix' };
  if (NON_SENSITIVE_COOKIE_RE.test(name)) return { isSensitive: false, reason: 'regex' };
  return { isSensitive: SENSITIVE_COOKIE_RE.test(name), reason: 'regex' };
}

// ─── Modern CSP Protection Checks ─────────────────────────────────────────────

const NONCE_RE = /'nonce-[A-Za-z0-9+/=_-]+'/i;
const HASH_RE = /'sha(256|384|512)-[A-Za-z0-9+/=_-]+'/i;

/**
 * Checks whether a script-src source-list employs modern CSP Level 3 safeguards
 * (nonces, hashes, or 'strict-dynamic').
 *
 * In CSP Level 3:
 *  - If 'nonce-...' or 'sha...' is present, browsers ignore 'unsafe-inline'.
 *  - If 'strict-dynamic' is present, browsers ignore 'unsafe-inline' and host sources (e.g. https:).
 */
export function hasCspBypassProtection(sourceList: string): {
  hasNonce: boolean;
  hasHash: boolean;
  hasStrictDynamic: boolean;
  isModernStrict: boolean;
} {
  const hasNonce = NONCE_RE.test(sourceList);
  const hasHash = HASH_RE.test(sourceList);
  const hasStrictDynamic = sourceList.includes("'strict-dynamic'");
  const isModernStrict = hasNonce || hasHash || hasStrictDynamic;
  return { hasNonce, hasHash, hasStrictDynamic, isModernStrict };
}

