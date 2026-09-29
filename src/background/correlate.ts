/**
 * correlate.ts
 *
 * Bridges Set-Cookie response headers with the live chrome.cookies store to
 * produce typed CookieRecord objects for the rule engine.
 *
 * IMPORTANT: Cookie *values* are never read, stored, or logged anywhere in
 * this file.  Only metadata fields (name, domain, flags, etc.) are accessed.
 */

import type { CookieRecord, Finding } from '../shared/types';
import { registrableDomain } from '../rules/headers/subdomain-trust';
import { sanitizeEvidence } from '../rules/utils';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the cookie name from a raw Set-Cookie header value.
 * The name is everything before the first '=' character.
 * If no '=' is found the entire token is treated as the name.
 */
function parseCookieName(setCookieHeader: string): string {
  const eqIdx = setCookieHeader.indexOf('=');
  if (eqIdx === -1) return setCookieHeader.trim();
  return setCookieHeader.slice(0, eqIdx).trim();
}

function parseCookieHeaderMetadata(setCookieHeader: string): {
  name: string;
  path: string | null;
  domainAttributePresent: boolean;
  domain: string | null;
  sameSiteNone: boolean;
  secure: boolean;
} {
  const parts = setCookieHeader.split(';').map((part) => part.trim());
  const name = parseCookieName(setCookieHeader);
  let path: string | null = null;
  let domainAttributePresent = false;
  let domain: string | null = null;
  let sameSiteNone = false;
  let secure = false;

  for (const attribute of parts.slice(1)) {
    const separator = attribute.indexOf('=');
    const attributeName = (separator === -1 ? attribute : attribute.slice(0, separator))
      .trim()
      .toLowerCase();
    if (attributeName === 'path' && separator !== -1) {
      path = attribute.slice(separator + 1).trim();
    }
    if (attributeName === 'domain') {
      domainAttributePresent = true;
      domain = separator === -1 ? '' : attribute.slice(separator + 1).trim().replace(/^\./, '').toLowerCase();
    }
    if (attributeName === 'samesite' && separator !== -1) {
      sameSiteNone = attribute.slice(separator + 1).trim().toLowerCase() === 'none';
    }
    if (attributeName === 'secure' && separator === -1) secure = true;
  }

  return { name, path, domainAttributePresent, domain, sameSiteNone, secure };
}

export function findUnobservedCookieFindings(
  setCookieHeaders: string[],
  cookies: Array<{ name: string; path: string; domain: string }>,
  tabUrl: string,
): Finding[] {
  const metadata = setCookieHeaders.map(parseCookieHeaderMetadata);
  const url = (() => {
    try {
      return new URL(tabUrl);
    } catch {
      return null;
    }
  })();
  if (url === null) return [];

  const visibleNames = new Set(cookies.map((cookie) => cookie.name));
  return metadata
    .filter((cookie) => cookie.name.length > 0 && !visibleNames.has(cookie.name))
    .flatMap((cookie): Finding[] => {
      const reasons: string[] = [];
      let likelyRejected = false;
      if (cookie.sameSiteNone && !cookie.secure) {
        reasons.push('SameSite=None requires Secure in modern browsers');
        likelyRejected = true;
      }
      if (cookie.domain !== null && cookie.domain.length > 0
        && url.hostname !== cookie.domain && !url.hostname.endsWith(`.${cookie.domain}`)) {
        reasons.push('the Domain attribute does not match the response host');
        likelyRejected = true;
      }
      if (cookie.domainAttributePresent && cookie.domain === '') {
        reasons.push('the Domain attribute is empty or malformed');
        likelyRejected = true;
      }

      const pathDoesNotMatch = cookie.path !== null
        && cookie.path.startsWith('/')
        && !cookiePathMatches(url.pathname, cookie.path);
      if (pathDoesNotMatch) {
        reasons.push(`the cookie Path (${cookie.path}) does not include the current page path`);
        if (!likelyRejected) return [];
      }
      if (reasons.length === 0) {
        reasons.push('browser privacy policy, third-party cookie blocking, expiry, or another cookie validation rule may apply');
      }

      return [{
        ruleId: 'COOKIE-REJECTED',
        category: 'cookie',
        severity: 'info',
        title: `Set-Cookie named "${sanitizeEvidence(cookie.name)}" was not observed in the accessible cookie jar`,
        impact: 'The cookie may not persist in this browser context, which can break a login or other stateful flow.',
        evidence: sanitizeEvidence(`Cookie name: ${cookie.name}; sent attributes: ${[
          cookie.sameSiteNone ? 'SameSite=None' : '',
          cookie.secure ? 'Secure' : '',
          cookie.domainAttributePresent ? 'Domain attribute' : 'host-only',
        ].filter((part) => part.length > 0).join(', ')}`),
        recommendation: `Check whether ${reasons.join('; ')}. A name-only jar comparison cannot prove rejection if a same-name cookie existed before this response.`,
        reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
        sourceUrl: url.href,
      }];
    });
}

function cookiePathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  if (cookiePath.endsWith('/')) return true;
  return requestPath[cookiePath.length] === '/';
}

/**
 * Map Chrome's SameSiteStatus enum to the project's union type.
 *
 * Chrome reports:
 *   'strict'        → 'strict'
 *   'lax'           → 'lax'
 *   'no_restriction'→ 'none'
 *   'unspecified'   → ''
 */
function mapSameSite(
  chromeSameSite: chrome.cookies.SameSiteStatus,
): 'strict' | 'lax' | 'none' | '' {
  switch (chromeSameSite) {
    case 'strict':
      return 'strict';
    case 'lax':
      return 'lax';
    case 'no_restriction':
      return 'none';
    case 'unspecified':
    default:
      return '';
  }
}

/**
 * Determine whether a cookie belongs to a third-party relative to the current
 * page.
 *
 * A cookie is considered first-party when the page's hostname ends with the
 * cookie's domain (accounting for the leading dot that Chrome adds for
 * host-level cookies).
 */
export function isThirdPartyCookie(pageHostname: string, cookieDomain: string): boolean {
  // Strip the leading dot used by Chrome for domain-scoped cookies.
  const normalised = (cookieDomain.startsWith('.')
    ? cookieDomain.slice(1)
    : cookieDomain).toLowerCase();
  const pageDomain = registrableDomain(pageHostname);
  const cookieRegistrableDomain = registrableDomain(normalised);

  if (pageDomain !== null && cookieRegistrableDomain !== null) {
    return pageDomain !== cookieRegistrableDomain;
  }

  // First-party: the page hostname IS the cookie domain, or is a subdomain.
  const normalisedPage = pageHostname.toLowerCase();
  return normalisedPage !== normalised && !normalisedPage.endsWith(`.${normalised}`);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Fetches all cookies accessible for `tabUrl` from the live cookie store and
 * correlates them with the Set-Cookie headers emitted by the most recent
 * response so we can tell whether each cookie was set by the server (via
 * headers) or by JavaScript.
 *
 * Cookie *values* are intentionally never accessed or stored.
 *
 * @param tabId          - The tab being analysed (unused directly but kept for
 *                         potential future use, e.g. per-tab JS-cookie heuristics).
 * @param tabUrl         - The full URL of the page (used to scope the query).
 * @param setCookieHeaders - Raw `Set-Cookie` header strings from the response.
 * @returns              Array of {@link CookieRecord} metadata objects.
 */
export async function correlateCookies(
  _tabId: number,
  tabUrl: string,
  setCookieHeaders: string[],
): Promise<{ records: CookieRecord[]; findings: Finding[] }> {
  // ------------------------------------------------------------------
  // 1. Build a set of names that appeared in Set-Cookie headers.
  //    These were definitively set by the server, not by JavaScript.
  // ------------------------------------------------------------------
  const headerMetadata = setCookieHeaders.map(parseCookieHeaderMetadata);
  const headerSetNames = new Set<string>(headerMetadata.map((item) => item.name));

  // ------------------------------------------------------------------
  // 2. Fetch cookies scoped to this URL from the live store.
  // ------------------------------------------------------------------
  let urlScopedCookies: chrome.cookies.Cookie[];
  try {
    urlScopedCookies = await chrome.cookies.getAll({ url: tabUrl });
  } catch {
    // Permissions not granted or invalid URL — return empty.
    return { records: [], findings: [] };
  }

  // ------------------------------------------------------------------
  // 3. Derive page hostname for third-party detection.
  // ------------------------------------------------------------------
  let pageHostname: string;
  try {
    pageHostname = new URL(tabUrl).hostname;
  } catch {
    pageHostname = '';
  }

  // ------------------------------------------------------------------
  // 4. Map each chrome.cookies.Cookie to a CookieRecord.
  //    We deliberately skip cookie.value everywhere.
  // ------------------------------------------------------------------
  const records: CookieRecord[] = urlScopedCookies.map(
    (cookie: chrome.cookies.Cookie): CookieRecord => {
      // Determine whether this cookie was set via a response header or JS.
      // Absence from this response does not prove JavaScript created the
      // cookie; it may have been set by an earlier server response.
      const setByJs: boolean | null = headerSetNames.has(cookie.name)
        ? false
        : null;
      const matchingHeaders = headerMetadata.filter((item) => item.name === cookie.name);
      const matchingPath = matchingHeaders.find((item) => item.path === cookie.path);
      const headerMatch = matchingPath ?? (matchingHeaders.length === 1 ? matchingHeaders[0] : undefined);

      // Third-party check: does the cookie's domain match the page origin?
      const thirdParty = isThirdPartyCookie(pageHostname, cookie.domain);

      // CHIPS (Partitioned cookies) — Chrome exposes an optional partitionKey
      // property when the cookie was set with the Partitioned attribute.
      // We check for its existence without importing a full type override.
      const partitioned =
        (cookie as chrome.cookies.Cookie & { partitionKey?: unknown })
          .partitionKey != null;

      // Expiry: session cookies have no expiry; persistent cookies expose
      // expirationDate in Unix seconds — we convert to milliseconds.
      const expiresAt: number | null = cookie.session
        ? null
        : Math.round(cookie.expirationDate ?? 0) * 1000;

      return {
        name: cookie.name,
        domain: cookie.domain,
        domainAttributePresent: setByJs === null
          ? null
          : headerMatch?.domainAttributePresent ?? false,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: mapSameSite(cookie.sameSite),
        session: cookie.session,
        expiresAt,
        partitioned,
        setByJs,
        isThirdParty: thirdParty,
        // cookie.value is intentionally NOT accessed here.
      };
    },
  );

  return {
    records,
    findings: findUnobservedCookieFindings(setCookieHeaders, urlScopedCookies, tabUrl),
  };
}
