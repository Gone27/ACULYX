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
  sameSite: 'strict' | 'lax' | 'none' | '';
  secure: boolean;
  httpOnly: boolean;
  partitioned: boolean;
  session: boolean;
  expiresAt: number | null;
  isDeletion: boolean;
} {
  const parts = setCookieHeader.split(';').map((part) => part.trim());
  const name = parseCookieName(setCookieHeader);
  let path: string | null = null;
  let domainAttributePresent = false;
  let domain: string | null = null;
  let sameSiteNone = false;
  let sameSite: 'strict' | 'lax' | 'none' | '' = '';
  let secure = false;
  let httpOnly = false;
  let partitioned = false;
  let isDeletion = false;
  let expiresAt: number | null = null;
  let hasMaxAgeOrExpires = false;

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
      const val = attribute.slice(separator + 1).trim().toLowerCase();
      if (val === 'none') {
        sameSiteNone = true;
        sameSite = 'none';
      } else if (val === 'lax') {
        sameSite = 'lax';
      } else if (val === 'strict') {
        sameSite = 'strict';
      }
    }
    if (attributeName === 'secure' && separator === -1) secure = true;
    if (attributeName === 'httponly' && separator === -1) httpOnly = true;
    if (attributeName === 'partitioned' && separator === -1) partitioned = true;
    if (attributeName === 'max-age' && separator !== -1) {
      hasMaxAgeOrExpires = true;
      const maxAge = parseInt(attribute.slice(separator + 1).trim(), 10);
      if (!isNaN(maxAge)) {
        if (maxAge <= 0) {
          isDeletion = true;
        } else {
          expiresAt = Date.now() + maxAge * 1000;
        }
      }
    }
    if (attributeName === 'expires' && separator !== -1) {
      hasMaxAgeOrExpires = true;
      const expTime = Date.parse(attribute.slice(separator + 1).trim());
      if (!isNaN(expTime)) {
        if (expTime <= Date.now()) {
          isDeletion = true;
        } else if (expiresAt === null) {
          expiresAt = expTime;
        }
      }
    }
  }

  const session = !hasMaxAgeOrExpires;
  return {
    name,
    path,
    domainAttributePresent,
    domain,
    sameSiteNone,
    sameSite,
    secure,
    httpOnly,
    partitioned,
    session,
    expiresAt,
    isDeletion,
  };
}

export const MAX_SET_COOKIES = 100;
export const MAX_COOKIE_RECORDS = 100;
export const MAX_UNOBSERVED_FINDINGS = 50;
export const COOKIE_SETTLE_DELAY_MS = 120;

interface ParsedCookieMeta {
  name: string;
  path: string | null;
  domainAttributePresent: boolean;
  domain: string | null;
  sameSiteNone: boolean;
  sameSite: 'strict' | 'lax' | 'none' | '';
  secure: boolean;
  httpOnly: boolean;
  partitioned: boolean;
  session: boolean;
  expiresAt: number | null;
  isDeletion: boolean;
}

function isCookiePresentInJar(
  cookieMeta: ParsedCookieMeta,
  cookies: Array<{ name: string; path: string; domain: string }>,
  responseUrl: URL,
): boolean {
  const candidates = cookies.filter((c) => c.name === cookieMeta.name);
  if (candidates.length === 0) return false;

  const expectedDomain = (cookieMeta.domain !== null && cookieMeta.domain.length > 0
    ? cookieMeta.domain
    : responseUrl.hostname).toLowerCase();

  return candidates.some((jarCookie) => {
    const jarHost = (jarCookie.domain || '').replace(/^\./, '').toLowerCase();
    const domainMatches = jarHost.length === 0 ||
      jarHost === expectedDomain ||
      (cookieMeta.domainAttributePresent && (expectedDomain.endsWith(`.${jarHost}`) || jarHost.endsWith(`.${expectedDomain}`)));

    if (!domainMatches) return false;

    const jarPath = jarCookie.path && jarCookie.path.length > 0 ? jarCookie.path : '/';
    if (cookieMeta.path !== null && cookieMeta.path.startsWith('/')) {
      return jarPath === cookieMeta.path || cookiePathMatches(cookieMeta.path, jarPath);
    }
    return cookiePathMatches(responseUrl.pathname, jarPath);
  });
}

export function findUnobservedCookieFindings(
  setCookieHeaders: string[],
  cookies: Array<{ name: string; path: string; domain: string }>,
  tabUrl: string,
  hopUrl?: string,
  inaccessibleParentDomains?: ReadonlySet<string>,
): Finding[] {
  const boundedSetCookies = setCookieHeaders.slice(0, MAX_SET_COOKIES);
  const metadata = boundedSetCookies.map(parseCookieHeaderMetadata);
  const pageUrl = (() => {
    try {
      return new URL(tabUrl);
    } catch {
      return null;
    }
  })();
  if (pageUrl === null) return [];

  const responseUrl = (() => {
    if (hopUrl !== undefined && hopUrl.length > 0) {
      try {
        return new URL(hopUrl);
      } catch {
        // Fall back to pageUrl
      }
    }
    return pageUrl;
  })();

  const pageHostname = pageUrl.hostname;
  const responseHostname = responseUrl.hostname;

  const findings = metadata
    .filter((cookie) => cookie.name.length > 0 && !cookie.isDeletion && !isCookiePresentInJar(cookie, cookies, responseUrl))
    .flatMap((cookie): Finding[] => {
      const effectiveDomain = (cookie.domain !== null && cookie.domain.length > 0)
        ? cookie.domain
        : responseHostname;
      const isThirdParty = isThirdPartyCookie(pageHostname, effectiveDomain);

      // If this cookie was set by a third-party host and its Domain attribute applies to that host,
      // it is naturally not in the URL-scoped jar of the top-level page, so do not falsely report as rejected.
      const domainMatchesResponseHost = cookie.domain === null || cookie.domain === '' ||
        responseHostname === cookie.domain || responseHostname.endsWith(`.${cookie.domain}`);
      if (isThirdParty && domainMatchesResponseHost && responseHostname !== pageHostname) {
        return [];
      }

      const reasons: string[] = [];
      let likelyRejected = false;
      if (cookie.sameSiteNone && !cookie.secure) {
        reasons.push('SameSite=None requires Secure in modern browsers');
        likelyRejected = true;
      }
      if (cookie.domain !== null && cookie.domain.length > 0
        && responseHostname !== cookie.domain && !responseHostname.endsWith(`.${cookie.domain}`)) {
        reasons.push('the Domain attribute does not match the response host');
        likelyRejected = true;
      }
      if (cookie.domainAttributePresent && cookie.domain === '') {
        reasons.push('the Domain attribute is empty or malformed');
        likelyRejected = true;
      }

      const pathDoesNotMatch = cookie.path !== null
        && cookie.path.startsWith('/')
        && !cookiePathMatches(responseUrl.pathname, cookie.path);
      if (pathDoesNotMatch) {
        reasons.push(`the cookie Path (${cookie.path}) does not include the current page path`);
        if (!likelyRejected) return [];
      }

      // Chrome's cookies.getAll({ url: 'https://www.example.com/' }) withholds parent-domain
      // cookies (e.g. Domain=.example.com) unless the extension also holds permission for
      // example.com/*. When no protocol rejection attribute is violated, do not report permission-
      // withheld parent-domain cookies as browser-rejected.
      if (!likelyRejected && cookie.domain !== null && cookie.domain.length > 0) {
        const domainLower = cookie.domain.toLowerCase();
        if (
          inaccessibleParentDomains !== undefined &&
          inaccessibleParentDomains.has(domainLower) &&
          domainMatchesResponseHost &&
          responseHostname.toLowerCase() !== domainLower
        ) {
          return [];
        }
      }

      if (reasons.length === 0) {
        reasons.push('browser privacy policy, third-party cookie blocking, expiry, or asynchronous cookie-store commit timing may apply');
      }

      return [{
        ruleId: 'COOKIE-REJECTED',
        category: 'cookie',
        severity: 'info',
        title: `Set-Cookie "${sanitizeEvidence(cookie.name)}" was not observed in the accessible cookie jar after bounded verification`,
        impact: 'The cookie was absent from the accessible browser cookie jar during initial and bounded follow-up checks; it may have been rejected, scoped elsewhere, or committed asynchronously.',
        evidence: sanitizeEvidence(`Cookie name: ${cookie.name}; sent attributes: ${[
          cookie.sameSiteNone ? 'SameSite=None' : '',
          cookie.secure ? 'Secure' : '',
          cookie.domainAttributePresent ? 'Domain attribute' : 'host-only',
        ].filter((part) => part.length > 0).join(', ')}`),
        recommendation: `Check whether ${reasons.join('; ')}. Bounded cookie-jar polling cannot distinguish silent browser rejection from delayed storage outside the check window.`,
        reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
        sourceUrl: responseUrl.href,
      }];
    });

  return findings.slice(0, MAX_UNOBSERVED_FINDINGS);
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

// ---------------------------------------------------------------------------
// In-flight correlation deduplication map
// ---------------------------------------------------------------------------

const inFlightCorrelations = new Map<
  string,
  Promise<{ records: CookieRecord[]; findings: Finding[]; discarded?: boolean }>
>();
const MAX_IN_FLIGHT_CORRELATIONS = 50;
const rememberedCookieSetters = new Map<string, string>();
const MAX_REMEMBERED_SETTERS = 500;

function sanitizeSetterUrl(rawUrl?: string): string | undefined {
  if (rawUrl === undefined || rawUrl.length === 0) return undefined;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return undefined;
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return undefined;
  }
}

function cookieSetterKey(domain: string, cookiePath: string, name: string): string {
  const normDomain = domain.replace(/^\./, '').toLowerCase();
  const normPath = cookiePath.length > 0 ? cookiePath : '/';
  return `${normDomain}|${normPath}|${name}`;
}

function rememberCookieSetter(domain: string, cookiePath: string, name: string, setterUrl: string): void {
  const key = cookieSetterKey(domain, cookiePath, name);
  if (rememberedCookieSetters.has(key)) {
    rememberedCookieSetters.delete(key);
  } else if (rememberedCookieSetters.size >= MAX_REMEMBERED_SETTERS) {
    const oldestKey = rememberedCookieSetters.keys().next().value;
    if (oldestKey !== undefined) rememberedCookieSetters.delete(oldestKey);
  }
  rememberedCookieSetters.set(key, setterUrl);
}

/**
 * Fetches all cookies accessible for `tabUrl` from the live cookie store and
 * correlates them with the Set-Cookie headers emitted by the most recent
 * response so we can tell whether each cookie was set by the server (via
 * headers) or by JavaScript.
 *
 * Generation-aware: discards late arrivals if the tab's navigation generation
 * has advanced before or during the live store query.
 *
 * Cookie *values* are intentionally never accessed or stored.
 *
 * @param tabId               - The tab being analysed.
 * @param tabUrl              - The full URL of the page (used to scope the query).
 * @param setCookieHeaders    - Raw `Set-Cookie` header strings from the response.
 * @param generation          - Optional navigation generation counter.
 * @param isCurrentGeneration - Optional callback verifying whether generation is still current.
 * @returns                   Array of {@link CookieRecord} metadata objects and findings.
 */
async function checkOriginPermission(originPattern: string): Promise<boolean> {
  if (typeof chrome === 'undefined') return true;
  const permsApi = (chrome as { permissions?: typeof chrome.permissions }).permissions;
  if (permsApi === undefined || typeof permsApi.contains !== 'function') {
    return true;
  }
  return await new Promise<boolean>((resolve) => {
    try {
      const maybePromise: unknown = permsApi.contains({ origins: [originPattern] }, (granted: boolean) => {
        resolve(granted === true);
      });
      if (
        typeof maybePromise === 'object' &&
        maybePromise !== null &&
        'then' in maybePromise &&
        typeof (maybePromise as Promise<boolean>).then === 'function'
      ) {
        void (maybePromise as Promise<boolean>).then((granted) => resolve(granted === true), () => resolve(true));
      }
    } catch {
      resolve(true);
    }
  });
}

async function collectInaccessibleParentDomains(
  headerMetadata: ParsedCookieMeta[],
  responseUrl: URL | null,
): Promise<Set<string>> {
  const inaccessible = new Set<string>();
  if (responseUrl === null) return inaccessible;
  const responseHost = responseUrl.hostname.toLowerCase();
  const checked = new Set<string>();

  for (const meta of headerMetadata) {
    if (meta.domain === null || meta.domain.length === 0) continue;
    const domainLower = meta.domain.toLowerCase();
    if (domainLower === responseHost || !responseHost.endsWith(`.${domainLower}`)) continue;
    if (checked.has(domainLower)) continue;
    checked.add(domainLower);

    const exactPerm = await checkOriginPermission(`${responseUrl.protocol}//${domainLower}/*`);
    if (exactPerm) continue;
    const wildcardPerm = await checkOriginPermission(`${responseUrl.protocol}//*.${domainLower}/*`);
    if (!wildcardPerm) {
      inaccessible.add(domainLower);
    }
  }
  return inaccessible;
}

async function waitForBoundedCookieSettle(
  missingNames: Set<string>,
  settleDelayMs: number,
): Promise<void> {
  if (settleDelayMs <= 0 || missingNames.size === 0) return;

  await new Promise<void>((resolve) => {
    const remaining = new Set(missingNames);
    const cookiesApi = typeof chrome !== 'undefined' ? (chrome.cookies as { onChanged?: chrome.cookies.CookieChangedEvent } | undefined) : undefined;
    const onChangedApi = cookiesApi?.onChanged;
    let settled = false;
    let timerId: ReturnType<typeof setTimeout> | null = null;

    const cleanup = () => {
      if (settled) return;
      settled = true;
      if (timerId !== null) {
        clearTimeout(timerId);
        timerId = null;
      }
      if (onChangedApi !== undefined && typeof onChangedApi.removeListener === 'function') {
        onChangedApi.removeListener(listener);
      }
      resolve();
    };

    const listener = (changeInfo: chrome.cookies.CookieChangeInfo) => {
      const changedName = changeInfo.cookie.name;
      if (!changeInfo.removed && changedName.length > 0 && remaining.has(changedName)) {
        remaining.delete(changedName);
        if (remaining.size === 0) {
          cleanup();
        }
      }
    };

    if (onChangedApi !== undefined && typeof onChangedApi.addListener === 'function') {
      onChangedApi.addListener(listener);
    }

    timerId = setTimeout(cleanup, settleDelayMs);
  });
}

export async function correlateCookies(
  tabId: number,
  tabUrl: string,
  setCookieHeaders: string[],
  generation?: number,
  isCurrentGeneration?: (tabId: number, generation: number) => boolean,
  hopId?: string,
  hopUrl?: string,
  options?: { settleDelayMs?: number },
): Promise<{ records: CookieRecord[]; findings: Finding[]; discarded?: boolean }> {
  // Pre-query generation check: discard if generation already superseded
  if (
    generation !== undefined &&
    isCurrentGeneration !== undefined &&
    !isCurrentGeneration(tabId, generation)
  ) {
    return { records: [], findings: [], discarded: true };
  }

  const dedupKey = hopId !== undefined && hopId.length > 0
    ? `${tabId}:${tabUrl}:${generation ?? 0}:${hopId}`
    : `${tabId}:${tabUrl}:${generation ?? 0}:${hopUrl ?? ''}`;
  const existing = inFlightCorrelations.get(dedupKey);
  if (existing) {
    return existing;
  }

  const correlationPromise = (async () => {
    // ------------------------------------------------------------------
    // 1. Build a set of names that appeared in Set-Cookie headers (bounded).
    // ------------------------------------------------------------------
    const boundedSetCookieHeaders = setCookieHeaders.slice(0, MAX_SET_COOKIES);
    const headerMetadata = boundedSetCookieHeaders.map(parseCookieHeaderMetadata);
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

    // Post-await generation check: discard if navigation advanced during fetch
    if (
      generation !== undefined &&
      isCurrentGeneration !== undefined &&
      !isCurrentGeneration(tabId, generation)
    ) {
      return { records: [], findings: [], discarded: true };
    }

    const parsedResponseUrl = (() => {
      const rawTarget = hopUrl !== undefined && hopUrl.length > 0 ? hopUrl : tabUrl;
      try {
        return new URL(rawTarget);
      } catch {
        return null;
      }
    })();
    const inaccessibleParentDomains = await collectInaccessibleParentDomains(headerMetadata, parsedResponseUrl);

    // 2b. Bounded delayed confirmation when Set-Cookie candidates are initially missing
    //     from chrome.cookies.getAll() (Chrome commits cookies to storage asynchronously).
    const initialUnobserved = findUnobservedCookieFindings(
      boundedSetCookieHeaders,
      urlScopedCookies,
      tabUrl,
      hopUrl,
      inaccessibleParentDomains,
    );
    const settleDelayMs = options?.settleDelayMs ?? COOKIE_SETTLE_DELAY_MS;
    if (initialUnobserved.length > 0 && settleDelayMs > 0) {
      const missingNames = new Set<string>();
      const visibleSet = new Set(urlScopedCookies.map((c) => c.name));
      for (const meta of headerMetadata) {
        if (meta.name.length > 0 && !meta.isDeletion && !visibleSet.has(meta.name)) {
          const domLower = meta.domain?.toLowerCase();
          if (domLower === undefined || !inaccessibleParentDomains.has(domLower)) {
            missingNames.add(meta.name);
          }
        }
      }
      if (missingNames.size > 0) {
        await waitForBoundedCookieSettle(missingNames, settleDelayMs);
        if (
          generation !== undefined &&
          isCurrentGeneration !== undefined &&
          !isCurrentGeneration(tabId, generation)
        ) {
          return { records: [], findings: [], discarded: true };
        }
        try {
          urlScopedCookies = await chrome.cookies.getAll({ url: tabUrl });
        } catch {
          return { records: [], findings: [] };
        }
        if (
          generation !== undefined &&
          isCurrentGeneration !== undefined &&
          !isCurrentGeneration(tabId, generation)
        ) {
          return { records: [], findings: [], discarded: true };
        }
      }
    }

    // ------------------------------------------------------------------
    // 3. Derive page & hop hostnames for third-party detection.
    // ------------------------------------------------------------------
    let pageHostname = '';
    try {
      pageHostname = new URL(tabUrl).hostname;
    } catch {
      pageHostname = '';
    }

    let hopHostname = '';
    if (hopUrl !== undefined && hopUrl.length > 0) {
      try {
        hopHostname = new URL(hopUrl).hostname;
      } catch {
        hopHostname = '';
      }
    }

    // ------------------------------------------------------------------
    // 4. Map each chrome.cookies.Cookie to a CookieRecord (bounded).
    //    We deliberately skip cookie.value everywhere.
    // ------------------------------------------------------------------
    const currentResponseSetterUrl = sanitizeSetterUrl(hopUrl ?? tabUrl);
    const boundedLiveCookies = urlScopedCookies.slice(0, MAX_COOKIE_RECORDS);
    const records: CookieRecord[] = boundedLiveCookies.map(
      (cookie: chrome.cookies.Cookie): CookieRecord => {
        const matchingHeaders = headerMetadata.filter((item) => item.name === cookie.name);
        const matchingPath = matchingHeaders.find((item) => item.path === cookie.path);
        const headerMatch = matchingPath ?? (matchingHeaders.length === 1 ? matchingHeaders[0] : undefined);
        const matchedOnCurrentResponse = headerMatch !== undefined || headerSetNames.has(cookie.name);
        const setByJs: boolean | null = matchedOnCurrentResponse ? false : null;

        // Derive target domain: header Domain attribute if present, else cookie.domain from jar
        const targetDomain = (headerMatch?.domainAttributePresent === true && headerMatch.domain !== null && headerMatch.domain.length > 0)
          ? headerMatch.domain
          : cookie.domain;
        const thirdParty = isThirdPartyCookie(pageHostname, targetDomain);

        let setterUrl: string | undefined;
        if (matchedOnCurrentResponse && currentResponseSetterUrl !== undefined) {
          setterUrl = currentResponseSetterUrl;
          rememberCookieSetter(targetDomain, cookie.path, cookie.name, currentResponseSetterUrl);
          if (cookie.domain !== targetDomain) {
            rememberCookieSetter(cookie.domain, cookie.path, cookie.name, currentResponseSetterUrl);
          }
        } else {
          setterUrl = rememberedCookieSetters.get(cookieSetterKey(cookie.domain, cookie.path, cookie.name));
        }

        const partitioned =
          (cookie as chrome.cookies.Cookie & { partitionKey?: unknown })
            .partitionKey != null;

        const expiresAt: number | null =
          cookie.session || cookie.expirationDate == null || cookie.expirationDate <= 0
            ? null
            : Math.round(cookie.expirationDate) * 1000;

        const baseRecord: CookieRecord = {
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
          evidenceSource: matchedOnCurrentResponse ? 'set-cookie-header' : 'cookie-jar',
          // cookie.value is intentionally NOT accessed here.
        };
        if (setterUrl !== undefined) {
          baseRecord.setterUrl = setterUrl;
        }
        return baseRecord;
      },
    );

    // ------------------------------------------------------------------
    // 5. Derive header-only records for third-party or permission-withheld
    //    parent-domain cookies absent from the URL-scoped jar query.
    // ------------------------------------------------------------------
    const liveNames = new Set(boundedLiveCookies.map((cookie) => cookie.name));
    const headerDerivedRecords: CookieRecord[] = [];
    const fallbackHost = hopHostname.length > 0 ? hopHostname : pageHostname;
    for (const header of headerMetadata) {
      if (header.name.length === 0 || header.isDeletion || liveNames.has(header.name)) {
        continue;
      }
      const effectiveDomain = (header.domainAttributePresent && header.domain !== null && header.domain.length > 0)
        ? header.domain
        : fallbackHost;
      const isThirdParty = isThirdPartyCookie(pageHostname, effectiveDomain);
      const isWithheldParentDomain = !isThirdParty && inaccessibleParentDomains.has(effectiveDomain.toLowerCase());
      if (isThirdParty || isWithheldParentDomain) {
        const derivedRecord: CookieRecord = {
          name: header.name,
          domain: effectiveDomain,
          domainAttributePresent: header.domainAttributePresent,
          path: header.path ?? '/',
          secure: header.secure,
          httpOnly: header.httpOnly,
          sameSite: header.sameSite,
          session: header.session,
          expiresAt: header.expiresAt,
          partitioned: header.partitioned,
          setByJs: false,
          isThirdParty,
          evidenceSource: 'set-cookie-header',
        };
        if (currentResponseSetterUrl !== undefined) {
          derivedRecord.setterUrl = currentResponseSetterUrl;
        }
        headerDerivedRecords.push(derivedRecord);
      }
    }

    const allRecords: CookieRecord[] = [...records, ...headerDerivedRecords].slice(0, MAX_COOKIE_RECORDS);

    return {
      records: allRecords,
      findings: findUnobservedCookieFindings(
        boundedSetCookieHeaders,
        boundedLiveCookies,
        tabUrl,
        hopUrl,
        inaccessibleParentDomains,
      ),
    };
  })();

  if (inFlightCorrelations.size < MAX_IN_FLIGHT_CORRELATIONS) {
    inFlightCorrelations.set(dedupKey, correlationPromise);
  }

  try {
    return await correlationPromise;
  } finally {
    inFlightCorrelations.delete(dedupKey);
  }
}

export function resetInFlightCorrelationsForTesting(): void {
  inFlightCorrelations.clear();
  rememberedCookieSetters.clear();
}
