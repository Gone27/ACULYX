/**
 * capture.ts
 *
 * Registers chrome.webRequest listeners that intercept HTTP response headers
 * at two distinct pipeline stages:
 *
 *   1. onHeadersReceived  — headers as the browser first sees them (may differ
 *                           from final values if extensions modify them).
 *   2. onResponseStarted  — final headers after all modifications.
 *
 * Comparing the two snapshots lets us detect header mutations by other
 * extensions or intermediaries (headersDiffer flag on the Hop).
 *
 * Captures top-level (`main_frame`) navigations and in-page `xmlhttprequest` (XHR/fetch)
 * API responses. Passive sub-resources (images, stylesheets, fonts, iframes) are excluded
 * to avoid noise. All captures are strictly origin-gated and require user permission.
 */

import { normalizeHeaders, headersDiffer, redactUrlQueryParams, redactUrlPath, redactHeaderValue } from '../rules/utils';
import type { Hop, ApiHop } from '../shared/types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Intermediate capture state accumulated across the two WebRequest events
 * for a single requestId.
 */
export interface PartialCapture {
  /** The tab that owns this request. */
  tabId: number;
  /** Final URL after any server-side rewrites. */
  url: string;
  /** HTTP status code (populated on onResponseStarted). */
  status: number;
  /** Normalised headers from onHeadersReceived. */
  headersReceived: Record<string, string> | null;
  /** Raw header array from onHeadersReceived. */
  rawHeadersReceived: Array<{ name: string; value: string }>;
  /** Normalised headers from onResponseStarted. */
  headersStarted: Record<string, string> | null;
  /** Raw header array from onResponseStarted. */
  rawHeadersStarted: Array<{ name: string; value: string }>;
  /** Whether the response was served from cache. */
  fromCache: boolean;
  /** Whether a redirect was detected before the final response. */
  wasRedirected: boolean;
  /** Timestamp of the first event. */
  timestamp: number;
  /** Number of redirects observed for this request. */
  redirectCount: number;
}

// ---------------------------------------------------------------------------
// In-flight capture store
// ---------------------------------------------------------------------------

/**
 * Keyed by Chrome's `requestId`.  Entries are created on onHeadersReceived
 * and deleted after onResponseStarted finishes processing.
 */
export const captureMap: Map<string, PartialCapture> = new Map();


// ---------------------------------------------------------------------------
// Hop builder helpers
// ---------------------------------------------------------------------------

/**
 * Detect the Non-Authoritative-Reason: HSTS header (case-insensitive name)
 * which indicates the browser silently upgraded the request from HTTP→HTTPS.
 */
function detectHstsUpgrade(raw: Array<{ name: string; value: string }>): boolean {
  return raw.some(
    (h) =>
      h.name.toLowerCase() === 'non-authoritative-reason' &&
      h.value.toUpperCase() === 'HSTS',
  );
}

/**
 * Convert a chrome.webRequest.HttpHeader array to the project's raw-header
 * format, ensuring the value is always a string.
 */
function toRawHeaders(
  headers: chrome.webRequest.HttpHeader[],
): Array<{ name: string; value: string }> {
  return headers.map((h) => ({
    name: h.name,
    value: redactHeaderValue(h.name, h.value ?? ''),
  }));
}

// ---------------------------------------------------------------------------
// Public registration function
// ---------------------------------------------------------------------------

/**
 * Registers all WebRequest listeners needed to capture response hops.
 *
 * @param onHopComplete - Callback invoked for every captured response, including
 *   intermediate redirect responses.
 * @param onApiHopComplete - Optional callback invoked for each captured XHR/Fetch response.
 */
export function registerCaptureListeners(
  onHopComplete: (tabId: number, hop: Hop) => void,
  onApiHopComplete?: (apiHop: ApiHop) => void,
): void {
  const filter: chrome.webRequest.RequestFilter = { urls: ['<all_urls>'] };
  const extraInfoSpec: string[] = ['responseHeaders', 'extraHeaders'];

  // Track in-flight request metadata (method, Origin header) captured at onBeforeSendHeaders.
  const inFlightRequests: Map<string, { method: string; origin?: string | undefined; timestamp: number }> = new Map();

  try {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details: chrome.webRequest.WebRequestHeadersDetails): void => {
        // ONLY track XHR/fetch requests
        if (details.type !== 'xmlhttprequest' || details.tabId < 0) return;
        const originHeader = details.requestHeaders?.find(
          (h) => h.name.toLowerCase() === 'origin',
        )?.value;
        // Bound the map size to prevent memory leaks if responses never finish
        if (inFlightRequests.size > 100) {
          const oldestKey = inFlightRequests.keys().next().value;
          if (oldestKey !== undefined) inFlightRequests.delete(oldestKey);
        }
        inFlightRequests.set(details.requestId, {
          method: details.method,
          origin: originHeader,
          timestamp: details.timeStamp,
        });
      },
      filter,
      ['requestHeaders', 'extraHeaders'],
    );

    // Clean up in-flight request tracking on error or completion
    chrome.webRequest.onErrorOccurred.addListener((details) => {
      inFlightRequests.delete(details.requestId);
    }, filter);
    chrome.webRequest.onCompleted.addListener((details) => {
      inFlightRequests.delete(details.requestId);
    }, filter);
  } catch {
    // extraHeaders may be restricted in some environments; fall back gracefully
  }

  // -------------------------------------------------------------------------
  // Stage 1 — onHeadersReceived
  // -------------------------------------------------------------------------
  chrome.webRequest.onHeadersReceived.addListener(
    (details: chrome.webRequest.WebResponseHeadersDetails): void => {
      // Only track top-level navigation frames.
      if (details.type !== 'main_frame' || details.tabId < 0) return;

      const raw = details.responseHeaders ?? [];
      const partial: PartialCapture = {
        tabId: details.tabId,
        url: details.url,
        status: details.statusCode,
        headersReceived: normalizeHeaders(raw),
        rawHeadersReceived: toRawHeaders(raw),
        headersStarted: null,
        rawHeadersStarted: [],
        fromCache: false, // not available at this stage
        wasRedirected: false,
        timestamp: details.timeStamp,
        redirectCount: 0,
      };

      captureMap.set(details.requestId, partial);
    },
    filter,
    extraInfoSpec,
  );

  // -------------------------------------------------------------------------
  // Stage 2 — onResponseStarted
  // -------------------------------------------------------------------------
  chrome.webRequest.onResponseStarted.addListener(
    (details: chrome.webRequest.WebResponseCacheDetails): void => {
      // Route XHR/Fetch responses to the API callback, if registered.
      if (details.type === 'xmlhttprequest' && details.tabId >= 0) {
        if (onApiHopComplete !== undefined) {
          const reqMeta = inFlightRequests.get(details.requestId);
          inFlightRequests.delete(details.requestId);
          const raw = details.responseHeaders ?? [];
          const apiHeaders = normalizeHeaders(raw);
          const apiRawHeaders = toRawHeaders(raw);
          let normalizedPath: string;
          try {
            const u = new URL(details.url);
            normalizedPath = u.origin + redactUrlPath(u.pathname);
          } catch {
            normalizedPath = redactUrlQueryParams(details.url);
          }
          const sanitizedUrl = redactUrlQueryParams(details.url);
          const apiHop: ApiHop = {
            requestId: details.requestId,
            tabId: details.tabId,
            url: sanitizedUrl,
            normalizedPath,
            method: reqMeta?.method ?? 'GET',
            requestOrigin: reqMeta?.origin,
            status: details.statusCode,
            headers: apiHeaders,
            rawHeaders: apiRawHeaders,
            timestamp: reqMeta?.timestamp ?? details.timeStamp,
            fromCache: details.fromCache ?? false,
          };
          onApiHopComplete(apiHop);
        }
        return;
      }

      if (details.type !== 'main_frame' || details.tabId < 0) return;

      const raw = details.responseHeaders ?? [];
      const normalised = normalizeHeaders(raw);
      const rawHeaders = toRawHeaders(raw);

      // Retrieve (or lazily create) the partial capture started in stage 1.
      let partial = captureMap.get(details.requestId);
      if (!partial) {
        // onHeadersReceived was missed (e.g. very fast cached response).
        // Build a minimal partial so we can still emit a hop.
        partial = {
          tabId: details.tabId,
          url: redactUrlQueryParams(details.url),
          status: details.statusCode,
          headersReceived: null,
          rawHeadersReceived: [],
          headersStarted: null,
          rawHeadersStarted: [],
          fromCache: details.fromCache ?? false,
          wasRedirected: false,
          timestamp: details.timeStamp,
          redirectCount: 0,
        };
      }

      const sanitizedUrl = redactUrlQueryParams(details.url);

      // Fill in stage-2 data.
      partial.headersStarted = normalised;
      partial.rawHeadersStarted = rawHeaders;
      partial.fromCache = details.fromCache ?? false;
      partial.status = details.statusCode;
      partial.url = sanitizedUrl;

      // Decide which raw-header snapshot to expose as the canonical one.
      // We prefer the stage-2 (onResponseStarted) snapshot as the final truth.
      const canonicalRaw = rawHeaders;
      const canonicalNormalised = normalised;

      // Compare the two snapshots (if both exist) to detect mutations.
      const differ =
        partial.headersReceived !== null
          ? headersDiffer(partial.headersReceived, canonicalNormalised)
          : false;

      // Construct the completed Hop.
      const hop: Hop = {
        requestId: details.requestId,
        url: sanitizedUrl,
        status: details.statusCode,
        headers: canonicalNormalised,
        rawHeaders: canonicalRaw,
        fromCache: partial.fromCache,
        isHstsUpgrade: detectHstsUpgrade(canonicalRaw),
        capturedAt: 'onResponseStarted',
        headersDiffer: differ,
        timestamp: partial.timestamp,
        redirectCount: partial.redirectCount,
      };

      // Clean up in-flight state.
      captureMap.delete(details.requestId);

      // Notify the orchestrator.
      void onHopComplete(details.tabId, hop);
    },
    filter,
    extraInfoSpec,
  );

  // -------------------------------------------------------------------------
  // Redirect tracking — onBeforeRedirect
  // -------------------------------------------------------------------------
  // Redirects produce a response (3xx) before the final response, so we record
  // them in captureMap and mark the capture as having been redirected.
  // The correlate/rule engine can inspect the hop chain if desired.
  chrome.webRequest.onBeforeRedirect.addListener(
    (details: chrome.webRequest.WebRedirectionResponseDetails): void => {
      if (details.type !== 'main_frame' || details.tabId < 0) return;

      const existing = captureMap.get(details.requestId);
      const raw = details.responseHeaders ?? existing?.rawHeadersReceived ?? [];
      const headers = normalizeHeaders(raw);
      const rawHeaders = toRawHeaders(raw);
      const beforeHeaders = existing?.headersReceived;
      const hop: Hop = {
        requestId: details.requestId,
        url: redactUrlQueryParams(details.url),
        status: details.statusCode,
        headers,
        rawHeaders,
        fromCache: false,
        isHstsUpgrade: detectHstsUpgrade(rawHeaders),
        capturedAt: 'onResponseStarted',
        headersDiffer: beforeHeaders !== null && beforeHeaders !== undefined
          ? headersDiffer(beforeHeaders, headers)
          : false,
        timestamp: existing?.timestamp ?? details.timeStamp,
        redirectCount: 0,
      };

      captureMap.delete(details.requestId);
      void onHopComplete(details.tabId, hop);
    },
    filter,
    extraInfoSpec,
  );
}
