/**
 * dom-collector.ts - Sensor 2 (S2)
 *
 * Isolated-world content script running at document_idle.
 * Extracts DOM structures, forms, scripts, iframes, meta tags, comments,
 * hydration data, resource timing, and storage key names (NEVER storage values).
 * Dispatches DOM_LEADS_COLLECTED to the background service worker.
 * Also listens for CustomEvents from S3 (main-world-hooks) and relays them to background.
 */

export interface ExtractedFormData {
  action: string;
  method: string;
  inputNames: string[];
}

export interface ExtractedIframeData {
  src: string;
  sandbox: string;
  allow: string;
}

export interface ExtractedScriptData {
  src: string;
  inlineContent?: string | undefined;
  sourceMappingURL?: string | undefined;
}

export interface ExtractedLinkData {
  href: string;
  rel?: string | undefined;
}

export interface ExtractedMetaData {
  name: string;
  content: string;
  generator?: string | undefined;
}

export interface ExtractedHydrationGlobals {
  nextData?: string | undefined;
  nuxt?: string | undefined;
  initialState?: string | undefined;
  apolloState?: string | undefined;
  env?: string | undefined;
}

export interface DomCollectionResult {
  forms: ExtractedFormData[];
  iframes: ExtractedIframeData[];
  scripts: ExtractedScriptData[];
  links: ExtractedLinkData[];
  metaTags: ExtractedMetaData[];
  comments: string[];
  hydrationGlobals: ExtractedHydrationGlobals;
  resourceTiming: string[];
  storageKeyNames: {
    localStorage: string[];
    sessionStorage: string[];
  };
}

const INLINE_SCRIPT_BUDGET_BYTES = 2 * 1024 * 1024; // 2 MB budget
const MAX_COMMENTS = 200;
const MAX_LINKS = 500;
const MAX_RESOURCES = 500;

export function collectDomLeads(): DomCollectionResult {
  // 1. Forms
  const forms: ExtractedFormData[] = [];
  const formElements = Array.from(document.querySelectorAll('form'));
  for (const form of formElements) {
    const rawAction = form.getAttribute('action') ?? '';
    const action = sanitizeClientUrl(rawAction);
    const method = (form.getAttribute('method') ?? 'GET').toUpperCase();
    const inputNames: string[] = [];
    const controls = form.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(
      'input, textarea, select'
    );
    for (const ctrl of Array.from(controls)) {
      const name = ctrl.getAttribute('name');
      if (typeof name === 'string' && name.trim().length > 0) {
        inputNames.push(name.trim());
      }
    }
    forms.push({ action, method, inputNames });
  }

  // 2. Iframes
  const iframes: ExtractedIframeData[] = [];
  const iframeElements = Array.from(document.querySelectorAll('iframe'));
  for (const iframe of iframeElements) {
    iframes.push({
      src: sanitizeClientUrl(iframe.getAttribute('src') ?? ''),
      sandbox: iframe.getAttribute('sandbox') ?? '',
      allow: iframe.getAttribute('allow') ?? '',
    });
  }

  // 3. Scripts
  const scripts: ExtractedScriptData[] = [];
  let remainingBudget = INLINE_SCRIPT_BUDGET_BYTES;
  const scriptElements = Array.from(document.querySelectorAll('script'));

  for (const script of scriptElements) {
    const rawSrc = script.getAttribute('src') ?? '';
    const src = sanitizeClientUrl(rawSrc);
    let inlineContent: string | undefined;
    let sourceMappingURL: string | undefined;

    const rawText = script.textContent ?? '';
    // Check for sourceMappingURL in both inline and linked script annotations
    const mapMatch = rawText.match(/\/\/[#@]\s*sourceMappingURL=([^\s]+)/) ??
                     rawText.match(/\/\*[#@]\s*sourceMappingURL=([^\s]+)\s*\*\//);
    if (mapMatch !== null && mapMatch[1] !== undefined && mapMatch[1].length > 0) {
      sourceMappingURL = mapMatch[1];
    }

    if (src.length === 0 && rawText.length > 0 && remainingBudget > 0) {
      const sliceLen = Math.min(rawText.length, remainingBudget);
      inlineContent = rawText.slice(0, sliceLen);
      remainingBudget -= sliceLen;
    }

    scripts.push({
      src,
      inlineContent,
      sourceMappingURL,
    });
  }

  // 4. Links
  const links: ExtractedLinkData[] = [];
  const linkElements = Array.from(document.querySelectorAll('a[href]')).slice(0, MAX_LINKS);
  for (const a of linkElements) {
    links.push({
      href: sanitizeClientUrl(a.getAttribute('href') ?? ''),
      rel: a.getAttribute('rel') ?? undefined,
    });
  }

  // 5. Meta tags
  const metaTags: ExtractedMetaData[] = [];
  const metaElements = Array.from(document.querySelectorAll('meta'));
  for (const meta of metaElements) {
    const name = meta.getAttribute('name') ?? meta.getAttribute('property') ?? meta.getAttribute('http-equiv') ?? '';
    const content = meta.getAttribute('content') ?? '';
    let generator: string | undefined;
    if (name.toLowerCase() === 'generator') {
      generator = content;
    }
    if (name.length > 0 || content.length > 0) {
      metaTags.push({ name, content, generator });
    }
  }

  // 6. HTML Comments
  const comments: string[] = [];
  try {
    const iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT);
    let node: Node | null;
    let count = 0;
    while ((node = iterator.nextNode()) !== null && count < MAX_COMMENTS) {
      const val = node.nodeValue?.trim();
      if (typeof val === 'string' && val.length > 0) {
        comments.push(val.slice(0, 2048));
        count++;
      }
    }
  } catch {
    // Ignore iterator errors
  }

  // 7. Hydration Globals & framework state tags
  const hydrationGlobals: ExtractedHydrationGlobals = {};

  // Next.js: <script id="__NEXT_DATA__" type="application/json">
  const nextDataEl = document.getElementById('__NEXT_DATA__');
  if (nextDataEl !== null && typeof nextDataEl.textContent === 'string' && nextDataEl.textContent.length > 0) {
    hydrationGlobals.nextData = nextDataEl.textContent.slice(0, 100_000);
  }

  // Nuxt.js: <script id="__NUXT_DATA__"> or window.__NUXT__
  const nuxtDataEl = document.getElementById('__NUXT_DATA__');
  if (nuxtDataEl !== null && typeof nuxtDataEl.textContent === 'string' && nuxtDataEl.textContent.length > 0) {
    hydrationGlobals.nuxt = nuxtDataEl.textContent.slice(0, 100_000);
  }

  // Check script tags for state assignments or data attributes
  for (const script of scriptElements) {
    const txt = script.textContent ?? '';
    if (hydrationGlobals.nuxt === undefined && txt.includes('window.__NUXT__')) {
      hydrationGlobals.nuxt = txt.slice(0, 50_000);
    }
    if (hydrationGlobals.initialState === undefined && txt.includes('__INITIAL_STATE__')) {
      hydrationGlobals.initialState = txt.slice(0, 50_000);
    }
    if (hydrationGlobals.apolloState === undefined && txt.includes('__APOLLO_STATE__')) {
      hydrationGlobals.apolloState = txt.slice(0, 50_000);
    }
    if (hydrationGlobals.env === undefined && (txt.includes('window.__ENV__') || txt.includes('window.ENV'))) {
      hydrationGlobals.env = txt.slice(0, 50_000);
    }
  }

  // Check dataset on root or body
  const rootDataEnv = document.documentElement.getAttribute('data-env') ?? document.body?.getAttribute('data-env');
  if (typeof rootDataEnv === 'string' && rootDataEnv.length > 0 && hydrationGlobals.env === undefined) {
    hydrationGlobals.env = rootDataEnv;
  }

  // 8. Performance resource timing
  const resourceTiming: string[] = [];
  try {
    if (typeof performance !== 'undefined' && typeof performance.getEntriesByType === 'function') {
      const entries = performance.getEntriesByType('resource');
      for (let i = 0; i < Math.min(entries.length, MAX_RESOURCES); i++) {
        const item = entries[i];
        if (item !== undefined && typeof item.name === 'string' && item.name.length > 0) {
          resourceTiming.push(item.name);
        }
      }
    }
  } catch {
    // Ignore performance timing errors
  }

  // 9. Storage Key Names (ONLY KEYS, NEVER VALUES)
  const localStorageKeys: string[] = [];
  const sessionStorageKeys: string[] = [];

  try {
    if (typeof window !== 'undefined' && 'localStorage' in window && window.localStorage !== null) {
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (typeof key === 'string' && key.length > 0) {
          localStorageKeys.push(key);
        }
      }
    }
  } catch {
    // Cross-origin or sandbox security error
  }

  try {
    if (typeof window !== 'undefined' && 'sessionStorage' in window && window.sessionStorage !== null) {
      for (let i = 0; i < window.sessionStorage.length; i++) {
        const key = window.sessionStorage.key(i);
        if (typeof key === 'string' && key.length > 0) {
          sessionStorageKeys.push(key);
        }
      }
    }
  } catch {
    // Cross-origin or sandbox security error
  }

  return {
    forms,
    iframes,
    scripts,
    links,
    metaTags,
    comments,
    hydrationGlobals,
    resourceTiming,
    storageKeyNames: {
      localStorage: localStorageKeys,
      sessionStorage: sessionStorageKeys,
    },
  };
}

function sanitizeClientUrl(rawUrl: string): string {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) return '';
  try {
    const u = new URL(rawUrl);
    // 1. Strip fragments entirely to prevent OAuth tokens from leaking
    u.hash = '';

    // 2. Strip embedded user:pass credentials
    u.username = '';
    u.password = '';

    // 3. Mask ALL query parameter values to '***' while retaining parameter names for attack-surface intelligence
    for (const k of Array.from(u.searchParams.keys())) {
      u.searchParams.set(k, '***');
    }

    return u.toString();
  } catch {
    // Relative or malformed URL fallback:
    // Drop fragment
    const splitHash = rawUrl.split('#')[0];
    let sanitized = typeof splitHash === 'string' ? splitHash : '';
    // Strip user:pass
    sanitized = sanitized.replace(/\/\/[^/:@\s]+:[^/@\s]+@/g, '//');
    // Mask all query parameter values
    sanitized = sanitized.replace(/([?&][^=&#\s]+)=([^&#\s]*)/g, '$1=***');
    return sanitized;
  }
}

const ALLOWED_SINKS = new Set([
  'Element.innerHTML',
  'Element.outerHTML',
  'Element.insertAdjacentHTML',
  'document.write',
  'document.writeln',
  'window.eval',
  'setTimeout(string)',
  'location.assign',
  'location.replace',
]);

const MAX_MAIN_WORLD_EVENTS = 50; // Strict cap per page load
let domCollectorInstalledInClosure = false;

export function initDomCollector(): void {
  if (domCollectorInstalledInClosure) return;
  domCollectorInstalledInClosure = true;

  let mainWorldEventCount = 0;

  interface RawMainWorldDetail {
    eventType?: unknown;
    sinkName?: unknown;
    sourceValue?: unknown;
    targetOrigin?: unknown;
    hasOriginCheck?: unknown;
    storageKey?: unknown;
    tokenShape?: unknown;
    details?: unknown;
  }

  // Listen for S3 (Main World Hooks) CustomEvents and relay to background as untrusted with strict payload caps
  window.addEventListener('__ACULYX_MAIN_WORLD_EVENT__', (event: Event) => {
    try {
      // 1. Strict event count cap
      if (mainWorldEventCount >= MAX_MAIN_WORLD_EVENTS) return;

      const customEvent = event as CustomEvent<unknown>;
      if (typeof customEvent.detail !== 'object' || customEvent.detail === null) return;
      const detail = customEvent.detail as RawMainWorldDetail;

      // 2. Validate eventType whitelist
      if (typeof detail.eventType !== 'string') return;
      const eventType = detail.eventType;
      if (!['sink', 'postmessage_call', 'postmessage_listener', 'storage_write'].includes(eventType)) {
        return;
      }

      // 3. Validate sink payload
      if (eventType === 'sink') {
        if (typeof detail.sinkName !== 'string' || !ALLOWED_SINKS.has(detail.sinkName)) {
          return;
        }
      }

      // 4. Strict payload caps: clamp string lengths to prevent memory exhaustion
      const safeDetail = {
        eventType,
        sinkName: typeof detail.sinkName === 'string' ? detail.sinkName.slice(0, 80) : undefined,
        sourceValue: typeof detail.sourceValue === 'string' ? detail.sourceValue.slice(0, 128) : undefined,
        targetOrigin: typeof detail.targetOrigin === 'string' ? detail.targetOrigin.slice(0, 128) : undefined,
        hasOriginCheck: typeof detail.hasOriginCheck === 'boolean' ? detail.hasOriginCheck : undefined,
        storageKey: typeof detail.storageKey === 'string' ? detail.storageKey.slice(0, 64) : undefined,
        tokenShape: typeof detail.tokenShape === 'string' ? detail.tokenShape.slice(0, 64) : undefined,
        details: typeof detail.details === 'string' ? detail.details.slice(0, 256) : undefined,
      };

      mainWorldEventCount++;

      void chrome.runtime?.sendMessage?.({
        type: 'MAIN_WORLD_LEADS_EVENT',
        url: sanitizeClientUrl(location.href),
        origin: location.origin,
        event: safeDetail,
      }).catch(() => undefined);
    } catch {
      // Ignore messaging errors
    }
  });

  function performCollection(): void {
    try {
      const data = collectDomLeads();
      void chrome.runtime?.sendMessage?.({
        type: 'DOM_LEADS_COLLECTED',
        url: sanitizeClientUrl(location.href),
        origin: location.origin,
        data,
      }).catch(() => undefined);
    } catch {
      // Ignore collection errors
    }
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    performCollection();
  } else {
    window.addEventListener('DOMContentLoaded', performCollection, { once: true });
    window.addEventListener('load', performCollection, { once: true });
  }
}

// Automatically initialize when running as content script
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  initDomCollector();
}
