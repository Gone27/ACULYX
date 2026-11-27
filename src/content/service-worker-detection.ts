/** Runs in the page's isolated world only after host permission is granted. */
export function reportPageSignals(generation?: number): void {
  const isolatedWorld = globalThis as typeof globalThis & { __seccheckPageSignalsInstalled?: boolean };
  if (isolatedWorld.__seccheckPageSignalsInstalled === true) return;
  isolatedWorld.__seccheckPageSignalsInstalled = true;

  const controller = navigator.serviceWorker?.controller;
  const swUrl = controller?.scriptURL ?? null;

  void chrome.runtime.sendMessage({
    type: 'SERVICE_WORKER_STATUS',
    status: controller == null ? 'not-controlled' : 'controlled',
    serviceWorkerUrl: swUrl,
    generation,
    eventId: `sw:${generation ?? 0}:${controller == null ? 'not-controlled' : 'controlled'}:${swUrl ?? ''}`,
  }).catch(() => undefined);

  // ── Meta CSP ──────────────────────────────────────────────────────────────
  // Collect all <meta http-equiv="Content-Security-Policy"> policies in document
  // order. The browser intersects multiple policies (most-restrictive per directive).
  // We send the full list so the background can run csp_evaluator on each policy.
  function getMetaCspPolicies(): string[] {
    const policies: string[] = [];
    for (const meta of Array.from(document.querySelectorAll('meta[http-equiv]'))) {
      if (meta.getAttribute('http-equiv')?.trim().toLowerCase() === 'content-security-policy') {
        const content = meta.getAttribute('content')?.trim();
        if (content !== undefined && content.length > 0) {
          policies.push(content.slice(0, 2048));
          if (policies.length >= 5) break;
        }
      }
    }
    return policies;
  }

  let metaCspFound = false;
  function reportMetaCsp(): void {
    if (metaCspFound) return;
    const policies = getMetaCspPolicies();
    if (policies.length === 0) return;
    metaCspFound = true;
    void chrome.runtime.sendMessage({
      type: 'META_CSP_FOUND',
      policies, // full policy strings — NOT injected into DOM, sent over runtime message
      generation,
      eventId: `meta-csp:${generation ?? 0}:${policies.length}:${policies.join(';').slice(0, 100)}`,
    }).catch(() => undefined);
  }

  let metaCspRaf: number | null = null;
  if (getMetaCspPolicies().length > 0) {
    reportMetaCsp();
  } else {
    const observer = new MutationObserver(() => {
      if (metaCspFound) {
        observer.disconnect();
        return;
      }
      if (metaCspRaf !== null) return;
      metaCspRaf = requestAnimationFrame(() => {
        metaCspRaf = null;
        reportMetaCsp();
      });
    });
    observer.observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['http-equiv', 'content'] });
    if (typeof window !== 'undefined') {
      window.addEventListener('pagehide', () => observer.disconnect(), { once: true });
      window.addEventListener('unload', () => observer.disconnect(), { once: true });
    }
  }

  // ── SRI scan ──────────────────────────────────────────────────────────────
  // Track current settled DOM cross-origin HTTP(S) resources separately from
  // historically observed dynamic resources later removed from the DOM.
  // Deduplicates exact URLs (preserving non-sensitive query versions).
  const MAX_REPORTED_SRI_URLS = 20;
  const MAX_SRI_URL_LEN = 256;
  const initialUrlsSeen = new Set<string>();
  const historicalUrlsMissing = new Set<string>();
  let initializedBaseline = false;

  function toEligibleCrossOriginUrl(rawRef: string): string | null {
    try {
      const parsed = new URL(rawRef, location.href);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }
      if (parsed.origin === location.origin) {
        return null;
      }
      const sensitiveQueryRe = /^(?:token|access_token|auth|key|apikey|api_key|secret|sig|signature|password|session|sid)$/i;
      const cleanParams = new URLSearchParams();
      for (const [k, v] of parsed.searchParams.entries()) {
        cleanParams.append(k, sensitiveQueryRe.test(k) ? '[REDACTED]' : v);
      }
      const query = cleanParams.toString();
      const normalized = `${parsed.origin}${parsed.pathname}${query.length > 0 ? `?${query}` : ''}`;
      return normalized.slice(0, MAX_SRI_URL_LEN);
    } catch {
      return null;
    }
  }

  function doReportSri(isMutationPass: boolean): void {
    const currentScripts = new Map<string, boolean>();
    const scripts = Array.from(document.querySelectorAll<HTMLScriptElement>('script[src]'));
    for (const script of scripts) {
      const eligibleUrl = toEligibleCrossOriginUrl(script.src);
      if (eligibleUrl === null) continue;
      const hasIntegrity = script.integrity.trim().length > 0;
      const prev = currentScripts.get(eligibleUrl);
      // If multiple tags reference exact URL, mark safe only if all have integrity
      currentScripts.set(eligibleUrl, prev === undefined ? hasIntegrity : (prev && hasIntegrity));
      if (!initializedBaseline && !isMutationPass) {
        initialUrlsSeen.add(`script:${eligibleUrl}`);
      }
    }

    const currentStyles = new Map<string, boolean>();
    const links = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="stylesheet"][href]'));
    for (const link of links) {
      const eligibleUrl = toEligibleCrossOriginUrl(link.href);
      if (eligibleUrl === null) continue;
      const hasIntegrity = link.integrity.trim().length > 0;
      const prev = currentStyles.get(eligibleUrl);
      currentStyles.set(eligibleUrl, prev === undefined ? hasIntegrity : (prev && hasIntegrity));
      if (!initializedBaseline && !isMutationPass) {
        initialUrlsSeen.add(`style:${eligibleUrl}`);
      }
    }
    initializedBaseline = true;

    const missingScriptUrls: string[] = [];
    let currentMissingScripts = 0;
    let dynamicMissingCount = 0;
    for (const [url, hasIntegrity] of currentScripts.entries()) {
      if (!hasIntegrity) {
        currentMissingScripts++;
        if (missingScriptUrls.length < MAX_REPORTED_SRI_URLS) {
          missingScriptUrls.push(url);
        }
        if (!initialUrlsSeen.has(`script:${url}`)) {
          dynamicMissingCount++;
        }
        historicalUrlsMissing.add(`script:${url}`);
      }
    }

    const missingStyleUrls: string[] = [];
    let currentMissingStyles = 0;
    for (const [url, hasIntegrity] of currentStyles.entries()) {
      if (!hasIntegrity) {
        currentMissingStyles++;
        if (missingStyleUrls.length < MAX_REPORTED_SRI_URLS) {
          missingStyleUrls.push(url);
        }
        if (!initialUrlsSeen.has(`style:${url}`)) {
          dynamicMissingCount++;
        }
        historicalUrlsMissing.add(`style:${url}`);
      }
    }

    let historicalRemovedMissingCount = 0;
    for (const histKey of historicalUrlsMissing) {
      if (histKey.startsWith('script:')) {
        const u = histKey.slice('script:'.length);
        if (!currentScripts.has(u)) historicalRemovedMissingCount++;
      } else if (histKey.startsWith('style:')) {
        const u = histKey.slice('style:'.length);
        if (!currentStyles.has(u)) historicalRemovedMissingCount++;
      }
    }

    const totalExternalScripts = currentScripts.size;
    const totalExternalStylesheets = currentStyles.size;

    void chrome.runtime.sendMessage({
      type: 'SRI_SCAN',
      externalScripts: totalExternalScripts,
      missingIntegrity: currentMissingScripts,
      externalStylesheets: totalExternalStylesheets,
      missingStyleIntegrity: currentMissingStyles,
      missingScriptUrls,
      missingStyleUrls,
      dynamicMissingCount,
      historicalRemovedMissingCount,
      generation,
      eventId: `sri:${generation ?? 0}:${totalExternalScripts}:${currentMissingScripts}:${totalExternalStylesheets}:${currentMissingStyles}:${dynamicMissingCount}:${historicalRemovedMissingCount}:${missingScriptUrls.join(',')}|${missingStyleUrls.join(',')}`,
    }).catch(() => undefined);
  }

  doReportSri(false);

  let sriRaf: number | null = null;
  const sriObserver = new MutationObserver((mutations) => {
    let hasRelevantMutation = false;
    for (const mutation of mutations) {
      if (mutation.type === 'attributes') {
        hasRelevantMutation = true;
        break;
      }
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1) {
          const el = node as Element;
          if (el.tagName === 'SCRIPT' || el.tagName === 'LINK' || el.querySelector('script[src], link[rel~="stylesheet"]')) {
            hasRelevantMutation = true;
            break;
          }
        }
      }
      if (hasRelevantMutation) break;
    }

    if (hasRelevantMutation && sriRaf === null) {
      if (typeof requestAnimationFrame === 'function') {
        sriRaf = requestAnimationFrame(() => {
          sriRaf = null;
          doReportSri(true);
        });
      } else {
        doReportSri(true);
      }
    }
  });

  const targetRoot = document.documentElement ?? document;
  sriObserver.observe(targetRoot, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src', 'integrity', 'href', 'rel'],
  });
  if (typeof window !== 'undefined') {
    window.addEventListener('pagehide', () => sriObserver.disconnect(), { once: true });
    window.addEventListener('unload', () => sriObserver.disconnect(), { once: true });
  }
}
