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
  // Track eligible cross-origin HTTP(S) external resources across page lifetime.
  // Excludes inline <script>, same-origin assets, and data:/blob: URLs.
  interface SriResourceEntry {
    hasIntegrity: boolean;
    isDynamic: boolean;
  }
  const MAX_REPORTED_SRI_URLS = 20;
  const externalScriptMap = new Map<string, SriResourceEntry>(); // origin+pathname -> status
  const externalStylesheetMap = new Map<string, SriResourceEntry>(); // origin+pathname -> status

  function toEligibleCrossOriginUrl(rawRef: string): string | null {
    try {
      const parsed = new URL(rawRef, location.href);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }
      if (parsed.origin === location.origin) {
        return null;
      }
      return `${parsed.origin}${parsed.pathname}`;
    } catch {
      return null;
    }
  }

  function doReportSri(isMutationPass: boolean): void {
    const scripts = Array.from(document.querySelectorAll<HTMLScriptElement>('script[src]'));
    for (const script of scripts) {
      const eligibleUrl = toEligibleCrossOriginUrl(script.src);
      if (eligibleUrl === null) continue;
      const hasIntegrity = script.integrity.trim().length > 0;
      const prev = externalScriptMap.get(eligibleUrl);
      externalScriptMap.set(eligibleUrl, {
        hasIntegrity,
        isDynamic: prev !== undefined ? prev.isDynamic : isMutationPass,
      });
    }

    const links = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="stylesheet"][href]'));
    for (const link of links) {
      const eligibleUrl = toEligibleCrossOriginUrl(link.href);
      if (eligibleUrl === null) continue;
      const hasIntegrity = link.integrity.trim().length > 0;
      const prev = externalStylesheetMap.get(eligibleUrl);
      externalStylesheetMap.set(eligibleUrl, {
        hasIntegrity,
        isDynamic: prev !== undefined ? prev.isDynamic : isMutationPass,
      });
    }

    const totalExternalScripts = externalScriptMap.size;
    const missingScriptUrls: string[] = [];
    let dynamicMissingCount = 0;
    for (const [url, entry] of externalScriptMap.entries()) {
      if (!entry.hasIntegrity) {
        if (missingScriptUrls.length < MAX_REPORTED_SRI_URLS) {
          missingScriptUrls.push(url);
        }
        if (entry.isDynamic) dynamicMissingCount++;
      }
    }

    const totalExternalStylesheets = externalStylesheetMap.size;
    const missingStyleUrls: string[] = [];
    for (const [url, entry] of externalStylesheetMap.entries()) {
      if (!entry.hasIntegrity) {
        if (missingStyleUrls.length < MAX_REPORTED_SRI_URLS) {
          missingStyleUrls.push(url);
        }
        if (entry.isDynamic) dynamicMissingCount++;
      }
    }

    const missingScriptIntegrity = Array.from(externalScriptMap.values()).filter((e) => !e.hasIntegrity).length;
    const missingStyleIntegrity = Array.from(externalStylesheetMap.values()).filter((e) => !e.hasIntegrity).length;

    void chrome.runtime.sendMessage({
      type: 'SRI_SCAN',
      externalScripts: totalExternalScripts,
      missingIntegrity: missingScriptIntegrity,
      externalStylesheets: totalExternalStylesheets,
      missingStyleIntegrity,
      missingScriptUrls,
      missingStyleUrls,
      dynamicMissingCount,
      generation,
      eventId: `sri:${generation ?? 0}:${totalExternalScripts}:${missingScriptIntegrity}:${totalExternalStylesheets}:${missingStyleIntegrity}:${dynamicMissingCount}`,
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
