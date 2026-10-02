/** Runs in the page's isolated world only after host permission is granted. */
export function reportPageSignals(): void {
  const isolatedWorld = globalThis as typeof globalThis & { __seccheckPageSignalsInstalled?: boolean };
  if (isolatedWorld.__seccheckPageSignalsInstalled === true) return;
  isolatedWorld.__seccheckPageSignalsInstalled = true;

  const controller = navigator.serviceWorker?.controller;

  void chrome.runtime.sendMessage({
    type: 'SERVICE_WORKER_STATUS',
    status: controller == null ? 'not-controlled' : 'controlled',
    serviceWorkerUrl: controller?.scriptURL ?? null,
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
  const scannedUrls = new Set<string>();
  let initialSriDone = false;

  function doReportSri(): void {
    const externalScripts = Array.from(document.querySelectorAll<HTMLScriptElement>('script[src]'))
      .filter((script) => {
        if (scannedUrls.has(script.src)) return false;
        scannedUrls.add(script.src);
        try { return new URL(script.src, location.href).origin !== location.origin; }
        catch { return false; }
      });

    const externalStylesheets = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="stylesheet"][href]'))
      .filter((link) => {
        if (scannedUrls.has(link.href)) return false;
        scannedUrls.add(link.href);
        try { return new URL(link.href, location.href).origin !== location.origin; }
        catch { return false; }
      });

    if (initialSriDone && externalScripts.length === 0 && externalStylesheets.length === 0) return;
    initialSriDone = true;

    const missingScriptIntegrity = externalScripts.filter((s) => !s.integrity.trim()).length;
    const missingStyleIntegrity = externalStylesheets.filter((l) => !l.integrity.trim()).length;

    void chrome.runtime.sendMessage({
      type: 'SRI_SCAN',
      externalScripts: externalScripts.length,
      missingIntegrity: missingScriptIntegrity,
      externalStylesheets: externalStylesheets.length,
      missingStyleIntegrity,
    }).catch(() => undefined);
  }

  doReportSri();

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
          doReportSri();
        });
      } else {
        doReportSri();
      }
    }
  });
  sriObserver.observe(document.documentElement, {
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
