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

  function reportMetaCsp(): void {
    const policies = getMetaCspPolicies();
    if (policies.length === 0) return;
    void chrome.runtime.sendMessage({
      type: 'META_CSP_FOUND',
      policies, // full policy strings — NOT injected into DOM, sent over runtime message
    }).catch(() => undefined);
  }

  if (getMetaCspPolicies().length > 0) {
    reportMetaCsp();
  } else {
    const observer = new MutationObserver(() => {
      if (getMetaCspPolicies().length > 0) {
        reportMetaCsp();
        observer.disconnect();
      }
    });
    observer.observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['http-equiv', 'content'] });
  }

  // ── SRI scan ──────────────────────────────────────────────────────────────
  // Scans current DOM for external <script src> and <link stylesheet href>
  // that lack integrity= attributes. NOTE: this audits only elements present
  // at scan time; dynamically injected subresources after this point may not
  // be captured. The observer below re-runs on DOM mutations to catch SPAs.
  function reportSri(): void {
    const externalScripts = Array.from(document.querySelectorAll<HTMLScriptElement>('script[src]'))
      .filter((script) => {
        try { return new URL(script.src, location.href).origin !== location.origin; }
        catch { return false; }
      });

    const externalStylesheets = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="stylesheet"][href]'))
      .filter((link) => {
        try { return new URL(link.href, location.href).origin !== location.origin; }
        catch { return false; }
      });

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

  reportSri();
  const sriObserver = new MutationObserver(reportSri);
  sriObserver.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src', 'integrity', 'href', 'rel'],
  });
}
