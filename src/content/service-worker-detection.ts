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

  function containsMetaCsp(): boolean {
    return Array.from(document.querySelectorAll('meta[http-equiv]')).some(
      (meta) => meta.getAttribute('http-equiv')?.trim().toLowerCase() === 'content-security-policy'
        && (meta.getAttribute('content')?.trim().length ?? 0) > 0,
    );
  }

  function reportMetaCsp(): void {
    void chrome.runtime.sendMessage({ type: 'META_CSP_FOUND' }).catch(() => undefined);
  }

  if (containsMetaCsp()) {
    reportMetaCsp();
  } else {
    const observer = new MutationObserver(() => {
      if (containsMetaCsp()) {
        reportMetaCsp();
        observer.disconnect();
      }
    });
    observer.observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['http-equiv', 'content'] });
  }

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
