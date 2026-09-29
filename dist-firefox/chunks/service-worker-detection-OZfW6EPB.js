function reportPageSignals() {
  const controller = navigator.serviceWorker?.controller;
  void chrome.runtime.sendMessage({
    type: "SERVICE_WORKER_STATUS",
    status: controller == null ? "not-controlled" : "controlled",
    serviceWorkerUrl: controller?.scriptURL ?? null
  }).catch(() => void 0);
  function containsMetaCsp() {
    return Array.from(document.querySelectorAll("meta[http-equiv]")).some(
      (meta) => meta.getAttribute("http-equiv")?.trim().toLowerCase() === "content-security-policy" && (meta.getAttribute("content")?.trim().length ?? 0) > 0
    );
  }
  function reportMetaCsp() {
    void chrome.runtime.sendMessage({ type: "META_CSP_FOUND" }).catch(() => void 0);
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
    observer.observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ["http-equiv", "content"] });
  }
}
export {
  reportPageSignals as r
};
//# sourceMappingURL=service-worker-detection-OZfW6EPB.js.map
