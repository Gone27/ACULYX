/** Report whether the current document is controlled by a service worker. */

const controller = navigator.serviceWorker?.controller;

void chrome.runtime.sendMessage({
  type: 'SERVICE_WORKER_STATUS',
  status: controller == null ? 'not-controlled' : 'controlled',
  serviceWorkerUrl: controller?.scriptURL ?? null,
}).catch(() => undefined);