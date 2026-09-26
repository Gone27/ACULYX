(function(){const controller = navigator.serviceWorker?.controller;
void chrome.runtime.sendMessage({
  type: "SERVICE_WORKER_STATUS",
  status: controller == null ? "not-controlled" : "controlled",
  serviceWorkerUrl: controller?.scriptURL ?? null
}).catch(() => void 0);
//# sourceMappingURL=service-worker-detection.ts-ZG0dyj9U.js.map
})()
