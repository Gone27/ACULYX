import { originFromUrl } from '../rules/utils';
import { reportPageSignals } from '../content/service-worker-detection';

function injectPageSignals(tabId: number, url: string): void {
  const origin = originFromUrl(url);
  if (origin === null || origin.length === 0) return;

  chrome.permissions.contains({ origins: [`${origin}/*`] }, (permitted) => {
    if (!permitted) return;

    void chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: reportPageSignals,
    }).catch(() => undefined);
  });
}

export function registerPageSignalInjection(): void {
  chrome.webNavigation.onCommitted.addListener((details): void => {
    if (details.frameId !== 0 || details.tabId < 0) return;
    injectPageSignals(details.tabId, details.url);
  });

  chrome.webNavigation.onHistoryStateUpdated.addListener((details): void => {
    if (details.frameId !== 0 || details.tabId < 0) return;
    injectPageSignals(details.tabId, details.url);
  });
}