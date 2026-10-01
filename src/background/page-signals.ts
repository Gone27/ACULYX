import { originFromUrl } from '../rules/utils';
import { reportPageSignals } from '../content/service-worker-detection';
import { isRestrictedUrl } from '../shared/gating';
import { SettingsService } from '../shared/settings';

function injectPageSignals(tabId: number, url: string): void {
  if (isRestrictedUrl(url)) return;
  const origin = originFromUrl(url);
  if (origin === null || origin.length === 0) return;

  const settings = SettingsService.getCachedSettings();
  if (settings.monitoringMode === 'off') return;

  if (typeof chrome === 'undefined' || typeof chrome.permissions === 'undefined') return;

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