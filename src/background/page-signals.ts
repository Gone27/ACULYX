import { originFromUrl } from '../rules/utils';
import { reportPageSignals } from '../content/service-worker-detection';
import { isModeCaptureAllowed, isRestrictedUrl } from '../shared/gating';
import { SettingsService } from '../shared/settings';
import { isBroadGrant } from './permissions';

export function injectPageSignals(tabId: number, url: string): void {
  if (isRestrictedUrl(url)) return;
  const origin = originFromUrl(url);
  if (origin === null || origin.length === 0) return;

  const settings = SettingsService.getCachedSettings();
  if (settings.monitoringMode === 'off') return;

  if (typeof chrome === 'undefined' || typeof chrome.permissions === 'undefined') return;

  const performInjection = (broadGrantPresent: boolean): void => {
    const gate = isModeCaptureAllowed(url, settings, broadGrantPresent);
    if (!gate.allowed) return;

    if (broadGrantPresent) {
      if (typeof chrome.scripting !== 'undefined') {
        void chrome.scripting.executeScript({
          target: { tabId, frameIds: [0] },
          func: reportPageSignals,
        }).catch(() => undefined);
      }
      return;
    }

    chrome.permissions.contains({ origins: [`${origin}/*`] }, (permitted) => {
      if (!permitted) return;

      if (typeof chrome.scripting !== 'undefined') {
        void chrome.scripting.executeScript({
          target: { tabId, frameIds: [0] },
          func: reportPageSignals,
        }).catch(() => undefined);
      }
    });
  };

  if (typeof chrome.permissions.getAll === 'function') {
    const handlePerms = (perms?: chrome.permissions.Permissions): void => {
      const broad = (perms?.origins ?? []).some(isBroadGrant);
      performInjection(broad);
    };
    try {
      const res: unknown = chrome.permissions.getAll(handlePerms);
      if (
        typeof res === 'object' &&
        res !== null &&
        'then' in res &&
        typeof res.then === 'function'
      ) {
        void (res as Promise<chrome.permissions.Permissions>).then(handlePerms);
      }
    } catch {
      performInjection(false);
    }
  } else {
    performInjection(false);
  }
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