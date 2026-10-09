import { originFromUrl } from '../rules/utils';
import { reportPageSignals } from '../content/service-worker-detection';
import { isModeCaptureAllowed, isRestrictedUrl } from '../shared/gating';
import { SettingsService } from '../shared/settings';
import { isBroadGrant, hasAllSitesCoverage } from './permissions';
import { incognitoTabIds } from './capture';
import { getTabGeneration } from './generations';
import type { SettingsV2 } from '../shared/types';

export async function injectPageSignals(tabId: number, url: string): Promise<void> {
  if (incognitoTabIds.has(tabId)) return;
  if (isRestrictedUrl(url)) return;
  const origin = originFromUrl(url);
  if (origin === null || origin.length === 0) return;

  // Hydration barrier: await SettingsService readiness if not yet hydrated
  let settings: SettingsV2;
  if (!SettingsService.isReady()) {
    try {
      settings = await SettingsService.whenReady();
    } catch {
      return;
    }
  } else {
    settings = SettingsService.getCachedSettings();
  }

  // Re-verify current tab URL if tabs API is available
  if (typeof chrome !== 'undefined' && typeof chrome.tabs !== 'undefined' && typeof chrome.tabs.get === 'function') {
    try {
      const tab = await new Promise<chrome.tabs.Tab | null>((resolve) => {
        chrome.tabs.get(tabId, (t) => {
          if (chrome.runtime.lastError !== undefined || t === undefined || t === null) resolve(null);
          else resolve(t);
        });
      });
      if (tab?.url !== undefined && tab.url !== '' && tab.url !== url) {
        return;
      }
    } catch {
      // Continue if tabs.get fails or not available
    }
  }

  if (settings.monitoringMode === 'off') return;

  const performInjection = (broadGrantPresent: boolean, hasCompleteCoverage: boolean): void => {
    const gate = isModeCaptureAllowed(url, settings, broadGrantPresent, undefined, hasCompleteCoverage);
    if (!gate.allowed) return;

    if (settings.monitoringMode === 'all-sites') {
      if (hasCompleteCoverage) {
        if (typeof chrome.scripting !== 'undefined') {
          void chrome.scripting.executeScript({
            target: { tabId, frameIds: [0] },
            func: reportPageSignals,
            args: [getTabGeneration(tabId)],
          }).catch(() => undefined);
        }
      }
      return;
    }

    if (broadGrantPresent) {
      return;
    }

    chrome.permissions.contains({ origins: [`${origin}/*`] }, (permitted) => {
      if (!permitted) return;

      if (typeof chrome.scripting !== 'undefined') {
        void chrome.scripting.executeScript({
          target: { tabId, frameIds: [0] },
          func: reportPageSignals,
          args: [getTabGeneration(tabId)],
        }).catch(() => undefined);
      }
    });
  };

  if (typeof chrome.permissions.getAll === 'function') {
    const handlePerms = (perms?: chrome.permissions.Permissions): void => {
      const origins = perms?.origins ?? [];
      const broad = origins.some(isBroadGrant);
      const complete = hasAllSitesCoverage(origins);
      performInjection(broad, complete);
    };
    try {
      const res: unknown = chrome.permissions.getAll(handlePerms);
      if (
        typeof res === 'object' &&
        res !== null &&
        'then' in res &&
        typeof (res as Promise<chrome.permissions.Permissions>).then === 'function'
      ) {
        void (res as Promise<chrome.permissions.Permissions>).then(handlePerms);
      }
    } catch {
      performInjection(false, false);
    }
  } else {
    performInjection(false, false);
  }
}

export function registerPageSignalInjection(): void {
  chrome.webNavigation.onCommitted.addListener((details): void => {
    if (details.frameId !== 0 || details.tabId < 0) return;
    void injectPageSignals(details.tabId, details.url);
  });

  chrome.webNavigation.onHistoryStateUpdated.addListener((details): void => {
    if (details.frameId !== 0 || details.tabId < 0) return;
    void injectPageSignals(details.tabId, details.url);
  });
}
