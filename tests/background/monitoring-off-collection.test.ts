import { describe, it, expect, beforeEach, vi } from 'vitest';
import { canCollectForTab } from '../../src/background/capture-policy';
import { handleDomLeadsCollected, handleMainWorldEvent } from '../../src/background/leads-handler';
import { globalLeadStore } from '../../src/leads';
import { clearReconMemory, getReconMemory } from '../../src/leads/store/recon-store';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import type { SettingsV2 } from '../../src/shared/types';
import type { DomLeadsCollectedMessage, MainWorldLeadsEventMessage } from '../../src/shared/messaging';
import { setTabGeneration, clearTabGenerations } from '../../src/background/generations';
import { incognitoTabIds } from '../../src/background/capture';

describe('P0 — Monitoring Off & Capture Policy Sensor Collection Gate', () => {
  beforeEach(async () => {
    await clearReconMemory();
    globalLeadStore.clearAll();
    clearTabGenerations();
    incognitoTabIds.clear();
    vi.clearAllMocks();
  });

  const baseSettings: SettingsV2 = {
    ...DEFAULT_SETTINGS,
    monitoringMode: 'all-sites',
    leadsEnabled: true,
    deepModeEnabled: true,
  };

  const validSnapshot = {
    ready: true,
    revision: 1,
    mode: 'all-sites' as const,
    broadGrantActive: true,
    grantedOrigins: new Set<string>(),
  };

  describe('canCollectForTab authoritative policy', () => {
    it('returns false when monitoring mode is off, even if permissions are granted and leads are enabled', () => {
      const offSettings: SettingsV2 = {
        ...baseSettings,
        monitoringMode: 'off',
      };
      const offSnapshot = {
        ...validSnapshot,
        mode: 'off' as const,
      };

      const result = canCollectForTab(101, 'https://example.com/app', {
        settings: offSettings,
        snapshot: offSnapshot,
      });

      expect(result).toBe(false);
    });

    it('returns false when leadsEnabled is false', () => {
      const noLeadsSettings: SettingsV2 = {
        ...baseSettings,
        leadsEnabled: false,
      };

      const result = canCollectForTab(101, 'https://example.com/app', {
        settings: noLeadsSettings,
        snapshot: validSnapshot,
      });

      expect(result).toBe(false);
    });

    it('returns false when tab is incognito', () => {
      incognitoTabIds.add(102);

      const result = canCollectForTab(102, 'https://example.com/app', {
        settings: baseSettings,
        snapshot: validSnapshot,
      });

      expect(result).toBe(false);
    });

    it('returns false when generation is stale', () => {
      setTabGeneration(103, 5);

      const result = canCollectForTab(103, 'https://example.com/app', {
        settings: baseSettings,
        snapshot: validSnapshot,
        generation: 4, // stale arrival
      });

      expect(result).toBe(false);
    });

    it('returns false when target is out-of-scope under active scope profile', () => {
      const scopedSettings: SettingsV2 = {
        ...baseSettings,
        activeScopeProfileId: 'target-prof',
        scopeProfiles: [
          {
            id: 'target-prof',
            name: 'Target Only',
            rules: [
              { pattern: 'in-scope.com', type: 'include' },
              { pattern: 'out-of-scope.com', type: 'exclude' },
            ],
          },
        ],
      };

      const result = canCollectForTab(104, 'https://out-of-scope.com/page', {
        settings: scopedSettings,
        snapshot: validSnapshot,
      });

      expect(result).toBe(false);
    });

    it('returns true when monitoring is active, permitted, in-scope, non-incognito, and generation is current', () => {
      setTabGeneration(105, 2);

      const result = canCollectForTab(105, 'https://example.com/app', {
        settings: baseSettings,
        snapshot: validSnapshot,
        generation: 2,
      });

      expect(result).toBe(true);
    });
  });

  describe('handleDomLeadsCollected fail-closed enforcement when monitoring is Off', () => {
    it('rejects late or stale DOM collection when monitoring is Off, producing 0 leads and 0 recon records', async () => {
      const offSettings: SettingsV2 = {
        ...baseSettings,
        monitoringMode: 'off',
      };

      const msg: DomLeadsCollectedMessage = {
        type: 'DOM_LEADS_COLLECTED',
        tabId: 201,
        url: 'https://example.com/login',
        origin: 'https://example.com',
        data: {
          forms: [{ action: '/login', method: 'POST', inputNames: ['username', 'password'] }],
          iframes: [],
          scripts: [{ src: 'https://example.com/app.js', inlineContent: 'const secret = "AKIA1111111111111111";' }],
          links: [{ href: 'https://example.com/api/v1/user?id=123' }],
          metaTags: [],
          comments: [],
          hydrationGlobals: {},
          resourceTiming: [],
          storageKeyNames: { localStorage: ['auth_token'], sessionStorage: [] },
        },
      };

      const state = await handleDomLeadsCollected(msg, offSettings);

      expect(state.leads).toHaveLength(0);
      expect(state.stats?.total).toBe(0);
      expect(globalLeadStore.getLeadsForTab(201, 'https://example.com')).toHaveLength(0);

      const recon = await getReconMemory();
      expect(recon.endpoints).toHaveLength(0);
      expect(recon.params).toHaveLength(0);
    });
  });

  describe('handleMainWorldEvent fail-closed enforcement when monitoring is Off', () => {
    it('rejects S3 events when monitoring is Off, producing 0 leads', () => {
      const offSettings: SettingsV2 = {
        ...baseSettings,
        monitoringMode: 'off',
      };

      const msg: MainWorldLeadsEventMessage = {
        type: 'MAIN_WORLD_LEADS_EVENT',
        tabId: 301,
        url: 'https://example.com/dashboard',
        origin: 'https://example.com',
        event: {
          eventType: 'sink',
          sinkName: 'eval',
          sourceCategory: 'network',
          details: 'eval(data)',
        },
      };

      const state = handleMainWorldEvent(msg, offSettings);

      expect(state.leads).toHaveLength(0);
      expect(globalLeadStore.getLeadsForTab(301, 'https://example.com')).toHaveLength(0);
    });
  });
});
