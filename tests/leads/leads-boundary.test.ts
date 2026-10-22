import { describe, it, expect, beforeEach } from 'vitest';
import {
  recordParam,
  recordEndpoint,
  recordBucket,
  getReconMemory,
  clearReconMemory,
} from '../../src/leads/store/recon-store';
import { handleDomLeadsCollected, handleDevToolsLeads } from '../../src/background/leads-handler';
import { globalLeadStore } from '../../src/leads';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import type { SettingsV2 } from '../../src/shared/types';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import type { DomLeadsCollectedMessage } from '../../src/shared/messaging';

describe('Leads Boundary, Scope Isolation & Recon Store Gates', () => {
  beforeEach(async () => {
    await clearReconMemory();
    globalLeadStore.clearAll();
  });

  describe('ReconStore Scope Gates', () => {
    it('rejects out-of-scope parameters from persistent recon memory', async () => {
      await recordParam({
        name: 'token',
        origin: 'https://out-of-scope.com',
        contexts: ['query'],
        scopeStatus: 'out-of-scope',
      });

      const mem = await getReconMemory();
      expect(mem.params.find((p) => p.name === 'token')).toBeUndefined();
    });

    it('accepts in-scope parameters into recon memory', async () => {
      await recordParam({
        name: 'user_id',
        origin: 'https://in-scope.com',
        contexts: ['query'],
        scopeStatus: 'in-scope',
      });

      const mem = await getReconMemory();
      expect(mem.params.find((p) => p.name === 'user_id')).toBeDefined();
    });

    it('rejects out-of-scope endpoints from persistent recon memory', async () => {
      await recordEndpoint({
        path: '/admin/keys',
        origin: 'https://out-of-scope.com',
        tags: ['script-harvested'],
        scopeStatus: 'out-of-scope',
      });

      const mem = await getReconMemory();
      expect(mem.endpoints.find((e) => e.path === '/admin/keys')).toBeUndefined();
    });

    it('accepts in-scope endpoints into recon memory', async () => {
      await recordEndpoint({
        path: '/api/v1/auth',
        origin: 'https://in-scope.com',
        tags: ['script-harvested'],
        scopeStatus: 'in-scope',
      });

      const mem = await getReconMemory();
      expect(mem.endpoints.find((e) => e.path === '/api/v1/auth')).toBeDefined();
    });

    it('rejects out-of-scope cloud buckets from persistent recon memory', async () => {
      await recordBucket({
        bucket: 'secret-backup-bucket',
        provider: 'aws',
        origin: 'https://out-of-scope.com',
        scopeStatus: 'out-of-scope',
      });

      const mem = await getReconMemory();
      expect(mem.buckets.find((b) => b.bucket === 'secret-backup-bucket')).toBeUndefined();
    });

    it('accepts in-scope cloud buckets into recon memory', async () => {
      await recordBucket({
        bucket: 'public-assets-bucket',
        provider: 'aws',
        origin: 'https://in-scope.com',
        scopeStatus: 'in-scope',
      });

      const mem = await getReconMemory();
      expect(mem.buckets.find((b) => b.bucket === 'public-assets-bucket')).toBeDefined();
    });
  });

  describe('External Resource Scope Independence in DOM Leads Collector', () => {
    const mockSettings: SettingsV2 = {
      ...DEFAULT_SETTINGS,
      monitoringMode: 'per-site',
      leadsEnabled: true,
      scopeProfiles: [
        {
          id: 'prof-1',
          name: 'Target Program',
          rules: [
            { pattern: 'target.com', type: 'include' },
            { pattern: 'untrusted-cdn.com', type: 'exclude' },
          ],
        },
      ],
      activeScopeProfileId: 'prof-1',
    };

    it('evaluates external script with its own scope status, rejecting out-of-scope secrets and endpoints', async () => {
      const msg: DomLeadsCollectedMessage = {
        type: 'DOM_LEADS_COLLECTED',
        tabId: 101,
        url: 'https://target.com/app',
        origin: 'https://target.com',
        data: {
          forms: [],
          iframes: [],
          scripts: [
            {
              src: 'https://untrusted-cdn.com/vendor.js',
              inlineContent: 'const aws_secret = "AKIAIOSFODNN7EXAMPLE"; fetch("/cdn-admin/secret");',
            },
          ],
          links: [],
          metaTags: [],
          comments: [],
          hydrationGlobals: {},
          resourceTiming: [],
          storageKeyNames: { localStorage: [], sessionStorage: [] },
        },
      };

      const result = await handleDomLeadsCollected(msg, mockSettings);

      // The external script is out-of-scope, so its leads should not be added to active leads
      const vendorLeads = result.leads.filter((l) => l.url.includes('untrusted-cdn.com'));
      expect(vendorLeads).toHaveLength(0);

      // Endpoints from out-of-scope script must not be stored in recon memory
      const mem = await getReconMemory();
      expect(mem.endpoints.find((e) => e.path.includes('cdn-admin'))).toBeUndefined();
    });
  });

  describe('DevTools S4 Leads Validation', () => {
    it('accepts properly formatted DevTools leads and correlates chains', () => {
      const validLeads = [
        {
          id: 'LD-TEST-01',
          ruleId: 'SEC-001',
          family: 'F1' as const,
          tier: 'observed' as const,
          potential: 'critical' as const,
          confidence: 1.0,
          title: 'Exposed API Token in response body',
          needs: [],
          doesNotProve: [],
          evidence: {
            preview: maskSecret('token=secret_val_1234567890abcdef'),
            location: maskLocation('https://target.com/api/user'),
          },
          tags: ['secret', 'api'],
          scopeStatus: 'in-scope' as const,
          timestamp: Date.now(),
          origin: 'https://target.com',
          url: 'https://target.com/api/user',
          sourceSensor: 'S4' as const,
        },
      ];

      const res = handleDevToolsLeads(validLeads, 10);
      expect(res.leads).toHaveLength(1);
      expect(res.stats?.critical).toBe(1);
    });
  });
});
