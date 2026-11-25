/**
 * @file navigation-reset.test.ts
 * Regression tests for P1: Stop tab-associated findings leaking across top-level navigations.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { LeadStore, globalLeadStore } from '../../src/leads/store/lead-store';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import { getLeadsState } from '../../src/background/leads-handler';
import type { Lead } from '../../src/leads/types';

function makeLead(overrides: Partial<Lead>): Lead {
  return {
    id: `LD-TEST-${Math.random().toString(36).slice(2, 8)}`,
    ruleId: 'SEC-001',
    family: 'F1',
    tier: 'observed',
    potential: 'high',
    confidence: 0.9,
    title: 'Synthetic Secret Token',
    needs: ['confirm credential liveness'],
    doesNotProve: ['provider validity'],
    evidence: {
      preview: maskSecret('ghp_0123***wxyz'),
      location: maskLocation('http://127.0.0.1:3489/lead-lab/credential-setting'),
    },
    tags: ['secret'],
    scopeStatus: 'in-scope',
    timestamp: Date.now(),
    origin: 'http://127.0.0.1:3489',
    url: 'http://127.0.0.1:3489/lead-lab/credential-setting',
    sourceSensor: 'S2',
    ...overrides,
  };
}

describe('P1 Navigation Reset & Tab-to-Lead Isolation', () => {
  beforeEach(() => {
    globalLeadStore.clearAll();
  });

  it('clears origin A lead from getLeadsState(tabId, originB) after committed navigation while preserving origin A history', () => {
    const store = new LeadStore();
    const tabId = 42;
    const originA = 'http://127.0.0.1:3489';
    const originB = 'https://example.com';

    const leadA = makeLead({
      id: 'LD-LOC-1',
      origin: originA,
      url: `${originA}/lead-lab/credential-setting`,
      triageState: 'triaged',
      pinned: true,
    });

    store.addLead(leadA, tabId, 1);
    expect(store.getLeadsForTab(tabId, originA).map((l) => l.id)).toContain('LD-LOC-1');

    // Simulate committed top-level navigation to origin B (generation advances 1 -> 2)
    store.clearTabAssociations(tabId, 2);

    // Tab query for origin B must NOT leak origin A's lead
    const tabLeadsOnB = store.getLeadsForTab(tabId, originB);
    expect(tabLeadsOnB.map((l) => l.id)).not.toContain('LD-LOC-1');
    expect(tabLeadsOnB).toHaveLength(0);

    // Underlying origin A history & triage state must remain intact
    const originAHistory = store.getLeadsForOrigin(originA);
    expect(originAHistory).toHaveLength(1);
    expect(originAHistory[0]?.id).toBe('LD-LOC-1');
    expect(originAHistory[0]?.triageState).toBe('triaged');
    expect(originAHistory[0]?.pinned).toBe(true);

    // A genuinely fresh tab on origin B also sees zero leads from origin A
    const freshTabLeadsOnB = store.getLeadsForTab(99, originB);
    expect(freshTabLeadsOnB).toHaveLength(0);
  });

  it('integrates with getLeadsState and preserves cross-origin resource leads discovered on origin B', () => {
    const tabId = 7;
    const originA = 'http://127.0.0.1:3489';
    const originB = 'https://example.com';

    globalLeadStore.addLead(
      makeLead({
        id: 'LD-SEC-LOCAL',
        origin: originA,
        url: `${originA}/fixture`,
      }),
      tabId,
      1,
    );

    expect(getLeadsState(tabId, originA).leads.map((l) => l.id)).toContain('LD-SEC-LOCAL');

    // Committed navigation on tab 7 (generation 2): header lead already arrived at gen 2 before onCommitted runs
    const headerOnB = makeLead({
      id: 'LD-HDR-B',
      ruleId: 'CSP-101',
      family: 'F6',
      origin: originB,
      url: `${originB}/`,
      evidence: {
        preview: maskSecret('csp-allowlist'),
        location: maskLocation(`${originB}/`),
      },
    });
    globalLeadStore.addLead(headerOnB, tabId, 2);

    // Clear stale gen 1 links while preserving gen 2 links
    globalLeadStore.clearTabAssociations(tabId, 2);

    // Now discover a cross-origin resource lead while on origin B (e.g. external S3 bucket)
    const crossOriginAssetOnB = makeLead({
      id: 'LD-CLD-B',
      ruleId: 'CLD-001',
      family: 'F8',
      origin: 'https://assets-bucket.s3.amazonaws.com',
      url: 'https://assets-bucket.s3.amazonaws.com/bundle.js',
      evidence: {
        preview: maskSecret('assets-bucket.s3.amazonaws.com'),
        location: maskLocation(`${originB}/index.html`),
      },
    });
    globalLeadStore.addLead(crossOriginAssetOnB, tabId, 2);

    const stateOnB = getLeadsState(tabId, originB);
    const idsOnB = stateOnB.leads.map((l) => l.id);

    // Prior localhost lead is gone; current-page header and cross-origin asset observed on B are present
    expect(idsOnB).not.toContain('LD-SEC-LOCAL');
    expect(idsOnB).toContain('LD-HDR-B');
    expect(idsOnB).toContain('LD-CLD-B');
  });

  it('handles same-origin navigation/reload without erasing persistent origin records', () => {
    const store = new LeadStore();
    const tabId = 15;
    const origin = 'https://app.example.com';

    store.addLead(
      makeLead({
        id: 'LD-APP-1',
        origin,
        url: `${origin}/page1`,
        evidence: {
          preview: maskSecret('key_1'),
          location: maskLocation(`${origin}/page1`),
        },
      }),
      tabId,
      1,
    );

    // Reload or navigate within same origin
    store.clearTabAssociations(tabId);

    // Persistent origin history remains available for that origin
    expect(store.getLeadsForOrigin(origin).map((l) => l.id)).toContain('LD-APP-1');
    expect(store.getLeadsForTab(tabId, origin).map((l) => l.id)).toContain('LD-APP-1');
  });

  it('handles tab closure/ID reuse and session persistence across worker restarts', async () => {
    const storeMap = new Map<string, unknown>();
    vi.stubGlobal('chrome', {
      storage: {
        session: {
          get: vi.fn((keys: string[]) => {
            const out: Record<string, unknown> = {};
            for (const k of keys) out[k] = storeMap.get(k);
            return Promise.resolve(out);
          }),
          set: vi.fn((obj: Record<string, unknown>) => {
            for (const [k, v] of Object.entries(obj)) storeMap.set(k, v);
            return Promise.resolve();
          }),
          remove: vi.fn((keys: string[]) => {
            for (const k of keys) storeMap.delete(k);
            return Promise.resolve();
          }),
        },
      },
    });

    try {
      const store1 = new LeadStore();
      await store1.init();

      const tabId = 55;
      store1.addLead(
        makeLead({
          id: 'LD-TAB-OLD',
          origin: 'https://old.example',
          url: 'https://old.example/',
          evidence: {
            preview: maskSecret('old_tok'),
            location: maskLocation('https://old.example/app.js'),
          },
        }),
        tabId,
        1,
      );

      // Tab closes -> clearTabAssociations removes tab link
      store1.clearTabAssociations(tabId);

      // Reused tabId opens new site with gen 2 lead
      store1.addLead(
        makeLead({
          id: 'LD-TAB-NEW',
          origin: 'https://new.example',
          url: 'https://new.example/',
          evidence: {
            preview: maskSecret('new_tok'),
            location: maskLocation('https://new.example/app.js'),
          },
        }),
        tabId,
        2,
      );

      // Flush debounced session save
      await new Promise((r) => setTimeout(r, 200));

      // Simulate service worker restart into fresh LeadStore instance
      const store2 = new LeadStore();
      await store2.init();

      const restoredNew = store2.getLeadsForTab(tabId, 'https://new.example').map((l) => l.id);
      expect(restoredNew).toContain('LD-TAB-NEW');
      expect(restoredNew).not.toContain('LD-TAB-OLD');
      expect(store2.getLeadsForOrigin('https://old.example').map((l) => l.id)).toContain('LD-TAB-OLD');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
