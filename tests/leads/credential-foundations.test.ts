import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SecretCandidateStore, globalSecretCandidateStore } from '../../src/background/secret-candidate-store';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';
import { LeadStore } from '../../src/leads/store/lead-store';
import type { Lead } from '../../src/leads/types';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import { migrateSettings } from '../../src/shared/settings';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';

describe('Credential Liveness Phase 1: Foundations & In-Memory Candidate Store', () => {
  let store: SecretCandidateStore;

  beforeEach(() => {
    store = new SecretCandidateStore();
    globalSecretCandidateStore.clear();
  });

  // ─── SecretCandidateStore ───────────────────────────────────────────────────

  describe('SecretCandidateStore', () => {
    it('stores and retrieves a candidate within TTL', () => {
      store.addCandidate('LEAD-1', 'github', 'ghp', 'ghp_123456789012345678901234567890123456');
      const candidate = store.getCandidate('LEAD-1');
      expect(candidate).toBeDefined();
      expect(candidate?.provider).toBe('github');
      expect(candidate?.tokenFamily).toBe('ghp');
      expect(candidate?.rawToken).toBe('ghp_123456789012345678901234567890123456');
    });

    it('expires candidate after 5-minute TTL', () => {
      const now = Date.now();
      vi.spyOn(Date, 'now').mockReturnValue(now);

      store.addCandidate('LEAD-TTL', 'stripe', 'sk_live', 'sk_live_123456789012345678901234');
      expect(store.getCandidate('LEAD-TTL')).toBeDefined();

      // Advance 5 minutes + 1 ms
      vi.spyOn(Date, 'now').mockReturnValue(now + 5 * 60 * 1000 + 1);
      expect(store.getCandidate('LEAD-TTL')).toBeUndefined();

      vi.restoreAllMocks();
    });

    it('consumes candidate exactly once; second call returns undefined', () => {
      store.addCandidate('LEAD-CONSUME', 'slack', 'xoxb', 'xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx');
      const first = store.consumeCandidate('LEAD-CONSUME');
      expect(first).toBeDefined();
      expect(first?.provider).toBe('slack');

      // One-use: both getCandidate and consumeCandidate must now return undefined
      expect(store.getCandidate('LEAD-CONSUME')).toBeUndefined();
      expect(store.consumeCandidate('LEAD-CONSUME')).toBeUndefined();
    });

    it('enforces capacity bound of 100 candidates by evicting oldest', () => {
      for (let i = 0; i < 110; i++) {
        store.addCandidate(`LEAD-${i}`, 'github', 'ghp', `ghp_${String(i).padStart(36, '0')}`);
      }
      expect(store.count()).toBeLessThanOrEqual(100);
      expect(store.getCandidate('LEAD-0')).toBeUndefined(); // evicted
      expect(store.getCandidate('LEAD-109')).toBeDefined(); // kept
    });

    it('clears all candidates on clear()', () => {
      store.addCandidate('LEAD-A', 'github', 'ghp', 'ghp_abc');
      store.addCandidate('LEAD-B', 'stripe', 'sk_live', 'sk_live_abc');
      store.clear();
      expect(store.count()).toBe(0);
      expect(store.getCandidate('LEAD-A')).toBeUndefined();
    });
  });

  // ─── f1-secrets candidate callback ─────────────────────────────────────────

  describe('f1-secrets candidate callback', () => {
    it('emits candidate via callback while keeping Lead preview strictly masked', () => {
      const candidates: Array<{ leadId: string; provider: string; tokenFamily: string; rawToken: string }> = [];
      const rawToken = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      const leads = detectSecrets(`const token = "${rawToken}";`, 'https://example.com/app.js', 'in-scope', (c) => {
        candidates.push(c);
      });

      const ghLead = leads.find((l) => l.tags.includes('github'));
      expect(ghLead).toBeDefined();

      // Lead preview must be masked — must not contain the raw token
      expect(ghLead?.evidence.preview).not.toBe(rawToken);
      expect(ghLead?.evidence.preview).toContain('...');
      expect(JSON.stringify(ghLead)).not.toContain(rawToken);

      // Callback must have received the raw value
      expect(candidates).toHaveLength(1);
      const first = candidates[0];
      expect(first).toBeDefined();
      expect(first?.leadId).toBe(ghLead?.id);
      expect(first?.provider).toBe('github');
      expect(first?.tokenFamily).toBe('ghp');
      expect(first?.rawToken).toBe(rawToken);
    });

    it('emits candidate for Stripe live secret key (sk_live_)', () => {
      const candidates: Array<{ leadId: string; provider: string; tokenFamily: string; rawToken: string }> = [];
      const rawToken = 'sk_live_abcdefghijklmnopqrstuvwxyz12';
      detectSecrets(`const key = "${rawToken}";`, 'https://example.com/app.js', 'in-scope', (c) => {
        candidates.push(c);
      });
      expect(candidates).toHaveLength(1);
      const first = candidates[0];
      expect(first).toBeDefined();
      expect(first?.provider).toBe('stripe');
      expect(first?.tokenFamily).toBe('sk_live');
      expect(first?.rawToken).toBe(rawToken);
    });

    it('emits candidate for Stripe test secret key (sk_test_) and restricted test key (rk_test_)', () => {
      const candidates: Array<{ leadId: string; provider: string; tokenFamily: string; rawToken: string }> = [];
      const code = [
        'const testKey = "sk_test_abcdefghijklmnopqrstuvwxyz12";',
        'const rkKey = "rk_test_abcdefghijklmnopqrstuvwxyz12";',
      ].join('\n');
      const leads = detectSecrets(code, 'https://example.com/app.js', 'in-scope', (c) => {
        candidates.push(c);
      });
      expect(candidates).toHaveLength(2);
      expect(candidates[0]?.tokenFamily).toBe('sk_test');
      expect(candidates[1]?.tokenFamily).toBe('rk_test');
      expect(leads.some((l) => l.title === 'Stripe Test Secret Key Exposure')).toBe(true);
      expect(leads.every((l) => l.potential === 'medium')).toBe(true);
    });

    it('emits candidate for xoxb (bot) and xoxp (user) Slack tokens; not xoxs (app-level)', () => {
      const candidates: Array<{ leadId: string; provider: string; tokenFamily: string; rawToken: string }> = [];
      const code = [
        'const bot  = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx";',
        'const user = "xoxp-123456789012-123456789012-abcdefghijklmnopqrstuvwx";',
        'const app  = "xoxs-123456789012-123456789012-abcdefghijklmnopqrstuvwx";',
      ].join('\n');
      detectSecrets(code, 'https://example.com/app.js', 'in-scope', (c) => {
        candidates.push(c);
      });
      const families = candidates.map((c) => c.tokenFamily);
      expect(families).toContain('xoxb');
      expect(families).toContain('xoxp');
      expect(families).not.toContain('xoxs');
    });

    it('does not emit candidate for unsupported token types (GCP key)', () => {
      const candidates: Array<{ leadId: string; provider: string; tokenFamily: string; rawToken: string }> = [];
      const gcpKey = 'AIzaSyD-7abcdef1234567890abcdef12345678';
      const leads = detectSecrets(
        `const gcpKey = "${gcpKey}";`,
        'https://example.com/app.js',
        'in-scope',
        (c) => { candidates.push(c); },
      );
      expect(leads.length).toBeGreaterThan(0); // lead still generated
      expect(candidates).toHaveLength(0);        // no candidate callback
    });

    it('backward compatible: no throw when callback is omitted', () => {
      expect(() => {
        const leads = detectSecrets(
          'const t = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";',
          'https://example.com/app.js',
          'in-scope',
        );
        expect(leads.length).toBeGreaterThan(0);
      }).not.toThrow();
    });
  });

  // ─── LeadStore credentialCheck sanitization ─────────────────────────────────

  describe('LeadStore credentialCheck sanitization & deduplication', () => {
    it('stores credentialCheck and strips forbidden raw payload fields', () => {
      const leadStore = new LeadStore();
      const rawLead: Lead = {
        id: 'LD-CRED-1',
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 0.95,
        title: 'GitHub Secret',
        needs: [],
        doesNotProve: [],
        evidence: {
          preview: maskSecret('ghp_123456789012345678901234567890123456'),
          location: maskLocation('https://example.com/app.js'),
        },
        tags: ['github'],
        scopeStatus: 'in-scope',
        timestamp: 1700000000000,
        origin: 'https://example.com',
        url: 'https://example.com/app.js',
        sourceSensor: 'S2',
        credentialCheck: {
          status: 'active_at_check',
          provider: 'github',
          tokenFamily: 'ghp',
          checkedAt: 1700000000000,
          details: 'Provider accepted at check time.',
          // @ts-expect-error intentional: forbidden field injection test
          rawToken: 'FORBIDDEN_LEAK',
        },
      };

      const addedId = leadStore.addLead(rawLead);
      expect(addedId).toBe('LD-CRED-1');

      const stored = leadStore.getLead('LD-CRED-1');
      expect(stored?.credentialCheck?.status).toBe('active_at_check');
      expect(stored?.credentialCheck?.provider).toBe('github');
      // Forbidden field must be absent
      expect((stored?.credentialCheck as unknown as Record<string, unknown>).rawToken).toBeUndefined();
    });

    it('addLead returns surviving leadId on deduplication, not the discarded incoming id', () => {
      const leadStore = new LeadStore();
      const base: Lead = {
        id: 'LD-FIRST',
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 0.9,
        title: 'Secret',
        needs: [],
        doesNotProve: [],
        evidence: {
          preview: maskSecret('sk_live_123456789012345678901234'),
          location: maskLocation('https://example.com/a.js'),
        },
        tags: ['stripe'],
        scopeStatus: 'in-scope',
        timestamp: 1000,
        origin: 'https://example.com',
        url: 'https://example.com/a.js',
        sourceSensor: 'S2',
      };

      expect(leadStore.addLead(base)).toBe('LD-FIRST');
      // Duplicate with a different ID
      expect(leadStore.addLead({ ...base, id: 'LD-DUPE', timestamp: 2000 })).toBe('LD-FIRST');
    });

    it('addLead returns undefined for out-of-scope leads', () => {
      const leadStore = new LeadStore();
      const oos: Lead = {
        id: 'LD-OOS',
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 0.9,
        title: 'OOS Secret',
        needs: [],
        doesNotProve: [],
        evidence: {
          preview: maskSecret('sk_live_123456789012345678901234'),
          location: maskLocation('https://other.com/a.js'),
        },
        tags: ['stripe'],
        scopeStatus: 'out-of-scope',
        timestamp: 1000,
        origin: 'https://other.com',
        url: 'https://other.com/a.js',
        sourceSensor: 'S2',
      };
      expect(leadStore.addLead(oos)).toBeUndefined();
    });
  });

  // ─── Settings schema ────────────────────────────────────────────────────────

  describe('Settings credentialLivenessEnabled schema', () => {
    it('defaults credentialLivenessEnabled to false', () => {
      expect(DEFAULT_SETTINGS.credentialLivenessEnabled).toBe(false);
      expect(migrateSettings({}).credentialLivenessEnabled).toBe(false);
    });

    it('preserves credentialLivenessEnabled when explicitly set to true', () => {
      expect(migrateSettings({ credentialLivenessEnabled: true }).credentialLivenessEnabled).toBe(true);
    });
  });
});
