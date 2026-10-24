import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  initDomCollector,
  resetDomCollectorForTesting,
} from '../../src/content/dom-collector';
import {
  handleMainWorldEvent,
  resetMainWorldCountForTab,
  globalLeadStore,
} from '../../src/background/leads-handler';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import type { MainWorldLeadsEventMessage } from '../../src/shared/messaging';

describe('S3 Event Trust Boundary & Schema Validation', () => {
  let sentMessages: unknown[] = [];
  let listeners: Record<string, Array<(e: Event) => void>> = {};

  beforeEach(() => {
    sentMessages = [];
    listeners = {};
    resetDomCollectorForTesting();
    resetMainWorldCountForTab(101);
    globalLeadStore.clearAll();

    const windowMock = {
      addEventListener: vi.fn((name: string, fn: (e: Event) => void) => {
        listeners[name] = listeners[name] || [];
        listeners[name].push(fn);
      }),
      dispatchEvent: vi.fn((event: Event) => {
        for (const fn of listeners[event.type] || []) {
          fn(event);
        }
      }),
      location: {
        href: 'https://example.com/app',
        origin: 'https://example.com',
      },
    };

    vi.stubGlobal('window', windowMock);
    vi.stubGlobal('location', windowMock.location);
    vi.stubGlobal('document', {
      querySelectorAll: vi.fn(() => []),
      documentElement: { getAttribute: vi.fn(() => null) },
      body: { getAttribute: vi.fn(() => null) },
    });

    // Mock chrome.runtime.sendMessage
    const chromeMock = {
      runtime: {
        sendMessage: vi.fn((msg: unknown) => {
          sentMessages.push(msg);
          return Promise.resolve();
        }),
        onMessage: {
          addListener: vi.fn(),
        },
      },
    };
    vi.stubGlobal('chrome', chromeMock);

    // Mock CustomEvent
    class MockCustomEvent {
      type: string;
      detail: unknown;
      constructor(type: string, dict?: { detail?: unknown }) {
        this.type = type;
        this.detail = dict?.detail;
      }
    }
    vi.stubGlobal('CustomEvent', MockCustomEvent);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('validates schema, extracts safe fields, and drops raw page canaries through actual collector listener', () => {
    initDomCollector();

    const canarySecret = 'CANARY_S3_SECRET_VAL_777';
    // Simulate forged or page-dispatched CustomEvent with forbidden extra properties and raw canary
    const detail = {
      eventType: 'sink',
      sinkName: 'Element.innerHTML',
      sourceCategory: 'location.hash',
      sourceValue: canarySecret, // Raw canary property that must be completely ignored/dropped
      arbitraryPageField: 'MALICIOUS_PAYLOAD',
      details: 'Sink executed',
    };

    window.dispatchEvent(new CustomEvent('__ACULYX_MAIN_WORLD_EVENT__', { detail }));

    expect(sentMessages.length).toBe(1);
    const sent = sentMessages[0] as MainWorldLeadsEventMessage;
    expect(sent.type).toBe('MAIN_WORLD_LEADS_EVENT');
    expect((sent.event as Record<string, unknown>).sourceValue).toBeUndefined();
    expect((sent.event as Record<string, unknown>).arbitraryPageField).toBeUndefined();
    expect(JSON.stringify(sent)).not.toContain(canarySecret);
    expect(sent.event.sinkName).toBe('Element.innerHTML');
    expect(sent.event.sourceCategory).toBe('location.hash');
  });

  it('rejects events with unwhitelisted sink names or invalid source categories', () => {
    initDomCollector();

    // Invalid sink name
    window.dispatchEvent(new CustomEvent('__ACULYX_MAIN_WORLD_EVENT__', {
      detail: {
        eventType: 'sink',
        sinkName: 'MaliciousCustomSink',
        sourceCategory: 'location.hash',
      },
    }));

    // Invalid source category
    window.dispatchEvent(new CustomEvent('__ACULYX_MAIN_WORLD_EVENT__', {
      detail: {
        eventType: 'sink',
        sinkName: 'Element.innerHTML',
        sourceCategory: 'attacker_untrusted_eval',
      },
    }));

    // Invalid eventType
    window.dispatchEvent(new CustomEvent('__ACULYX_MAIN_WORLD_EVENT__', {
      detail: {
        eventType: 'grant_admin_scope',
      },
    }));

    // None of these invalid events should have dispatched chrome.runtime.sendMessage
    expect(sentMessages.length).toBe(0);
  });

  it('enforces strict rate limits per-type and total on relayed DOM events', () => {
    initDomCollector();

    // Dispatch 40 sink events (limit is 25 per type)
    for (let i = 0; i < 40; i++) {
      window.dispatchEvent(new CustomEvent('__ACULYX_MAIN_WORLD_EVENT__', {
        detail: {
          eventType: 'sink',
          sinkName: 'Element.innerHTML',
          sourceCategory: 'location.search',
        },
      }));
    }

    // Should be clamped at MAX_EVENTS_PER_TYPE (25)
    expect(sentMessages.length).toBe(25);
  });

  it('ensures forged-but-well-formed events only produce labelled, weak/whisper page-reported leads without granting scope or modifying score', () => {
    const msg: MainWorldLeadsEventMessage = {
      type: 'MAIN_WORLD_LEADS_EVENT',
      url: 'https://example.com/app',
      origin: 'https://example.com',
      tabId: 101,
      event: {
        eventType: 'sink',
        sinkName: 'Element.innerHTML',
        sourceCategory: 'location.hash',
        details: 'Assigned to Element.innerHTML',
      },
    };

    const res = handleMainWorldEvent(msg, DEFAULT_SETTINGS);
    const s3Lead = res.leads.find(l => l.sourceSensor === 'S3');
    expect(s3Lead).toBeDefined();
    expect(s3Lead?.title).toContain('[Page-Reported]');
    expect(s3Lead?.tags).toContain('page-reported');
    expect(['weak', 'whisper']).toContain(s3Lead?.tier);

    // Verify it does not grant permissions or escalate potential beyond medium
    expect(['low', 'medium', 'info']).toContain(s3Lead?.potential);
    expect(s3Lead?.potential).not.toBe('critical');
  });

  it('rejects forged events with invalid sourceCategory or unwhitelisted eventType on background boundary', () => {
    const badCategoryMsg: MainWorldLeadsEventMessage = {
      type: 'MAIN_WORLD_LEADS_EVENT',
      url: 'https://example.com/app',
      origin: 'https://example.com',
      tabId: 101,
      event: {
        eventType: 'sink',
        sinkName: 'Element.innerHTML',
        sourceCategory: 'attacker_crafted_category',
      },
    };
    const resBadCat = handleMainWorldEvent(badCategoryMsg, DEFAULT_SETTINGS);
    expect(resBadCat.leads.filter(l => l.sourceSensor === 'S3' && l.ruleId === 'PAR-004')).toHaveLength(0);

    const badTypeMsg: MainWorldLeadsEventMessage = {
      type: 'MAIN_WORLD_LEADS_EVENT',
      url: 'https://example.com/app',
      origin: 'https://example.com',
      tabId: 101,
      event: {
        eventType: 'admin_escalate' as unknown as MainWorldLeadsEventMessage['event']['eventType'],
      },
    };
    const resBadType = handleMainWorldEvent(badTypeMsg, DEFAULT_SETTINGS);
    expect(resBadType.leads.filter(l => l.sourceSensor === 'S3')).toHaveLength(0);
  });
});
