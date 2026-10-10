/**
 * leads-handler.ts
 *
 * Coordinates Lead Radar sensors (S1 WebRequest, S2 DOM Collector, S3 Main-World Hooks, S4 DevTools),
 * evaluates detector rules (F1-F8), runs vulnerability chains (CH-001..CH-007),
 * computes ranking, and orchestrates LeadStore & ReconStore persistence.
 */

import {
  LeadStore,
  recordHost,
  recordParam,
  recordEndpoint,
  recordBucket,
} from '../leads';
import { detectSecrets } from '../leads/detectors/f1-secrets';
import { detectEndpoints } from '../leads/detectors/f2-endpoints';
import { detectSourceMaps } from '../leads/detectors/f3-sourcemaps';
import { detectAuthLeads } from '../leads/detectors/f4-auth';
import { detectParamLeads, classifyParamName } from '../leads/detectors/f5-params';
import { detectReconLeads } from '../leads/detectors/f8-recon';
import { evaluateChains } from '../leads/chains/chains';
import { rankLeads } from '../leads/ranking/ranking';
import { executeHunterProbe } from '../leads/hunter/hunter';
import { maskSecret, maskLocation } from '../leads/sieve/mask';
import { ScopeEngine } from '../shared/scope/engine';
import type {
  Lead,
  HunterProbeRequest,
  HunterLedgerEntry,
  HunterConfig,
} from '../leads/types';
import type {
  DomLeadsCollectedMessage,
  MainWorldLeadsEventMessage,
  LeadStateUpdateMessage,
} from '../shared/messaging';
import type { SettingsV2 } from '../shared/types';

export const globalLeadStore = new LeadStore();

let leadCounter = 0;
function nextId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function resolveScopeStatus(
  targetUrl: string,
  settings: SettingsV2
): Lead['scopeStatus'] {
  if (
    typeof settings.activeScopeProfileId === 'string' &&
    settings.activeScopeProfileId.length > 0 &&
    settings.scopeProfiles !== undefined &&
    settings.scopeProfiles.length > 0
  ) {
    const profile = settings.scopeProfiles.find((p) => p.id === settings.activeScopeProfileId);
    if (profile !== undefined) {
      const engine = new ScopeEngine(profile);
      const res = engine.evaluate(targetUrl);
      return res.status;
    }
  }
  return 'unknown';
}

/**
 * S1: Sensor 1 parameter harvesting handler.
 * Called when URLs with query parameters are observed in WebRequest listeners.
 */
export async function handleParamHarvest(
  rawUrl: string,
  paramNames: string[],
  tabId?: number,
  settings?: SettingsV2
): Promise<void> {
  let origin = 'https://unknown';
  let hostname = 'unknown';
  try {
    const parsed = new URL(rawUrl);
    origin = parsed.origin;
    hostname = parsed.hostname;
  } catch {
    return;
  }

  const scopeStatus = settings ? resolveScopeStatus(rawUrl, settings) : 'unknown';

  // 1. Record Host in Recon
  await recordHost({
    hostname,
    scopeStatus,
    discoveredVia: 'query-param',
    firstSeen: Date.now(),
    lastSeen: Date.now(),
  });

  // 2. Record Parameters in Recon
  for (const name of paramNames) {
    const category = classifyParamName(name);
    await recordParam({
      name,
      category,
      origin,
      contexts: ['query'],
    });
  }

  // 3. Evaluate Parameter leads (PAR-002, etc.)
  const paramLeads = detectParamLeads(rawUrl, scopeStatus);
  for (const lead of paramLeads) {
    globalLeadStore.addLead(lead, tabId);
  }
}

/**
 * S2: Sensor 2 DOM collection handler.
 * Receives full client-side DOM collection payload from dom-collector content script.
 */
export async function handleDomLeadsCollected(
  msg: DomLeadsCollectedMessage,
  settings: SettingsV2
): Promise<LeadStateUpdateMessage> {
  const { url, origin, data, tabId } = msg;
  const scopeStatus = resolveScopeStatus(url, settings);

  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = origin;
  }

  // 1. Record main host in Recon
  await recordHost({
    hostname,
    scopeStatus,
    discoveredVia: 'dom-scan',
    firstSeen: Date.now(),
    lastSeen: Date.now(),
  });

  // 2. Analyze Forms
  if (data.forms !== undefined && data.forms.length > 0) {
    const authLeads = detectAuthLeads(
      {
        url,
        forms: data.forms.map((f) => ({
          action: f.action,
          method: f.method,
          inputs: f.inputNames.map((n) => ({ name: n })),
        })),
        storageKeys: data.storageKeyNames.localStorage,
      },
      scopeStatus
    );

    for (const lead of authLeads) {
      globalLeadStore.addLead(lead, tabId);
    }

    for (const f of data.forms) {
      if (typeof f.action === 'string' && f.action.length > 0) {
        const maskedAct = maskLocation(f.action);
        await recordEndpoint({
          path: maskedAct.length > 0 ? maskedAct : f.action,
          origin,
          method: f.method,
          tags: ['form'],
        });
      }
      for (const inputName of f.inputNames) {
        const cat = classifyParamName(inputName);
        await recordParam({
          name: inputName,
          category: cat,
          origin,
          contexts: ['form-input'],
        });
      }
    }
  }

  // 3. Analyze Scripts (Secrets, Endpoints, SourceMaps)
  if (data.scripts !== undefined && data.scripts.length > 0) {
    for (const script of data.scripts) {
      const scriptUrl = typeof script.src === 'string' && script.src.length > 0 ? script.src : url;

      if (typeof script.src === 'string' && script.src.length > 0) {
        try {
          const sHost = new URL(script.src).hostname;
          if (sHost !== hostname) {
            await recordHost({
              hostname: sHost,
              scopeStatus: resolveScopeStatus(script.src, settings),
              discoveredVia: 'script-src',
              firstSeen: Date.now(),
              lastSeen: Date.now(),
            });
          }
        } catch {
          // Ignore URL parse error
        }
      }

      if (typeof script.inlineContent === 'string' && script.inlineContent.length > 0) {
        // F1: Secrets
        const secretLeads = detectSecrets(script.inlineContent, scriptUrl, scopeStatus);
        for (const lead of secretLeads) {
          globalLeadStore.addLead(lead, tabId);
        }

        // F2: Endpoints
        const endpointLeads = detectEndpoints(script.inlineContent, scriptUrl, scopeStatus);
        for (const lead of endpointLeads) {
          globalLeadStore.addLead(lead, tabId);
          if (lead.evidence.extractedNames !== undefined) {
            for (const ep of lead.evidence.extractedNames) {
              await recordEndpoint({
                path: ep,
                origin,
                tags: ['script-harvested'],
              });
            }
          }
        }

        // F3: Source Maps
        const sourceMapLeads = detectSourceMaps(script.inlineContent, {}, scriptUrl, scopeStatus);
        for (const lead of sourceMapLeads) {
          globalLeadStore.addLead(lead, tabId);
        }
      }

      if (typeof script.sourceMappingURL === 'string' && script.sourceMappingURL.length > 0) {
        const maskedScriptUrl = maskLocation(scriptUrl);
        const smLead: Lead = {
          id: nextId('MAP-REF'),
          ruleId: 'MAP-001',
          family: 'F3',
          tier: 'observed',
          potential: 'low',
          confidence: 0.95,
          title: `JavaScript Source Map Reference Detected: ${script.sourceMappingURL}`,
          needs: ['fetch .map file to inspect original TypeScript/JavaScript source code'],
          doesNotProve: ['source map is accessible without authorization'],
          evidence: {
            preview: maskSecret(script.sourceMappingURL),
            location: maskLocation(scriptUrl),
            context: `Found sourceMappingURL in script tag`,
          },
          tags: ['sourcemap', 'source-code', 'recon'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url: maskedScriptUrl.length > 0 ? maskedScriptUrl : scriptUrl,
          sourceSensor: 'S2',
        };
        globalLeadStore.addLead(smLead, tabId);
      }
    }
  }

  // 4. Analyze Iframes (IFR-001)
  if (data.iframes !== undefined && data.iframes.length > 0) {
    for (const iframe of data.iframes) {
      if (typeof iframe.src === 'string' && iframe.src.length > 0) {
        try {
          const ifHost = new URL(iframe.src).hostname;
          if (ifHost !== hostname) {
            await recordHost({
              hostname: ifHost,
              scopeStatus: resolveScopeStatus(iframe.src, settings),
              discoveredVia: 'iframe-src',
              firstSeen: Date.now(),
              lastSeen: Date.now(),
            });
          }
        } catch {
          // Ignore
        }
      }

      const hasScripts = typeof iframe.sandbox === 'string' && iframe.sandbox.includes('allow-scripts');
      const hasSameOrigin = typeof iframe.sandbox === 'string' && iframe.sandbox.includes('allow-same-origin');
      if (iframe.sandbox === undefined || iframe.sandbox === '' || (hasScripts && hasSameOrigin)) {
        const maskedUrl = maskLocation(url);
        const iframeSrc = typeof iframe.src === 'string' && iframe.src.length > 0 ? iframe.src : 'inline';
        const ifrLead: Lead = {
          id: nextId('IFR-PERM'),
          ruleId: 'IFR-001',
          family: 'F8',
          tier: 'observed',
          potential: 'low',
          confidence: 0.85,
          title: `Iframe Embed Without Strict Sandbox Isolation (${iframeSrc})`,
          needs: ['verify whether embedded content is untrusted and can execute scripts'],
          doesNotProve: ['clickjacking or iframe escape'],
          evidence: {
            preview: maskSecret(iframeSrc),
            location: maskLocation(url),
            context: `sandbox="${typeof iframe.sandbox === 'string' ? iframe.sandbox : 'none'}", allow="${typeof iframe.allow === 'string' ? iframe.allow : 'none'}"`,
          },
          tags: ['iframe', 'sandbox', 'cross-origin'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url: maskedUrl.length > 0 ? maskedUrl : url,
          sourceSensor: 'S2',
        };
        globalLeadStore.addLead(ifrLead, tabId);
      }
    }
  }

  // 5. Analyze Links & Content for Cloud Buckets & Recon
  if (data.links !== undefined && data.links.length > 0) {
    const combinedHrefs = data.links.map((l) => l.href).join('\n');
    const reconLeads = detectReconLeads(combinedHrefs, url, scopeStatus);
    for (const lead of reconLeads) {
      globalLeadStore.addLead(lead, tabId);
      if (lead.ruleId === 'CLD-001' && lead.evidence.extractedNames !== undefined) {
        for (const bucketName of lead.evidence.extractedNames) {
          const prov = lead.tags.includes('aws')
            ? 'aws'
            : lead.tags.includes('gcp')
            ? 'gcp'
            : lead.tags.includes('azure')
            ? 'azure'
            : 'digitalocean';
          await recordBucket({
            bucket: bucketName,
            provider: prov,
            origin,
          });
        }
      }
    }

    for (const link of data.links) {
      try {
        const u = new URL(link.href);
        if (typeof u.hostname === 'string' && u.hostname.length > 0 && u.hostname !== hostname) {
          await recordHost({
            hostname: u.hostname,
            scopeStatus: resolveScopeStatus(link.href, settings),
            discoveredVia: 'dom-link',
            firstSeen: Date.now(),
            lastSeen: Date.now(),
          });
        }
      } catch {
        // Ignore
      }
    }
  }

  // 6. Analyze Framework Hydration Globals
  const hyd = data.hydrationGlobals;
  if (hyd !== undefined) {
    const stateBlobs = [hyd.nextData, hyd.nuxt, hyd.initialState, hyd.apolloState, hyd.env].filter(
      (b): b is string => typeof b === 'string' && b.length > 0
    );
    for (const blob of stateBlobs) {
      const secrets = detectSecrets(blob, url, scopeStatus);
      for (const s of secrets) {
        s.title = `[Hydration State] ${s.title}`;
        globalLeadStore.addLead(s, tabId);
      }
      const endpoints = detectEndpoints(blob, url, scopeStatus);
      for (const ep of endpoints) {
        globalLeadStore.addLead(ep, tabId);
      }
    }
  }

  // 7. Analyze HTML Comments
  if (data.comments !== undefined && data.comments.length > 0) {
    for (const comment of data.comments) {
      const secretLeads = detectSecrets(comment, url, scopeStatus);
      for (const s of secretLeads) {
        s.title = `[HTML Comment] ${s.title}`;
        globalLeadStore.addLead(s, tabId);
      }
    }
  }

  // 8. Storage Keys Analysis
  const allStorageKeys = [
    ...data.storageKeyNames.localStorage,
    ...data.storageKeyNames.sessionStorage,
  ];
  if (allStorageKeys.length > 0) {
    const authLeads = detectAuthLeads(
      {
        url,
        storageKeys: allStorageKeys,
      },
      scopeStatus
    );
    for (const l of authLeads) {
      globalLeadStore.addLead(l, tabId);
    }
    for (const k of allStorageKeys) {
      const cat = classifyParamName(k);
      await recordParam({
        name: k,
        category: cat,
        origin,
        contexts: ['storage-key'],
      });
    }
  }

  // 9. Resource Timing Harvesting
  if (data.resourceTiming !== undefined && data.resourceTiming.length > 0) {
    for (const resUrl of data.resourceTiming) {
      try {
        const u = new URL(resUrl);
        if (typeof u.hostname === 'string' && u.hostname.length > 0 && u.hostname !== hostname) {
          await recordHost({
            hostname: u.hostname,
            scopeStatus: resolveScopeStatus(resUrl, settings),
            discoveredVia: 'resource-timing',
            firstSeen: Date.now(),
            lastSeen: Date.now(),
          });
        }
      } catch {
        // Ignore
      }
    }
  }

  return getLeadsState(tabId, origin);
}

/**
 * S3: Sensor 3 Main-World Hook event handler.
 */
export function handleMainWorldEvent(
  msg: MainWorldLeadsEventMessage,
  settings: SettingsV2
): LeadStateUpdateMessage {
  const { url, origin, event, tabId } = msg;
  if (typeof event !== 'object' || event === null || typeof event.eventType !== 'string') {
    return getLeadsState(tabId, origin);
  }

  const safeUrl = typeof url === 'string' ? url : '';
  const maskedLoc = maskLocation(safeUrl);
  const sanitizedUrl = maskedLoc.length > 0 ? maskedLoc : safeUrl;
  const scopeStatus = resolveScopeStatus(sanitizedUrl, settings);

  if (event.eventType === 'sink') {
    const sinkName = typeof event.sinkName === 'string' && event.sinkName.length > 0 ? event.sinkName : 'sink';
    const sourceVal = typeof event.sourceValue === 'string' && event.sourceValue.length > 0 ? event.sourceValue : 'tainted-input';
    const contextStr = typeof event.details === 'string' && event.details.length > 0 ? event.details : `Assigned to ${sinkName}`;
    const lead: Lead = {
      id: nextId('SINK-TAINT'),
      ruleId: 'PAR-004',
      family: 'F5',
      tier: 'weak',
      potential: 'medium',
      confidence: 0.7,
      title: `[Page-Reported] Client-Side DOM Sink Execution with Controlled Input (${sinkName})`,
      needs: ['audit whether input reaches sink unescaped to verify DOM XSS'],
      doesNotProve: ['exploitable DOM XSS execution'],
      evidence: {
        preview: maskSecret(sourceVal),
        location: maskLocation(sanitizedUrl),
        context: contextStr,
      },
      tags: ['page-reported', 'dom-xss', 'sink', 'taint-lite', sinkName],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: sanitizedUrl,
      sourceSensor: 'S3',
    };
    globalLeadStore.addLead(lead, tabId);
  } else if (event.eventType === 'postmessage_call') {
    const detailsStr = typeof event.details === 'string' && event.details.length > 0 ? event.details : 'postMessage(*)';
    const lead: Lead = {
      id: nextId('POST-WILD'),
      ruleId: 'IFR-001',
      family: 'F8',
      tier: 'weak',
      potential: 'low',
      confidence: 0.65,
      title: `[Page-Reported] window.postMessage Dispatched to Wildcard Target Origin "*"`,
      needs: ['inspect message payload and determine if sensitive tokens or state can be intercepted'],
      doesNotProve: ['unauthorized cross-origin token interception'],
      evidence: {
        preview: maskSecret(detailsStr),
        location: maskLocation(sanitizedUrl),
        context: detailsStr,
      },
      tags: ['page-reported', 'postmessage', 'wildcard-origin', 'cross-origin'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: sanitizedUrl,
      sourceSensor: 'S3',
    };
    globalLeadStore.addLead(lead, tabId);
  } else if (event.eventType === 'postmessage_listener') {
    const detailsStr = typeof event.details === 'string' && event.details.length > 0 ? event.details : 'message listener missing origin check';
    const lead: Lead = {
      id: nextId('POST-NO-ORIGIN'),
      ruleId: 'IFR-002',
      family: 'F8',
      tier: 'whisper',
      potential: 'info',
      confidence: 0.6,
      title: `[Page-Reported] window message Event Listener Registered Without Origin Validation Check`,
      needs: ['verify if listener handler processes untrusted cross-origin postMessage payloads'],
      doesNotProve: ['cross-origin message manipulation'],
      evidence: {
        preview: maskSecret(detailsStr),
        location: maskLocation(sanitizedUrl),
        context: detailsStr,
      },
      tags: ['page-reported', 'postmessage', 'missing-origin-check', 'event-listener'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: sanitizedUrl,
      sourceSensor: 'S3',
    };
    globalLeadStore.addLead(lead, tabId);
  } else if (event.eventType === 'storage_write') {
    const keyStr = typeof event.storageKey === 'string' && event.storageKey.length > 0 ? event.storageKey : 'key';
    const previewStr = typeof event.storageKey === 'string' && event.storageKey.length > 0 ? event.storageKey : 'storage-token';
    const contextStr = typeof event.details === 'string' && event.details.length > 0 ? event.details : `Key: ${keyStr}`;
    const lead: Lead = {
      id: nextId('STOR-TOKEN'),
      ruleId: 'AUTH-003',
      family: 'F4',
      tier: 'whisper',
      potential: 'info',
      confidence: 0.65,
      title: `[Page-Reported] Sensitive Token Stored in Web Storage (${keyStr})`,
      needs: ['check if tokens stored in localStorage are vulnerable to XSS exfiltration'],
      doesNotProve: ['token compromise'],
      evidence: {
        preview: maskSecret(previewStr),
        location: maskLocation(sanitizedUrl),
        context: contextStr,
      },
      tags: ['page-reported', 'storage', 'jwt', 'auth-token', keyStr],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: sanitizedUrl,
      sourceSensor: 'S3',
    };
    globalLeadStore.addLead(lead, tabId);
  }

  return getLeadsState(tabId, origin);
}

/**
 * S4: Sensor 4 DevTools collected leads handler.
 */
export function handleDevToolsLeads(
  leads: Lead[],
  tabId?: number
): LeadStateUpdateMessage {
  let origin = 'https://unknown';
  for (const lead of leads) {
    lead.sourceSensor = 'S4';
    globalLeadStore.addLead(lead, tabId);
    if (typeof lead.origin === 'string' && lead.origin.length > 0 && lead.origin !== 'https://unknown') {
      origin = lead.origin;
    }
  }

  return getLeadsState(tabId, origin);
}

/**
 * Handles triage and pin updates on leads.
 */
export function handleLeadAction(
  leadId: string,
  action: 'pin' | 'unpin' | 'triage',
  triageState?: Lead['triageState'],
  pinned?: boolean
): boolean {
  try {
    const newPinned = action === 'pin' ? true : action === 'unpin' ? false : pinned;
    globalLeadStore.updateLeadTriage(leadId, triageState, newPinned);
    return true;
  } catch {
    return false;
  }
}

/**
 * Returns current lead state for tab or origin, with evaluated chains and ranked order.
 */
export function getLeadsState(
  tabId?: number,
  origin?: string
): LeadStateUpdateMessage {
  let leads: Lead[] = [];

  if (typeof origin === 'string' && origin.length > 0) {
    leads = globalLeadStore.getLeadsForOrigin(origin);
  } else if (tabId !== undefined && tabId >= 0) {
    leads = globalLeadStore.getLeadsForTab(tabId, typeof origin === 'string' && origin.length > 0 ? origin : '');
  } else {
    leads = globalLeadStore.getAllLeads();
  }

  // Correlate Chains
  const chainResult = evaluateChains(leads);
  const ranked = rankLeads(chainResult.leads);

  // Compute summary stats
  const stats = {
    total: ranked.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const lead of ranked) {
    if (lead.potential === 'critical') stats.critical++;
    else if (lead.potential === 'high') stats.high++;
    else if (lead.potential === 'medium') stats.medium++;
    else if (lead.potential === 'low') stats.low++;
    else if (lead.potential === 'info') stats.info++;
  }

  return {
    type: 'LEAD_STATE_UPDATE',
    tabId,
    origin: typeof origin === 'string' && origin.length > 0 ? origin : 'https://unknown',
    leads: ranked,
    activeChains: chainResult.activeChains,
    stats,
  };
}

/**
 * Active Hunter probe execution handler.
 */
export async function handleHunterProbe(
  probe: HunterProbeRequest,
  scopeStatus: Lead['scopeStatus'] = 'unknown',
  config: HunterConfig = { enabled: false, maxRequestsPerSecond: 1 },
  confirmedByUser = false
): Promise<HunterLedgerEntry> {
  return executeHunterProbe(probe, scopeStatus, config, confirmedByUser);
}
