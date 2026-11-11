/**
 * leads-handler.ts
 *
 * Coordinates Lead Radar sensors (S1 WebRequest, S2 DOM Collector, S3 Main-World Hooks, S4 DevTools),
 * evaluates detector rules (F1-F8), runs vulnerability chains (CH-001..CH-007),
 * computes ranking, and orchestrates LeadStore & ReconStore persistence.
 */

import {
  globalLeadStore,
  recordHost,
  recordParam,
  recordEndpoint,
  recordBucket,
} from '../leads';
export { globalLeadStore };
import { detectSecrets, type SecretCandidateEmit } from '../leads/detectors/f1-secrets';
import { globalSecretCandidateStore } from './secret-candidate-store';
import { detectEndpoints } from '../leads/detectors/f2-endpoints';
import { detectSourceMaps } from '../leads/detectors/f3-sourcemaps';
import { detectAuthLeads } from '../leads/detectors/f4-auth';
import { detectParamLeads, classifyParamName } from '../leads/detectors/f5-params';
import { detectReconLeads } from '../leads/detectors/f8-recon';
import { evaluateChains } from '../leads/chains/chains';
import { rankLeads } from '../leads/ranking/ranking';
import {
  executeHunterProbe,
  executeHunterProbeWithBody,
  executeHunterCorsProbe,
} from '../leads/hunter/hunter';
import { applyPassiveVerdicts, verifyLeadActive, type ApprovedProbePlan } from '../leads/verify';
import { maskSecret, maskLocation } from '../leads/sieve/mask';
import { ScopeEngine } from '../shared/scope/engine';
import { originFromUrl } from '../rules/utils';
import { canCollectForTab } from './capture-policy';
import type {
  Lead,
  HunterProbeRequest,
  HunterLedgerEntry,
  HunterConfig,
  CloudBucketProvider,
  LeadVerdict,
} from '../leads/types';
import {
  S3_ALLOWED_SINKS,
  S3_ALLOWED_SOURCE_CATEGORIES,
  type DomLeadsCollectedMessage,
  type MainWorldLeadsEventMessage,
  type LeadStateUpdateMessage,
} from '../shared/messaging';
import type { SettingsV2 } from '../shared/types';

// Wire LeadStore eviction to background ephemeral candidate store
globalLeadStore.onLeadRemoved = (leadId) => {
  globalSecretCandidateStore.removeCandidate(leadId);
};
globalLeadStore.onCleared = () => {
  globalSecretCandidateStore.clear();
};

function ingestSecretLeads(
  leads: Lead[],
  candidates: Map<string, SecretCandidateEmit>,
  tabId: number | undefined,
  settings: SettingsV2,
  scopeStatus: Lead['scopeStatus']
): void {
  for (const lead of leads) {
    const incomingId = lead.id;
    const survivingId = globalLeadStore.addLead(lead, tabId);
    const cand = candidates.get(incomingId);
    if (
      cand !== undefined &&
      survivingId !== undefined &&
      survivingId.length > 0 &&
      settings.credentialLivenessEnabled === true &&
      scopeStatus !== 'out-of-scope'
    ) {
      globalSecretCandidateStore.addCandidate(
        survivingId,
        cand.provider,
        cand.tokenFamily,
        cand.rawToken
      );
    }
  }
}


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

  // Issue 4: Fail-closed scope gate — discard out-of-scope data from recon and persistent leads
  if (scopeStatus === 'out-of-scope') {
    return;
  }

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
      scopeStatus,
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

  // Authoritative monitoring & capture policy gate: Fail closed if Off, not permitted, or stale
  if (!canCollectForTab(tabId ?? -1, url, { settings, generation: msg.generation })) {
    return {
      type: 'LEAD_STATE_UPDATE',
      tabId: tabId ?? -1,
      origin,
      leads: [],
      activeChains: [],
      stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
  }

  const scopeStatus = resolveScopeStatus(url, settings);

  // Issue 4: Fail-closed scope gate — discard out-of-scope DOM collection
  if (scopeStatus === 'out-of-scope') {
    return {
      type: 'LEAD_STATE_UPDATE',
      tabId,
      origin,
      leads: [],
      activeChains: [],
      stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
  }

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
          inputs: f.inputs !== undefined
            ? f.inputs.map((i) => ({ name: i.name, type: i.type }))
            : f.inputNames.map((n) => ({ name: n })),
        })),
        storageKeys: data.storageKeyNames.localStorage,
      },
      scopeStatus
    );

    for (const lead of authLeads) {
      globalLeadStore.addLead(lead, tabId);
    }

    for (const f of data.forms) {
      const formUrl = typeof f.action === 'string' && f.action.length > 0 ? f.action : url;
      const formOrigin = originFromUrl(formUrl) ?? origin;
      const formScope = typeof f.action === 'string' && f.action.length > 0
        ? resolveScopeStatus(f.action, settings)
        : scopeStatus;

      if (typeof f.action === 'string' && f.action.length > 0) {
        const maskedAct = maskLocation(f.action);
        await recordEndpoint({
          path: maskedAct.length > 0 ? maskedAct : f.action,
          origin: formOrigin,
          method: f.method,
          tags: ['form'],
          scopeStatus: formScope,
        });
      }
      for (const inputName of f.inputNames) {
        const cat = classifyParamName(inputName);
        await recordParam({
          name: inputName,
          category: cat,
          origin: formOrigin,
          contexts: ['form-input'],
          scopeStatus: formScope,
        });
      }
    }
  }

  // 3. Analyze Scripts (Secrets, Endpoints, SourceMaps)
  if (data.scripts !== undefined && data.scripts.length > 0) {
    for (const script of data.scripts) {
      const scriptUrl = typeof script.src === 'string' && script.src.length > 0 ? script.src : url;
      // Independent scope classification for scripts (prevents external CDNs/scripts inheriting top-level in-scope)
      const scriptScope = typeof script.src === 'string' && script.src.length > 0
        ? resolveScopeStatus(script.src, settings)
        : scopeStatus;

      if (typeof script.src === 'string' && script.src.length > 0) {
        try {
          const sHost = new URL(script.src).hostname;
          if (sHost !== hostname) {
            await recordHost({
              hostname: sHost,
              scopeStatus: scriptScope,
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
        // F1: Secrets evaluated with script's own scope
        const secretCandidates = new Map<string, SecretCandidateEmit>();
        const secretLeads = detectSecrets(script.inlineContent, scriptUrl, scriptScope, (c) => {
          secretCandidates.set(c.leadId, c);
        });
        ingestSecretLeads(secretLeads, secretCandidates, tabId, settings, scriptScope);

        // F2: Endpoints evaluated with script's own scope
        const endpointLeads = detectEndpoints(script.inlineContent, scriptUrl, scriptScope);
        for (const lead of endpointLeads) {
          globalLeadStore.addLead(lead, tabId);
          if (lead.evidence.extractedNames !== undefined) {
            for (const ep of lead.evidence.extractedNames) {
              await recordEndpoint({
                path: ep,
                origin: originFromUrl(scriptUrl) ?? origin,
                tags: ['script-harvested'],
                scopeStatus: scriptScope,
              });
            }
          }
        }

        // F3: Source Maps evaluated with script's own scope
        const sourceMapLeads = detectSourceMaps(script.inlineContent, {}, scriptUrl, scriptScope);
        for (const lead of sourceMapLeads) {
          globalLeadStore.addLead(lead, tabId);
        }
      }

      if (typeof script.sourceMappingURL === 'string' && script.sourceMappingURL.length > 0 && !script.sourceMappingURL.startsWith('data:')) {
        const maskedScriptUrl = maskLocation(scriptUrl);
        const maskedSmUrl = maskLocation(script.sourceMappingURL);
        const smLead: Lead = {
          id: nextId('MAP-REF'),
          ruleId: 'MAP-001',
          family: 'F3',
          tier: 'observed',
          potential: 'low',
          confidence: 0.95,
          title: maskedSmUrl.length > 0
            ? `JavaScript Source Map Reference Detected: ${maskedSmUrl}`
            : 'JavaScript Source Map Reference Detected',
          needs: ['fetch .map file to inspect original TypeScript/JavaScript source code'],
          doesNotProve: ['source map is accessible without authorization'],
          evidence: {
            preview: maskedSmUrl.length > 0 ? maskedSmUrl : maskSecret(script.sourceMappingURL),
            location: maskLocation(scriptUrl),
            context: `Found sourceMappingURL in script tag`,
          },
          tags: ['sourcemap', 'source-code', 'recon'],
          scopeStatus: scriptScope,
          timestamp: Date.now(),
          origin: originFromUrl(scriptUrl) ?? origin,
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
      // Independent scope classification for embedded iframe origins
      const iframeScope = typeof iframe.src === 'string' && iframe.src.length > 0
        ? resolveScopeStatus(iframe.src, settings)
        : scopeStatus;

      if (typeof iframe.src === 'string' && iframe.src.length > 0) {
        try {
          const ifHost = new URL(iframe.src).hostname;
          if (ifHost !== hostname) {
            await recordHost({
              hostname: ifHost,
              scopeStatus: iframeScope,
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
          scopeStatus: iframeScope,
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
    for (const link of data.links) {
      if (typeof link.href !== 'string' || link.href.trim().length === 0) continue;
      const linkScope = resolveScopeStatus(link.href, settings);
      const reconLeads = detectReconLeads(
        link.href,
        link.href,
        linkScope,
        (targetUrl: string) => resolveScopeStatus(targetUrl, settings)
      );
      for (const lead of reconLeads) {
        globalLeadStore.addLead(lead, tabId);
        if (lead.ruleId === 'CLD-001' && lead.evidence.extractedNames !== undefined) {
          const KNOWN_PROVIDERS: CloudBucketProvider[] = [
            'aws',
            'gcp',
            'azure',
            'digitalocean',
            'cloudflare-r2',
            'alibaba-oss',
            'oracle-oss',
            'backblaze-b2',
          ];
          const matched = KNOWN_PROVIDERS.find(p => lead.tags.includes(p));
          const prov: CloudBucketProvider = matched !== undefined ? matched : 'generic';

          for (const bucketName of lead.evidence.extractedNames) {
            await recordBucket({
              bucket: bucketName,
              provider: prov,
              origin: lead.origin,
              scopeStatus: lead.scopeStatus,
            });
          }
        }
      }

      // Also evaluate parameter leads from discovered links
      if (link.href.includes('?')) {
        const linkParamLeads = detectParamLeads(link.href, linkScope);
        for (const pl of linkParamLeads) {
          globalLeadStore.addLead(pl, tabId);
        }
      }

      try {
        const u = new URL(link.href);
        if (typeof u.hostname === 'string' && u.hostname.length > 0 && u.hostname !== hostname) {
          await recordHost({
            hostname: u.hostname,
            scopeStatus: linkScope,
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
      const candidates = new Map<string, SecretCandidateEmit>();
      const secrets = detectSecrets(blob, url, scopeStatus, (c) => {
        candidates.set(c.leadId, c);
      });
      for (const s of secrets) {
        s.title = `[Hydration State] ${s.title}`;
      }
      ingestSecretLeads(secrets, candidates, tabId, settings, scopeStatus);
      const endpoints = detectEndpoints(blob, url, scopeStatus);
      for (const ep of endpoints) {
        globalLeadStore.addLead(ep, tabId);
      }
    }
  }

  // 7. Analyze HTML Comments
  if (data.comments !== undefined && data.comments.length > 0) {
    for (const comment of data.comments) {
      const candidates = new Map<string, SecretCandidateEmit>();
      const secretLeads = detectSecrets(comment, url, scopeStatus, (c) => {
        candidates.set(c.leadId, c);
      });
      for (const s of secretLeads) {
        s.title = `[HTML Comment] ${s.title}`;
      }
      ingestSecretLeads(secretLeads, candidates, tabId, settings, scopeStatus);
      const epLeads = detectEndpoints(comment, url, scopeStatus);
      for (const ep of epLeads) {
        ep.title = `[HTML Comment] ${ep.title}`;
        globalLeadStore.addLead(ep, tabId);
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
        scopeStatus,
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

const tabMainWorldCounts = new Map<number, number>();
const MAX_BACKGROUND_S3_PER_TAB = 100;

export function resetMainWorldCountForTab(tabId: number): void {
  tabMainWorldCounts.delete(tabId);
}

/**
 * S3: Sensor 3 Main-World Hook event handler.
 */
export function handleMainWorldEvent(
  msg: MainWorldLeadsEventMessage,
  settings: SettingsV2
): LeadStateUpdateMessage {
  const { url, origin, event, tabId } = msg;

  // Authoritative monitoring & capture policy gate: Fail closed if Off, not permitted, or stale
  if (!canCollectForTab(tabId ?? -1, url, { settings, generation: msg.generation })) {
    return {
      type: 'LEAD_STATE_UPDATE',
      tabId: tabId ?? -1,
      origin,
      leads: [],
      activeChains: [],
      stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
  }

  if (typeof event !== 'object' || event === null || typeof event.eventType !== 'string') {
    return getLeadsState(tabId, origin);
  }

  // Schema validation on background boundary: reject unknown event types
  if (!['sink', 'postmessage_call', 'postmessage_listener', 'storage_write'].includes(event.eventType)) {
    return getLeadsState(tabId, origin);
  }

  // Enforce background rate limit per tab
  if (typeof tabId === 'number' && tabId >= 0) {
    const curCount = tabMainWorldCounts.get(tabId) ?? 0;
    if (curCount >= MAX_BACKGROUND_S3_PER_TAB) {
      return getLeadsState(tabId, origin);
    }
    tabMainWorldCounts.set(tabId, curCount + 1);
  }

  const safeUrl = typeof url === 'string' ? url : '';
  const maskedLoc = maskLocation(safeUrl);
  const sanitizedUrl = maskedLoc.length > 0 ? maskedLoc : safeUrl;
  const scopeStatus = resolveScopeStatus(sanitizedUrl, settings);

  if (scopeStatus === 'out-of-scope') {
    return getLeadsState(tabId, origin);
  }

  if (event.eventType === 'sink') {
    if (typeof event.sinkName !== 'string' || event.sinkName.length === 0 || !S3_ALLOWED_SINKS.has(event.sinkName)) {
      return getLeadsState(tabId, origin);
    }
    if (typeof event.sourceCategory === 'string' && event.sourceCategory.length > 0 && !S3_ALLOWED_SOURCE_CATEGORIES.has(event.sourceCategory)) {
      return getLeadsState(tabId, origin);
    }
    const sourceCategory = typeof event.sourceCategory === 'string' && event.sourceCategory.length > 0
      ? event.sourceCategory
      : 'controlled input';
    const sinkName = event.sinkName;
    const contextStr = `Sink ${sinkName} invoked with ${sourceCategory}`;
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
        preview: maskSecret(`Controlled input from ${sourceCategory} detected`),
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
    const detailsStr = 'window.postMessage sent message to wildcard target origin "*"';
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
    const detailsStr = 'Message listener registered without origin validation check';
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
    const rawKey = typeof event.storageKey === 'string'
      ? event.storageKey.slice(0, 64).replace(/[^\w.:-]/g, '')
      : '';
    if (rawKey.length === 0) {
      return getLeadsState(tabId, origin);
    }
    const safeKey = maskSecret(rawKey);
    const allowedShapes = ['JWT (JSON Web Token)', 'Bearer Token', 'High-Entropy Hex Token'];
    const tokenShape = typeof event.tokenShape === 'string' && allowedShapes.includes(event.tokenShape)
      ? event.tokenShape
      : undefined;
    const contextStr = tokenShape !== undefined
      ? `Storage write to key "${safeKey}" contains ${tokenShape} shape in memory`
      : `Storage write to key "${safeKey}" observed`;
    const lead: Lead = {
      id: nextId('STOR-TOKEN'),
      ruleId: 'AUTH-003',
      family: 'F4',
      tier: 'whisper',
      potential: 'info',
      confidence: 0.65,
      title: `[Page-Reported] Client-Side Storage Token Write Observed (${safeKey})`,
      needs: ['check if tokens stored in localStorage are vulnerable to XSS exfiltration'],
      doesNotProve: ['token compromise'],
      evidence: {
        preview: safeKey,
        location: maskLocation(sanitizedUrl),
        context: contextStr,
      },
      tags: ['page-reported', 'storage', 'token', 'auth-lead'],
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

  if (tabId !== undefined && tabId >= 0) {
    leads = globalLeadStore.getLeadsForTab(tabId, typeof origin === 'string' && origin.length > 0 ? origin : '');
  } else if (typeof origin === 'string' && origin.length > 0) {
    leads = globalLeadStore.getLeadsForOrigin(origin);
  } else {
    leads = globalLeadStore.getAllLeads();
  }

  // Correlate Chains
  const chainResult = evaluateChains(leads);
  // Self-check: every lead gets an explicit verdict across evidence, scope, and security assessment
  const verified = applyPassiveVerdicts(chainResult.leads);
  const ranked = rankLeads(verified);

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

/**
 * Active self-check of a single lead. Runs ONLY when the researcher asked for it (confirmedByUser) and every
 * Hunter gate passes per target URL (in-scope, Hunter tier enabled, read-only method, rate-limited, no cookies).
 * The resulting verdict is stored on the lead; response bodies are inspected in memory and discarded.
 */
export async function handleVerifyLead(
  leadId: string,
  settings: SettingsV2,
  confirmedByUser = false,
  approvedPlan?: ApprovedProbePlan,
): Promise<LeadVerdict | undefined> {
  const lead = globalLeadStore.getLead(leadId);
  if (lead === undefined) return undefined;

  const config: HunterConfig = settings.hunterConfig ?? { enabled: false, maxRequestsPerSecond: 1 };
  const verdict = await verifyLeadActive(lead, {
    resolveScope: (url: string) => resolveScopeStatus(url, settings),
    probe: (req, scope, bodyLimit) => executeHunterProbeWithBody(req, scope, config, confirmedByUser, bodyLimit),
    corsProbe: (url, scope) => executeHunterCorsProbe(url, scope, config, confirmedByUser),
    approvedPlan,
  });
  globalLeadStore.setVerdict(leadId, verdict);
  return verdict;
}
