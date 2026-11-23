import type {
  HunterProbeRequest,
  HunterLedgerEntry,
  HunterConfig,
  Lead,
} from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

let hunterCounter = 0;
function nextHunterId(): string {
  hunterCounter++;
  return `HNT-${Date.now().toString(36)}-${hunterCounter}`;
}

const ledger: HunterLedgerEntry[] = [];
const MAX_LEDGER_ENTRIES = 200;

let lastRequestTime = 0;

/**
 * Enforces token bucket rate limiter (default 1 req/sec, concurrency 1).
 */
async function throttle(maxReqPerSec: number): Promise<void> {
  const minIntervalMs = 1000 / Math.max(0.1, maxReqPerSec || 1);
  const now = Date.now();
  const elapsed = now - lastRequestTime;

  if (elapsed < minIntervalMs) {
    const delayMs = minIntervalMs - elapsed;
    await new Promise(resolve => setTimeout(resolve, delayMs));
  }
  lastRequestTime = Date.now();
}

export interface HunterProbeOutcome {
  /** Ledger entry (headers + status only; response bodies are never written to the ledger). */
  entry: HunterLedgerEntry;
  /** Bounded, in-memory-only body sample. Present only when the caller asked for one AND the probe actually ran. */
  body?: string;
}

const MAX_BODY_SAMPLE_BYTES = 32 * 1024;

async function readBodyCapped(res: Response, limit: number): Promise<string | undefined> {
  try {
    const cap = Math.max(0, Math.min(limit, MAX_BODY_SAMPLE_BYTES));
    if (cap === 0 || res.body === null) return undefined;
    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let out = '';
    let bytesRead = 0;
    while (bytesRead < cap) {
      const { done, value } = await reader.read();
      if (done || value === undefined) break;
      const slice = value.subarray(0, Math.min(value.length, cap - bytesRead));
      out += decoder.decode(slice, { stream: true });
      bytesRead += slice.length;
    }
    out += decoder.decode();
    return out;
  } catch {
    return undefined;
  }
}

/**
 * Executes a strictly gated hunter probe request.
 */
export async function executeHunterProbe(
  probe: HunterProbeRequest,
  scopeStatus: Lead['scopeStatus'],
  config: HunterConfig,
  confirmedByUser = false
): Promise<HunterLedgerEntry> {
  const outcome = await executeHunterProbeWithBody(probe, scopeStatus, config, confirmedByUser, 0);
  return outcome.entry;
}

export async function executeHunterProbeWithBody(
  probe: HunterProbeRequest,
  scopeStatus: Lead['scopeStatus'],
  config: HunterConfig,
  confirmedByUser = false,
  bodyLimitBytes = 0
): Promise<HunterProbeOutcome> {
  const entryId = nextHunterId();
  const timestamp = Date.now();

  // User Confirmation Gate: Probe must be explicitly authorized by the user
  if (!confirmedByUser) {
    const unconfirmedEntry: HunterLedgerEntry = {
      id: entryId,
      timestamp,
      request: probe,
      confirmedByUser: false,
      scopeStatus,
      resultNotes: 'Blocked: Probe was not explicitly confirmed by the user.',
    };
    recordLedgerEntry(unconfirmedEntry);
    return { entry: unconfirmedEntry };
  }

  // Scope Gating Check 1: strictly in-scope only
  if (scopeStatus !== 'in-scope') {
    const blockedEntry: HunterLedgerEntry = {
      id: entryId,
      timestamp,
      request: probe,
      confirmedByUser,
      scopeStatus,
      resultNotes: `Blocked: Target URL is ${scopeStatus}. Active validation is strictly forbidden outside declared scope.`,
    };
    recordLedgerEntry(blockedEntry);
    return { entry: blockedEntry };
  }

  // Active Tier Enabled Check
  if (!config.enabled) {
    const disabledEntry: HunterLedgerEntry = {
      id: entryId,
      timestamp,
      request: probe,
      confirmedByUser,
      scopeStatus,
      resultNotes: 'Blocked: Hunter active tier is disabled in configuration.',
    };
    recordLedgerEntry(disabledEntry);
    return { entry: disabledEntry };
  }

  // Method Safety Check: Only GET, HEAD, OPTIONS
  const allowedMethods = ['GET', 'HEAD', 'OPTIONS'];
  const method = (probe.method || '').toUpperCase();
  if (!allowedMethods.includes(method)) {
    const rejectedEntry: HunterLedgerEntry = {
      id: entryId,
      timestamp,
      request: probe,
      confirmedByUser,
      scopeStatus,
      resultNotes: `Prohibited method: Only GET, HEAD, and OPTIONS are allowed. Method '${method}' is disallowed for safe verification.`,
    };
    recordLedgerEntry(rejectedEntry);
    return { entry: rejectedEntry };
  }

  // Rate Limiting
  await throttle(config.maxRequestsPerSecond > 0 ? config.maxRequestsPerSecond : 1);

  // Prepare Headers
  const reqHeaders: Record<string, string> = { ...(probe.headers !== undefined ? probe.headers : {}) };
  if (
    typeof config.programHeaderName === 'string' &&
    config.programHeaderName.length > 0 &&
    typeof config.programHeaderValue === 'string' &&
    config.programHeaderValue.length > 0
  ) {
    reqHeaders[config.programHeaderName] = config.programHeaderValue;
  }

  const startTime = Date.now();
  try {
    const res = await fetch(probe.targetUrl, {
      method: method,
      headers: reqHeaders,
      credentials: 'omit', // INVARIANT: zero cookies sent
      mode: 'cors',
      redirect: 'manual', // Scope safety: never auto-follow a redirect to a host that was not scope-checked
    });

    const elapsedMs = Date.now() - startTime;
    const resHeaders: Record<string, string> = {};
    const body = bodyLimitBytes > 0 ? await readBodyCapped(res, bodyLimitBytes) : undefined;

    res.headers.forEach((val, key) => {
      // Discard set-cookie from retained header ledger
      if (key.toLowerCase() !== 'set-cookie') {
        resHeaders[key.toLowerCase()] = val;
      }
    });

    const entry: HunterLedgerEntry = {
      id: entryId,
      timestamp,
      request: probe,
      response: {
        status: res.status,
        headers: resHeaders,
        elapsedMs,
      },
      confirmedByUser: true,
      scopeStatus,
      resultNotes: res.type === 'opaqueredirect'
        ? `Probe answered with a redirect that was NOT followed (scope safety) in ${elapsedMs}ms`
        : `Completed probe (${res.status} ${res.statusText}) in ${elapsedMs}ms`,
    };

    recordLedgerEntry(entry);
    return body !== undefined ? { entry, body } : { entry };
  } catch (err) {
    const elapsedMs = Date.now() - startTime;
    const msg = err instanceof Error ? err.message : String(err);
    const isCspError = msg.includes('Failed to fetch') || msg.includes('CSP') || msg.includes('Refused to connect');
    const hint = isCspError
      ? ' (Active HTTP probes are blocked by passive CSP connect-src \'none\' in standard build. Use ACULYX Hunter build flavor).'
      : '';
    const errorEntry: HunterLedgerEntry = {
      id: entryId,
      timestamp,
      request: probe,
      confirmedByUser,
      scopeStatus,
      resultNotes: `Probe network error: ${msg}${hint} (${elapsedMs}ms)`,
    };
    recordLedgerEntry(errorEntry);
    return { entry: errorEntry };
  }
}

function recordLedgerEntry(entry: HunterLedgerEntry): void {
  ledger.push(entry);
  if (ledger.length > MAX_LEDGER_ENTRIES) {
    ledger.shift();
  }
}

export function getHunterLedger(): HunterLedgerEntry[] {
  return [...ledger];
}

export function clearHunterLedger(): void {
  ledger.length = 0;
}

export interface HunterCorsProbeResult {
  targetUrl: string;
  testedOrigin: string;
  confirmedVulnerable: boolean;
  lead?: Lead | undefined;
  details: string;
}

/**
 * Actively probes a target endpoint with test Origin headers (null, evil.tld, target.evil.tld, eviltarget).
 * Only reports a vulnerability when both ACAO (reflecting test origin) AND ACAC (true) confirm impact!
 * Gated by: confirmedByUser === true AND scopeStatus === 'in-scope' AND config.enabled === true.
 */
export async function executeHunterCorsProbe(
  targetUrl: string,
  scopeStatus: Lead['scopeStatus'],
  config: HunterConfig,
  confirmedByUser = false
): Promise<HunterCorsProbeResult[]> {
  const results: HunterCorsProbeResult[] = [];
  if (!confirmedByUser || scopeStatus !== 'in-scope' || !config.enabled) {
    return results;
  }

  let targetHost = '';
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    return results;
  }

  const candidateOrigins = [
    'null',
    'https://evil.tld',
    `https://${targetHost}.evil.tld`,
    `https://evil${targetHost}`,
  ];

  for (const testOrigin of candidateOrigins) {
    const probeRequest: HunterProbeRequest = {
      targetUrl,
      method: 'GET',
      headers: {
        Origin: testOrigin,
      },
      reason: `Active CORS verification testing arbitrary Origin reflection (${testOrigin}) with credentials`,
    };

    const ledgerEntry = await executeHunterProbe(probeRequest, scopeStatus, config, confirmedByUser);
    if (!ledgerEntry.response) continue;

    const resHeaders = ledgerEntry.response.headers;
    const acao = resHeaders['access-control-allow-origin']?.trim();
    const acac = resHeaders['access-control-allow-credentials']?.trim().toLowerCase() === 'true';

    const originMatches =
      testOrigin === 'null'
        ? acao?.toLowerCase() === 'null'
        : acao?.toLowerCase() === testOrigin.toLowerCase();

    // Invariant: ONLY report when both ACAO reflects test origin AND ACAC is true!
    const confirmedVulnerable = Boolean(originMatches && acac);

    let lead: Lead | undefined;
    if (confirmedVulnerable) {
      lead = {
        id: `HNT-CORS-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        ruleId: 'SEC-001',
        family: 'F3',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: `Active CORS Verification: Arbitrary Origin (${testOrigin}) Reflected with Credentials`,
        needs: [],
        doesNotProve: [],
        evidence: {
          preview: maskSecret(`Origin: ${testOrigin} -> ACAO: ${acao ?? ''}; ACAC: true`),
          location: maskLocation(targetUrl),
          context: `Active probe verified vulnerable CORS configuration for Origin: ${testOrigin}`,
        },
        tags: ['cors', 'active-verified', 'hunter', 'credentialed'],
        scopeStatus,
        timestamp: Date.now(),
        origin: new URL(targetUrl).origin,
        url: targetUrl,
        sourceSensor: 'S1',
        remediation:
          'Remove dynamic Origin reflection. Implement a strict server-side allowlist for Access-Control-Allow-Origin when Access-Control-Allow-Credentials is true.',
      };
    }

    results.push({
      targetUrl,
      testedOrigin: testOrigin,
      confirmedVulnerable,
      lead,
      details: confirmedVulnerable
        ? `CRITICAL: Server reflected Origin "${testOrigin}" with Access-Control-Allow-Credentials: true`
        : `Not reproduced: Server did not reflect "${testOrigin}" with credentials (ACAO: ${acao ?? 'none'}, ACAC: ${String(acac)}). Not proof of safety: the server may trust other origins or only reflect on other paths.`,
    });

    if (confirmedVulnerable) {
      break;
    }
  }

  return results;
}
