import type {
  HunterProbeRequest,
  HunterLedgerEntry,
  HunterConfig,
  Lead,
} from '../types';

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

/**
 * Executes a strictly gated hunter probe request.
 */
export async function executeHunterProbe(
  probe: HunterProbeRequest,
  scopeStatus: Lead['scopeStatus'],
  config: HunterConfig,
  confirmedByUser = false
): Promise<HunterLedgerEntry> {
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
    return unconfirmedEntry;
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
    return blockedEntry;
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
    return disabledEntry;
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
    return rejectedEntry;
  }

  // Rate Limiting
  await throttle(config.maxRequestsPerSecond || 1);

  // Prepare Headers
  const reqHeaders: Record<string, string> = { ...(probe.headers || {}) };
  if (config.programHeaderName && config.programHeaderValue) {
    reqHeaders[config.programHeaderName] = config.programHeaderValue;
  }

  const startTime = Date.now();
  try {
    const res = await fetch(probe.targetUrl, {
      method: method as 'GET' | 'HEAD' | 'OPTIONS',
      headers: reqHeaders,
      credentials: 'omit', // INVARIANT: zero cookies sent
      mode: 'cors',
    });

    const elapsedMs = Date.now() - startTime;
    const resHeaders: Record<string, string> = {};

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
      resultNotes: `Completed probe (${res.status} ${res.statusText}) in ${elapsedMs}ms`,
    };

    recordLedgerEntry(entry);
    return entry;
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
    return errorEntry;
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
