/**
 * Active lead verification (opt-in, per lead).
 *
 * Re-tests a lead with a tiny, read-only request and turns the answer into a verdict. It deliberately reuses the
 * Hunter gates (explicit user confirmation, strictly in-scope target, Hunter tier enabled, GET/HEAD/OPTIONS only,
 * rate limit, zero cookies, redirects not followed). If any gate blocks the probe, the lead keeps its passive
 * verdict and the verdict says why it could not be verified - it is never silently promoted or dismissed.
 *
 * What this module will NOT do: replay a discovered credential against its vendor/API. Using a leaked key is
 * access to someone else's account in most programs' rules; liveness of secrets stays a manual, program-approved step.
 */
import type {
  EvidenceStatus,
  HunterProbeRequest,
  Lead,
  LeadVerdict,
  SecurityAssessment,
  VerdictCheck,
  VerdictStatus,
} from '../types';
import type { HunterCorsProbeResult, HunterProbeOutcome } from '../hunter/hunter';
import { verifyLeadPassive } from './passive';

const BODY_SAMPLE_BYTES = 16 * 1024;

export interface ActiveVerifyDeps {
  /** Re-resolves scope for an exact target URL (never trust the lead's stored scope for a new request). */
  resolveScope: (url: string) => Lead['scopeStatus'];
  /** Gated probe (user confirmation + Hunter config already bound by the caller). */
  probe: (req: HunterProbeRequest, scope: Lead['scopeStatus'], bodyLimitBytes: number) => Promise<HunterProbeOutcome>;
  corsProbe: (url: string, scope: Lead['scopeStatus']) => Promise<HunterCorsProbeResult[]>;
  now?: () => number;
  approvedPlan?: ApprovedProbePlan | undefined;
}

interface ActiveResult {
  status: VerdictStatus;
  summary: string;
  checks: VerdictCheck[];
  missing: string[];
  /** false when every probe was blocked/failed before reaching the target. */
  ran: boolean;
  evidenceStatus?: EvidenceStatus | undefined;
}

const check = (id: string, outcome: VerdictCheck['outcome'], detail: string): VerdictCheck => ({
  id,
  kind: 'active',
  outcome,
  detail,
});

function headerOf(h: Record<string, string> | undefined, name: string): string {
  return (h?.[name.toLowerCase()] ?? '').toLowerCase();
}

// ---------------------------------------------------------------------------------------------------------------
// Pure interpreters (unit-tested without any network)
// ---------------------------------------------------------------------------------------------------------------

interface ParsedPartialMap {
  valid: boolean;
  sources: string[];
  hasSourcesContent: boolean;
}

function parsePartialSourceMap(prefix: string): ParsedPartialMap {
  const trimmed = prefix.trimStart();
  if (!trimmed.startsWith('{')) {
    return { valid: false, sources: [], hasSourcesContent: false };
  }

  // Must declare v3 version
  if (!/"version"\s*:\s*3\b/.test(trimmed)) {
    return { valid: false, sources: [], hasSourcesContent: false };
  }

  // If mappings property appears in prefix, it must be a string
  const mappingsMatch = trimmed.match(/"mappings"\s*:\s*([^\s,{}]+)/);
  if (mappingsMatch !== null && mappingsMatch[1] !== undefined) {
    if (!mappingsMatch[1].startsWith('"')) {
      return { valid: false, sources: [], hasSourcesContent: false };
    }
  }

  // Extract sources array: look for "sources" key followed by [
  const sourcesMatch = trimmed.match(/"sources"\s*:\s*\[/);
  if (sourcesMatch === null || sourcesMatch.index === undefined) {
    return { valid: false, sources: [], hasSourcesContent: false };
  }

  const arrayStart = sourcesMatch.index + sourcesMatch[0].length;
  const arrayEnd = trimmed.indexOf(']', arrayStart);
  let sources: string[] = [];

  if (arrayEnd !== -1) {
    const rawArray = trimmed.slice(arrayStart - 1, arrayEnd + 1);
    try {
      const parsed: unknown = JSON.parse(rawArray);
      if (Array.isArray(parsed) && parsed.length > 0 && parsed.every((s): s is string => typeof s === 'string')) {
        sources = parsed.filter((s) => s.trim().length > 0);
      }
    } catch {
      sources = [];
    }
  } else {
    // Array was cut off midway before closing ]: parse whatever complete quoted strings exist inside
    const segment = trimmed.slice(arrayStart, Math.min(trimmed.length, arrayStart + 4096));
    const stringTokens = [...segment.matchAll(/"((?:[^"\\]|\\.)+)"/g)];
    sources = stringTokens.map((m) => m[1]?.trim() ?? '').filter((s) => s.length > 0);
  }

  if (sources.length === 0) {
    return { valid: false, sources: [], hasSourcesContent: false };
  }

  // Check for demonstrated sourcesContent disclosure
  let hasSourcesContent = false;
  const scMatch = trimmed.match(/"sourcesContent"\s*:\s*\[/);
  if (scMatch !== null && scMatch.index !== undefined) {
    const scStart = scMatch.index + scMatch[0].length;
    const scEnd = trimmed.indexOf(']', scStart);
    if (scEnd !== -1) {
      try {
        const parsedSc: unknown = JSON.parse(trimmed.slice(scStart - 1, scEnd + 1));
        if (Array.isArray(parsedSc) && (parsedSc as unknown[]).some((c) => typeof c === 'string' && c.trim().length > 0)) {
          hasSourcesContent = true;
        }
      } catch {
        // Fall back to token scan
      }
    }
    if (!hasSourcesContent) {
      const scSegment = trimmed.slice(scStart, Math.min(trimmed.length, scStart + 4096));
      const firstStrMatch = scSegment.match(/^\s*"((?:[^"\\]|\\.)+)"/);
      if (firstStrMatch !== null && firstStrMatch[1] !== undefined && firstStrMatch[1].trim().length > 0) {
        hasSourcesContent = true;
      }
    }
  }

  return {
    valid: true,
    sources,
    hasSourcesContent,
  };
}

export function interpretSourceMapProbe(outcome: HunterProbeOutcome): ActiveResult {
  const res = outcome.entry.response;
  if (res === undefined) {
    return {
      status: 'uncertain',
      summary: 'Source map could not be fetched; exposure not established.',
      checks: [check('sourcemap-fetch', 'inconclusive', outcome.entry.resultNotes ?? 'Probe did not run.')],
      missing: ['Fetch the .map URL manually (or enable Hunter + declare scope).'],
      ran: false,
    };
  }
  const st = res.status;
  if (st === 401 || st === 403) {
    return {
      status: 'uncertain',
      summary: `Source map is not retrievable without authentication (HTTP ${st}).`,
      checks: [check('sourcemap-fetch', 'inconclusive', `GET returned HTTP ${st}; access requires authentication.`)],
      missing: ['Test with authorized session if permitted by program rules.'],
      ran: true,
    };
  }
  if (st === 404 || st === 410) {
    return {
      status: 'false_positive',
      summary: `Source map not found at this URL during this check (HTTP ${st}).`,
      checks: [check('sourcemap-fetch', 'fail', `GET returned HTTP ${st}; resource not found at this location.`)],
      missing: [],
      ran: true,
    };
  }
  if (st === 200 || st === 206) {
    const ct = headerOf(res.headers, 'content-type');
    const body = outcome.body ?? '';
    if (ct.includes('text/html') || /^\s*<(?:!doctype|html)/i.test(body)) {
      return {
        status: 'false_positive',
        summary: 'URL returns an HTML page (SPA/catch-all fallback), not a source map.',
        checks: [check('sourcemap-fetch', 'fail', 'HTTP 200 but body is HTML, not a source map.')],
        missing: [],
        ran: true,
      };
    }

    let parsedMap: Record<string, unknown> | null = null;
    try {
      const trimmed = body.trim();
      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        const obj: unknown = JSON.parse(trimmed);
        if (typeof obj === 'object' && obj !== null && !Array.isArray(obj)) {
          parsedMap = obj as Record<string, unknown>;
        }
      }
    } catch {
      parsedMap = null;
    }

    if (
      parsedMap !== null &&
      parsedMap.version === 3 &&
      typeof parsedMap.mappings === 'string' &&
      Array.isArray(parsedMap.sources) &&
      parsedMap.sources.length > 0 &&
      parsedMap.sources.some((s) => typeof s === 'string' && s.length > 0)
    ) {
      const hasContent =
        Array.isArray(parsedMap.sourcesContent) &&
        parsedMap.sourcesContent.some((c) => typeof c === 'string' && c.length > 0);
      return {
        status: 'confirmed',
        summary: hasContent
          ? 'Source map is publicly downloadable and embeds original source (sourcesContent).'
          : 'Source map is publicly downloadable (original file paths exposed).',
        checks: [
          check('sourcemap-fetch', 'pass', `HTTP ${st}, valid source-map v3 structure (${parsedMap.sources.length} sources, mappings string present).`),
          check(
            'sourcemap-content',
            hasContent ? 'pass' : 'inconclusive',
            hasContent ? 'sourcesContent array present and embeds source.' : 'sourcesContent not present in parsed map.',
          ),
        ],
        missing: [],
        ran: true,
      };
    }

    // Real source maps are far larger than the bounded body sample, so the JSON is often TRUNCATED.
    // Use bounded incremental parsing to strictly verify v3 structure and source paths without false certainty.
    const declaredLength = Number(headerOf(res.headers, 'content-length'));
    const wasTruncated =
      st === 206 ||
      headerOf(res.headers, 'content-range') !== '' ||
      (Number.isFinite(declaredLength) && declaredLength > body.length + 64) ||
      body.length >= BODY_SAMPLE_BYTES - 256;

    if (parsedMap === null && wasTruncated) {
      const partial = parsePartialSourceMap(body);
      if (partial.valid) {
        if (partial.hasSourcesContent) {
          // Demonstrated source-content disclosure: original code found in sampled bytes
          return {
            status: 'confirmed',
            summary: 'Source map is publicly downloadable and embeds original source (sourcesContent).',
            checks: [
              check('sourcemap-fetch', 'pass', `HTTP ${st}; verified source-map v3 prefix (${partial.sources.length} sources identified; response truncated).`),
              check('sourcemap-content', 'pass', 'Embedded original source code verified in sourcesContent within sampled bytes.'),
            ],
            missing: [],
            ran: true,
          };
        }
        // Valid map structure and at least one source file path verified, but full map truncated and no source code embedded.
        // Return 'likely' with inconclusive evidence, reserving 'confirmed' for parsed map or demonstrated code disclosure.
        return {
          status: 'likely',
          summary: `Source map v3 prefix observed with ${partial.sources.length} source file path(s), but response was truncated before full map could be verified.`,
          checks: [
            check('sourcemap-fetch', 'pass', `HTTP ${st}; verified source-map v3 prefix with source paths (${partial.sources.slice(0, 3).join(', ')}).`),
            check('sourcemap-content', 'inconclusive', 'sourcesContent not observed in sampled bytes; full map was truncated.'),
          ],
          missing: ['Download the full source map to confirm unminified source code retrieval.'],
          ran: true,
          evidenceStatus: 'inconclusive',
        };
      }
    }

    return {
      status: 'uncertain',
      summary: `URL answered HTTP ${st} but body does not match source-map v3 format.`,
      checks: [check('sourcemap-fetch', 'inconclusive', 'Neither HTML nor a standard source-map JSON was recognized.')],
      missing: ['Open the URL manually to confirm what it serves.'],
      ran: true,
    };
  }
  return {
    status: 'uncertain',
    summary: `Unexpected answer (HTTP ${st}); exposure not established.`,
    checks: [check('sourcemap-fetch', 'inconclusive', st === 0 ? 'Redirect was not followed (scope safety).' : `HTTP ${st}.`)],
    missing: ['Check manually; the server redirected or errored.'],
    ran: true,
  };
}

export function interpretBucketProbe(outcome: HunterProbeOutcome, provider: 'aws' | 'gcp'): ActiveResult {
  const res = outcome.entry.response;
  if (res === undefined) {
    return {
      status: 'uncertain',
      summary: 'Bucket could not be probed; permissions not established.',
      checks: [check('bucket-list', 'inconclusive', outcome.entry.resultNotes ?? 'Probe did not run.')],
      missing: ['Declare the bucket host in scope and enable Hunter, or test with the program-approved tooling.'],
      ran: false,
    };
  }
  const body = outcome.body ?? '';
  const st = res.status;
  if (st === 200 && body.includes('<ListBucketResult')) {
    return {
      status: 'confirmed',
      summary: 'Bucket allows anonymous listing (public ListBucket).',
      checks: [check('bucket-list', 'pass', `Anonymous GET with max-keys=0 returned a ListBucketResult (${provider}). No object names were retrieved.`)],
      missing: [],
      ran: true,
    };
  }
  if (st === 404 && /NoSuchBucket/i.test(body)) {
    return {
      status: 'likely',
      summary: 'Referenced bucket does not exist (NoSuchBucket) - possible dangling reference / takeover candidate.',
      checks: [check('bucket-exists', 'pass', 'Provider reports NoSuchBucket for the referenced name.')],
      missing: ['Check whether the name is still referenced for live assets and whether it can be registered (do not register without program permission).'],
      ran: true,
    };
  }
  if ((st === 403 || st === 401) && /AccessDenied|Forbidden|AllAccessDisabled/i.test(body + ' ' + headerOf(res.headers, 'content-type'))) {
    return {
      status: 'informational',
      summary: `Bucket exists but anonymous listing is denied (HTTP ${st} AccessDenied); individual object read access was not tested.`,
      checks: [check('bucket-list', 'inconclusive', `HTTP ${st} AccessDenied. Listing is denied. Object-level read permissions were not tested.`)],
      missing: ['Test object-level read permissions on specific known object paths.'],
      ran: true,
    };
  }
  return {
    status: 'uncertain',
    summary: `Unclear bucket response (HTTP ${st}).`,
    checks: [check('bucket-list', 'inconclusive', `HTTP ${st}; response not recognised as listing / NoSuchBucket / AccessDenied.`)],
    missing: ['Test manually.'],
    ran: true,
  };
}

export function interpretCorsProbes(results: HunterCorsProbeResult[]): ActiveResult {
  if (results.length === 0) {
    return {
      status: 'uncertain',
      summary: 'CORS probe did not run (blocked by a Hunter gate or unreachable).',
      checks: [check('cors-reflect', 'inconclusive', 'No probe result: needs user confirmation, in-scope target and Hunter enabled.')],
      missing: ['Enable Hunter, declare scope and confirm the probe - or reproduce with curl -H "Origin: ..." yourself.'],
      ran: false,
    };
  }
  const hit = results.find((r) => r.confirmedVulnerable);
  if (hit !== undefined) {
    return {
      status: 'likely',
      summary: `Reproduced: server reflects Origin "${hit.testedOrigin}" with Access-Control-Allow-Credentials: true.`,
      checks: [check('cors-reflect', 'pass', hit.details)],
      missing: ['Show that the endpoint returns user-specific or sensitive data to a credentialed cross-origin request.'],
      ran: true,
    };
  }
  return {
    status: 'uncertain',
    summary: 'Could not reproduce arbitrary-origin reflection with credentials; the original reflection may come from an allowlisted partner origin.',
    checks: [check('cors-reflect', 'inconclusive', `${results.length} test origins tried; none reflected with credentials.`)],
    missing: [
      'Check whether the originally reflected origin is attacker-controllable (e.g. subdomain takeover, wildcard match).',
      'Browsers may ignore an Origin header set from script, so a negative result is not proof: re-test with curl -H "Origin: https://evil.tld".',
    ],
    ran: true,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Planning + orchestration
// ---------------------------------------------------------------------------------------------------------------

export type ActiveCapability = 'sourcemap' | 'bucket' | 'cors' | 'none';

export interface ProbePlan {
  capability: ActiveCapability;
  targetUrl: string;
  maxRequests: number;
  testOrigins?: string[] | undefined;
  method: string;
  credentials: 'omit';
  redirect: 'manual';
  description: string;
}

export interface ApprovedProbePlan {
  capability: ActiveCapability;
  targetUrl: string;
  maxRequests: number;
  method: string;
  testOrigins?: string[] | undefined;
}

export function matchProbePlan(
  current: ProbePlan | undefined,
  approved: ApprovedProbePlan | undefined,
): boolean {
  if (current === undefined || approved === undefined) return false;
  if (current.capability !== approved.capability) return false;
  if (current.targetUrl !== approved.targetUrl) return false;
  if (current.method !== approved.method) return false;
  if (current.maxRequests !== approved.maxRequests) return false;
  const curOrigins = current.testOrigins ?? [];
  const appOrigins = approved.testOrigins ?? [];
  if (curOrigins.length !== appOrigins.length) return false;
  for (let i = 0; i < curOrigins.length; i++) {
    if (curOrigins[i] !== appOrigins[i]) return false;
  }
  return true;
}

export function activeCapabilityOf(lead: Lead): ActiveCapability {
  if (lead.ruleId === 'MAP-001') return 'sourcemap';
  if (lead.ruleId === 'CLD-001' && (lead.tags.includes('aws') || lead.tags.includes('gcp'))) return 'bucket';
  if (lead.ruleId === 'COR-001' && lead.tags.includes('cors-reflection')) return 'cors';
  return 'none';
}

export function planActiveProbe(lead: Lead): ProbePlan | undefined {
  const cap = activeCapabilityOf(lead);
  if (cap === 'sourcemap') {
    const url = planSourceMapUrl(lead);
    if (url === undefined) return undefined;
    return {
      capability: 'sourcemap',
      targetUrl: url,
      maxRequests: 1,
      method: 'GET',
      credentials: 'omit',
      redirect: 'manual',
      description: `Send 1 read-only GET request (no cookies, redirects not followed) to inspect source map headers and validate version 3 JSON format.\nTarget: ${url}`,
    };
  }
  if (cap === 'bucket') {
    const plan = planBucketUrl(lead);
    if (plan === undefined) return undefined;
    return {
      capability: 'bucket',
      targetUrl: plan.url,
      maxRequests: 1,
      method: 'GET',
      credentials: 'omit',
      redirect: 'manual',
      description: `Send 1 read-only GET request with max-keys=0 (no cookies, redirects not followed) to test anonymous ListBucket permission without reading object contents.\nTarget: ${plan.url}`,
    };
  }
  if (cap === 'cors') {
    let targetHost = '';
    try {
      targetHost = new URL(lead.url).hostname;
    } catch {
      targetHost = 'target';
    }
    const testOrigins = [
      'null',
      'https://evil.tld',
      `https://${targetHost}.evil.tld`,
      `https://evil${targetHost}`,
    ];
    return {
      capability: 'cors',
      targetUrl: lead.url,
      maxRequests: testOrigins.length,
      testOrigins,
      method: 'GET',
      credentials: 'omit',
      redirect: 'manual',
      description:
        `Send up to ${testOrigins.length} read-only GET requests (no cookies, redirects not followed) to test whether arbitrary origins are reflected with credentials.\n` +
        `Target URL: ${lead.url}\n` +
        `Test Origins:\n` +
        testOrigins.map((o) => ` - ${o}`).join('\n') +
        `\nOnly reported if both ACAO reflects the test origin and ACAC is true.`,
    };
  }
  return undefined;
}

export function planSourceMapUrl(lead: Lead): string | undefined {
  const ref = lead.evidence.preview as string;
  if (typeof ref !== 'string' || ref.length === 0 || ref.startsWith('data:')) return undefined;
  try {
    const u = new URL(ref, lead.url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
    // Query values were masked ("***") at detection time; a signed map URL cannot be replayed from masked data.
    if (u.search.includes('***')) return undefined;
    return u.toString();
  } catch {
    return undefined;
  }
}

export function planBucketUrl(lead: Lead): { url: string; provider: 'aws' | 'gcp' } | undefined {
  const name = lead.evidence.extractedNames?.[0];
  if (name === undefined || !/^[a-z0-9][a-z0-9._-]{1,62}$/.test(name)) return undefined;
  if (lead.tags.includes('aws')) return { url: `https://${name}.s3.amazonaws.com/?max-keys=0`, provider: 'aws' };
  if (lead.tags.includes('gcp')) return { url: `https://storage.googleapis.com/${name}/?max-keys=0`, provider: 'gcp' };
  return undefined;
}

function merge(base: LeadVerdict, active: ActiveResult, now: number): LeadVerdict {
  // Passive vetoes (researcher triage, expired token, ...) are never overridden by a probe.
  if (base.status === 'false_positive') return base;
  if (!active.ran) {
    // The probe never reached the target: keep the passive judgement, record why, and keep every open item.
    return {
      ...base,
      summary: `${base.summary} Active check not completed: ${active.summary}`,
      checks: [...base.checks, ...active.checks],
      missing: [...new Set([...base.missing, ...active.missing])],
      verifiedAt: now,
    };
  }
  const scope = base.scopeStatus;
  let finalStatus = active.status;
  let finalAssessment: SecurityAssessment =
    active.status === 'confirmed'
      ? 'confirmed'
      : active.status === 'likely'
        ? 'likely'
        : active.status === 'informational'
          ? 'informational'
          : active.status === 'false_positive'
            ? 'false_positive'
            : 'unreviewed';

  if (scope !== 'in-scope') {
    if (finalAssessment === 'confirmed') finalAssessment = 'unreviewed';
    if (finalStatus === 'confirmed') finalStatus = scope === 'unknown' ? 'likely' : 'uncertain';
  }

  return {
    status: finalStatus,
    evidenceStatus:
      active.evidenceStatus !== undefined
        ? active.evidenceStatus
        : active.status === 'confirmed' || active.status === 'likely' || active.status === 'informational'
          ? 'reproduced'
          : 'inconclusive',
    scopeStatus: scope,
    securityAssessment: finalAssessment,
    method: 'active',
    summary: active.summary,
    checks: [...base.checks, ...active.checks],
    missing:
      finalStatus === 'confirmed' && scope === 'in-scope'
        ? []
        : finalStatus === 'false_positive'
          ? []
          : [...new Set(active.missing.length > 0 ? active.missing : base.missing)],
    verifiedAt: now,
  };
}

export async function verifyLeadActive(lead: Lead, deps: ActiveVerifyDeps): Promise<LeadVerdict> {
  const now = deps.now !== undefined ? deps.now() : Date.now();
  const base = verifyLeadPassive(lead, now);
  if (base.status === 'false_positive') return base;

  if (deps.approvedPlan !== undefined) {
    const planned = planActiveProbe(lead);
    if (!matchProbePlan(planned, deps.approvedPlan)) {
      return {
        status: 'uncertain',
        evidenceStatus: 'inconclusive',
        scopeStatus: base.scopeStatus,
        securityAssessment: 'unreviewed',
        method: 'active',
        summary: 'Rejected: approved probe plan does not match current target plan (stale or altered lead state).',
        checks: [
          ...base.checks,
          check('plan-binding', 'fail', 'Approved plan does not match current plan computed from stored lead.'),
        ],
        missing: ['Re-open the lead verification dialog and review the updated target plan.'],
        verifiedAt: now,
      };
    }
  }

  const cap = activeCapabilityOf(lead);
  let result: ActiveResult;

  if (cap === 'sourcemap') {
    const target = planSourceMapUrl(lead);
    if (target === undefined) {
      result = {
        status: base.status,
        summary: 'source map URL cannot be reconstructed safely (masked or non-http).',
        checks: [check('sourcemap-plan', 'inconclusive', 'Could not derive a replayable map URL.')],
        missing: base.missing,
        ran: false,
      };
    } else {
      const scope = deps.resolveScope(target);
      const outcome = await deps.probe(
        {
          targetUrl: target,
          method: 'GET',
          headers: { Range: `bytes=0-${BODY_SAMPLE_BYTES - 1}` },
          reason: 'Verify whether the referenced source map is publicly retrievable',
          leadId: lead.id,
        },
        scope,
        BODY_SAMPLE_BYTES,
      );
      result = interpretSourceMapProbe(outcome);
    }
  } else if (cap === 'bucket') {
    const plan = planBucketUrl(lead);
    if (plan === undefined) {
      result = {
        status: base.status,
        summary: 'bucket name is not a safely probeable identifier.',
        checks: [check('bucket-plan', 'inconclusive', 'Bucket name failed validation.')],
        missing: base.missing,
        ran: false,
      };
    } else {
      const scope = deps.resolveScope(plan.url);
      const outcome = await deps.probe(
        { targetUrl: plan.url, method: 'GET', reason: 'Verify whether the referenced bucket allows anonymous listing (max-keys=0)', leadId: lead.id },
        scope,
        BODY_SAMPLE_BYTES,
      );
      result = interpretBucketProbe(outcome, plan.provider);
    }
  } else if (cap === 'cors') {
    const scope = deps.resolveScope(lead.url);
    result = interpretCorsProbes(await deps.corsProbe(lead.url, scope));
  } else {
    result = {
      status: base.status,
      summary: 'no safe automated check exists for this lead type.',
      checks: [check('no-active-check', 'inconclusive', 'ACULYX has no read-only active test for this rule; verify manually.')],
      missing: base.missing,
      ran: false,
    };
  }

  return merge(base, result, now);
}
