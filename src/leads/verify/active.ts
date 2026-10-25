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
}

interface ActiveResult {
  status: VerdictStatus;
  summary: string;
  checks: VerdictCheck[];
  missing: string[];
  /** false when every probe was blocked/failed before reaching the target. */
  ran: boolean;
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
  if (st === 401 || st === 403 || st === 404 || st === 410) {
    return {
      status: 'false_positive',
      summary: `Source map is not retrievable without authentication (HTTP ${st}).`,
      checks: [check('sourcemap-fetch', 'fail', `GET returned HTTP ${st}.`)],
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
    const looksLikeMap = /"version"\s*:\s*3/.test(body) && /"sources"\s*:\s*\[/.test(body);
    if (looksLikeMap) {
      const hasContent = /"sourcesContent"\s*:\s*\[/.test(body);
      return {
        status: 'confirmed',
        summary: hasContent
          ? 'Source map is publicly downloadable and embeds original source (sourcesContent).'
          : 'Source map is publicly downloadable (original file paths exposed).',
        checks: [
          check('sourcemap-fetch', 'pass', `HTTP ${st}, valid source-map structure (version 3, sources[]).`),
          check(
            'sourcemap-content',
            hasContent ? 'pass' : 'inconclusive',
            hasContent ? 'sourcesContent present in first bytes.' : 'sourcesContent not seen in the sampled bytes.',
          ),
        ],
        missing: [],
        ran: true,
      };
    }
    return {
      status: 'uncertain',
      summary: 'URL answered HTTP 200 but body does not match source-map v3 format.',
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
      status: 'false_positive',
      summary: 'Bucket exists but denies anonymous listing (default-secure).',
      checks: [check('bucket-list', 'fail', `HTTP ${st} AccessDenied. Individual object ACLs were not tested.`)],
      missing: [],
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
    missing: ['Check whether the originally reflected origin is attacker-controllable (e.g. subdomain takeover, wildcard match).'],
    ran: true,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Planning + orchestration
// ---------------------------------------------------------------------------------------------------------------

export type ActiveCapability = 'sourcemap' | 'bucket' | 'cors' | 'none';

export function activeCapabilityOf(lead: Lead): ActiveCapability {
  if (lead.ruleId === 'MAP-001') return 'sourcemap';
  if (lead.ruleId === 'CLD-001' && (lead.tags.includes('aws') || lead.tags.includes('gcp'))) return 'bucket';
  if (lead.ruleId === 'COR-001' && lead.tags.includes('cors-reflection')) return 'cors';
  return 'none';
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
    evidenceStatus: active.status === 'confirmed' ? 'reproduced' : 'inconclusive',
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
