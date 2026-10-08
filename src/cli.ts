import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import process from 'node:process';
import packageInfo from '../package.json';
import fixesData from '../fixes.json';
import { runRules } from './rules/engine';
import type { CookieRecord, Finding, Hop, Grade, ScoreBreakdown, SubdomainTrustAnalysis, BaselineMetadata } from './shared/types';

interface CliInput {
  url: string;
  status?: number;
  headers: Record<string, string>;
  cookies?: CookieRecord[];
}

interface FixSuggestion {
  summary: string;
  snippet?: string;
  note?: string;
}

export interface CliReport {
  generatedAt: string;
  target: string;
  score: number;
  grade: Grade;
  qualityScore: number;
  qualityGrade: Grade;
  scoreVersion: string;
  scoreBreakdown: ScoreBreakdown[];
  findings: Array<Finding & { fix?: FixSuggestion }>;
  subdomainTrust: SubdomainTrustAnalysis;
  metadata?: BaselineMetadata;
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: { driver: { name: string; version: string; informationUri: string; rules: Array<Record<string, unknown>> } };
    results: Array<Record<string, unknown>>;
    properties: Record<string, unknown>;
  }>;
}

const ruleFixes = fixesData.rules as Record<string, FixSuggestion>;
const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (lower === 'set-cookie' || lower === 'authorization' || lower === 'proxy-authorization') {
      result[lower] = '[redacted]';
    } else {
      result[lower] = value;
    }
  }
  return result;
}

export function redactResponseHeaders(source: Headers): Record<string, string> {
  const headers: Record<string, string> = {};
  source.forEach((value, name) => {
    const lower = name.toLowerCase();
    headers[lower] = (lower === 'set-cookie' || lower === 'authorization' || lower === 'proxy-authorization')
      ? '[redacted]'
      : value;
  });
  return headers;
}

function redactHarHeaders(value: unknown): Record<string, string> {
  if (!Array.isArray(value)) throw new Error('HAR response headers must be an array.');
  const headers: Record<string, string> = {};
  for (const headerValue of value) {
    const header = requireRecord(headerValue, 'HAR response header');
    if (typeof header.name !== 'string' || typeof header.value !== 'string') continue;
    const name = header.name.toLowerCase();
    const sanitizedValue = name === 'set-cookie' ? '[redacted]' : header.value;
    headers[name] = headers[name] === undefined
      ? sanitizedValue
      : name === 'set-cookie'
        ? '[redacted]'
        : `${headers[name]}, ${sanitizedValue}`;
  }
  return headers;
}

function normalizeMatchUrl(value: string): string {
  const url = new URL(value);
  url.hash = '';
  return url.href;
}

export function selectHarInput(harData: unknown, targetUrl: string): CliInput {
  const root = requireRecord(harData, 'HAR file');
  const log = requireRecord(root.log, 'HAR log');
  const entriesValue: unknown = log.entries;
  if (!Array.isArray(entriesValue)) throw new Error('HAR log requires an entries array.');
  const entries: unknown[] = entriesValue;
  const wantedUrl = normalizeMatchUrl(targetUrl);
  const matches = entries.filter((entryValue: unknown) => {
    const entry = requireRecord(entryValue, 'HAR entry');
    const request = requireRecord(entry.request, 'HAR request');
    return typeof request.url === 'string' && normalizeMatchUrl(request.url) === wantedUrl;
  });
  const selected = matches[matches.length - 1];
  if (selected === undefined) throw new Error(`No HAR response matched ${wantedUrl}.`);

  const entry = requireRecord(selected, 'HAR entry');
  const request = requireRecord(entry.request, 'HAR request');
  if (typeof request.url !== 'string') throw new Error('Selected HAR request requires a URL.');
  const requestUrl = request.url;
  const response = requireRecord(entry.response, 'HAR response');
  if (typeof response.status !== 'number') throw new Error('HAR response requires a numeric status.');
  const headers = redactHarHeaders(response.headers);
  const hostname = new URL(requestUrl).hostname;
  const cookies = Array.isArray(response.cookies)
    ? response.cookies.map((cookieValue) => {
      const cookie = requireRecord(cookieValue, 'HAR response cookie');
      const expiry = typeof cookie.expires === 'string' ? Date.parse(cookie.expires) : Number.NaN;
      return normalizeCookie({
        name: cookie.name,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: typeof cookie.sameSite === 'string' ? cookie.sameSite.toLowerCase() : '',
        session: !Number.isFinite(expiry),
        expiresAt: Number.isFinite(expiry) ? expiry : null,
        partitioned: false,
        setByJs: false,
        isThirdParty: false,
      }, hostname);
    })
    : [];

  return {
    url: requestUrl,
    status: response.status,
    headers,
    cookies,
  };
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function normalizeCookie(value: unknown, pageHostname: string): CookieRecord {
  const cookie = requireRecord(value, 'Each cookie');
  if ('value' in cookie) {
    throw new Error('Cookie values are not accepted. Supply attributes only.');
  }
  if (typeof cookie.name !== 'string' || cookie.name.length === 0) {
    throw new Error('Each cookie requires a non-empty name.');
  }
  if (cookie.domain !== undefined && typeof cookie.domain !== 'string') {
    throw new Error(`Cookie ${cookie.name} has an invalid domain.`);
  }
  const sameSite = cookie.sameSite;
  if (sameSite !== undefined && sameSite !== '' && sameSite !== 'strict' && sameSite !== 'lax' && sameSite !== 'none') {
    throw new Error(`Cookie ${cookie.name} has an invalid sameSite value.`);
  }

  return {
    name: cookie.name,
    domain: typeof cookie.domain === 'string' ? cookie.domain : pageHostname,
    domainAttributePresent: typeof cookie.domainAttributePresent === 'boolean' ? cookie.domainAttributePresent : null,
    path: typeof cookie.path === 'string' ? cookie.path : '/',
    secure: cookie.secure === true,
    httpOnly: cookie.httpOnly === true,
    sameSite: sameSite === 'strict' || sameSite === 'lax' || sameSite === 'none' ? sameSite : '',
    session: cookie.session === true,
    expiresAt: typeof cookie.expiresAt === 'number' ? cookie.expiresAt : null,
    partitioned: cookie.partitioned === true,
    setByJs: typeof cookie.setByJs === 'boolean' ? cookie.setByJs : null,
    isThirdParty: cookie.isThirdParty === true,
  };
}

function validateInput(input: CliInput): { url: URL; status: number; headers: Record<string, string>; cookies: CookieRecord[] } {
  const url = new URL(input.url);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http:// and https:// targets can be audited.');
  }
  const status = input.status ?? 200;
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    throw new Error('status must be an HTTP status code from 100 to 599.');
  }
  if (typeof input.headers !== 'object' || input.headers === null || Array.isArray(input.headers)) {
    throw new Error('headers must be a JSON object of header names to string values.');
  }

  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.headers)) {
    if (typeof value !== 'string') throw new Error(`Header ${name} must have a string value.`);
    headers[name.toLowerCase()] = name.toLowerCase() === 'set-cookie' ? '[redacted]' : value;
  }
  if (!Array.isArray(input.cookies ?? [])) throw new Error('cookies must be an array of cookie attributes.');
  const cookies = (input.cookies ?? []).map((cookie) => normalizeCookie(cookie, url.hostname));
  return { url, status, headers, cookies };
}

export function buildCliReport(input: CliInput): CliReport {
  const validated = validateInput(input);
  const rawHeaders = Object.entries(validated.headers).map(([name, value]) => ({
    name,
    value: name === 'set-cookie' ? '[redacted]' : value,
  }));
  const hop: Hop = {
    requestId: 'cli',
    url: validated.url.href,
    status: validated.status,
    headers: validated.headers,
    rawHeaders,
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
    redirectCount: 0,
  };
  const result = runRules({ 
    hops: [hop], 
    cookies: validated.cookies, 
    origin: validated.url.origin,
    cookieSettings: { alwaysSensitive: [], alwaysIgnore: [] }
  });

  return {
    generatedAt: new Date().toISOString(),
    target: validated.url.href,
    score: result.score,
    grade: result.grade,
    qualityScore: result.qualityScore,
    qualityGrade: result.qualityGrade,
    scoreVersion: result.scoreVersion,
    scoreBreakdown: result.breakdown,
    findings: result.findings.map((finding) => {
      const fix = ruleFixes[finding.ruleId];
      return fix ? { ...finding, fix } : finding;
    }),
    subdomainTrust: result.subdomainTrust,
    metadata: {
      schemaVersion: '2',
      rulesetVersion: result.scoreVersion,
      captureScope: 'document',
      coverageHopsExpected: 1,
      coverageHopsCaptured: 1,
    },
  };
}

export function formatMarkdown(report: CliReport): string {
  const lines = [
    `# ACULYX audit: ${report.target}`,
    '',
    `**Grade:** ${report.grade}  `,
    `**Score:** ${report.score}/100  `,
    `**Configuration quality:** ${report.qualityGrade} (${report.qualityScore}/100)  `,
    `**Generated:** ${report.generatedAt}`,
    '',
    `## Findings (${report.findings.length})`,
  ];

  if (report.findings.length === 0) lines.push('', 'No findings were produced.');
  for (const finding of report.findings) {
    lines.push('', `### [${finding.severity.toUpperCase()}] ${finding.title}`, '', `- Rule: ${finding.ruleId}`);
    if (finding.evidence.length > 0) lines.push(`- Evidence: ${finding.evidence}`);
    lines.push(`- Recommendation: ${finding.recommendation}`);
    const fix = finding.fix;
    if (fix !== undefined) {
      lines.push('', `**Suggested fix:** ${fix.summary}`);
      if (fix.snippet !== undefined && fix.snippet.length > 0) lines.push('', '```text', fix.snippet, '```');
      if (fix.note !== undefined && fix.note.length > 0) lines.push('', `> ${fix.note}`);
    }
  }

  lines.push('', '> Fix snippets are examples and require manual review; no files are modified.');
  return `${lines.join('\n')}\n`;
}

export function computeFindingFingerprint(finding: Finding, target: string): string {
  return createHash('sha256')
    .update(`${finding.ruleId}:${finding.sourceUrl ?? target}:${finding.title}`)
    .digest('hex');
}

export function formatSarif(report: CliReport): SarifLog {
  const rules = new Map<string, Finding>();
  for (const finding of report.findings) {
    if (!rules.has(finding.ruleId)) rules.set(finding.ruleId, finding);
  }
  const ruleList = [...rules.entries()];
  const ruleIndexes = new Map(ruleList.map(([ruleId], index) => [ruleId, index]));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ACULYX',
          version: packageInfo.version,
          informationUri: 'https://github.com/Gone27/Cookie-and-header-reader-extention',
          rules: ruleList.map(([ruleId, finding]) => ({
            id: ruleId,
            name: ruleId,
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.impact ?? finding.recommendation },
            helpUri: finding.reference,
            properties: { category: finding.category },
          })),
        },
      },
      results: report.findings.map((finding) => ({
        ruleId: finding.ruleId,
        ruleIndex: ruleIndexes.get(finding.ruleId),
        level: finding.severity === 'critical' || finding.severity === 'high'
          ? 'error'
          : finding.severity === 'medium'
            ? 'warning'
            : 'note',
        message: { text: `${finding.title}\n${finding.recommendation}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.sourceUrl ?? report.target } } }],
        partialFingerprints: {
          primaryLocationLineHash: computeFindingFingerprint(finding, report.target),
        },
        properties: {
          evidence: finding.evidence,
          impact: finding.impact,
          category: finding.category,
          confidence: finding.confidence ?? 'deterministic',
          provenance: finding.provenance,
          outcome: finding.outcome,
          scoreVersion: report.scoreVersion,
        },
      })),
      properties: {
        target: report.target,
        score: report.score,
        grade: report.grade,
        qualityScore: report.qualityScore,
        qualityGrade: report.qualityGrade,
        scoreVersion: report.scoreVersion,
      },
    }],
  };
}

export interface FindingDiff {
  target: string;
  baselineDate?: string | undefined;
  currentDate: string;
  baselineScore?: number | undefined;
  currentScore: number;
  scoreDelta?: number | undefined;
  regressions: Finding[];
  fixes: Finding[];
  unchanged: Finding[];
  changed: Array<{ before: Finding; after: Finding }>;
  warnings?: string[];
}

export function computeFindingDiff(baselineReport: CliReport, currentReport: CliReport): FindingDiff {
  const fullKey = (f: Finding) => `${f.ruleId}::${f.sourceUrl ?? ''}::${(f.evidence ?? '').slice(0, 80)}`;
  const ruleKey = (f: Finding) => `${f.ruleId}::${f.sourceUrl ?? ''}`;

  const remainingBaseline = [...baselineReport.findings];
  const remainingCurrent = [...currentReport.findings];

  const regressions: Finding[] = [];
  const unchanged: Finding[] = [];
  const fixes: Finding[] = [];
  const changed: Array<{ before: Finding; after: Finding }> = [];

  // 1. Exact matches (same identity & severity)
  for (let i = remainingCurrent.length - 1; i >= 0; i--) {
    const curr = remainingCurrent[i];
    if (curr === undefined) continue;
    const matchIdx = remainingBaseline.findIndex(
      (base) => fullKey(base) === fullKey(curr) && base.severity === curr.severity,
    );
    if (matchIdx !== -1) {
      unchanged.push(curr);
      remainingCurrent.splice(i, 1);
      remainingBaseline.splice(matchIdx, 1);
    }
  }

  // 2. Modified matches (same rule and source, but severity or evidence evolved)
  for (let i = remainingCurrent.length - 1; i >= 0; i--) {
    const curr = remainingCurrent[i];
    if (curr === undefined) continue;
    const matchIdx = remainingBaseline.findIndex((base) => ruleKey(base) === ruleKey(curr));
    if (matchIdx !== -1) {
      const before = remainingBaseline[matchIdx];
      if (before !== undefined) {
        changed.push({ before, after: curr });
      }
      remainingCurrent.splice(i, 1);
      remainingBaseline.splice(matchIdx, 1);
    }
  }

  // 3. New findings in current (regressions)
  regressions.push(...remainingCurrent);

  // 4. Resolved findings from baseline (fixes)
  fixes.push(...remainingBaseline);

  const warnings: string[] = [];
  const baseHops = baselineReport.metadata?.coverageHopsCaptured;
  const currHops = currentReport.metadata?.coverageHopsCaptured;
  if (baseHops !== undefined && currHops !== undefined && currHops < baseHops) {
    warnings.push(`comparison incomplete (coverage decreased from ${baseHops} to ${currHops})`);
  }

  return {
    target: currentReport.target,
    baselineDate: baselineReport.generatedAt,
    currentDate: currentReport.generatedAt,
    baselineScore: baselineReport.score,
    currentScore: currentReport.score,
    scoreDelta: currentReport.score - baselineReport.score,
    regressions,
    fixes,
    unchanged,
    changed,
    warnings,
  };
}

export interface AuditBundle {
  bundleVersion: '1.0.0';
  generatedAt: string;
  target: string;
  score: number;
  grade: Grade;
  qualityScore: number;
  qualityGrade: Grade;
  scoreVersion: string;
  findings: Array<Finding & { fix?: FixSuggestion }>;
  redactedHeaders: Record<string, string>;
  subdomainTrust: SubdomainTrustAnalysis;
  /** SHA-256 content checksum of the canonical representation of all bundle fields. */
  integrityChecksum: string;
  /** Backward-compatible alias for integrityChecksum. */
  integrityHash?: string;
}

export function computeBundleChecksum(payload: Omit<AuditBundle, 'integrityChecksum' | 'integrityHash'>): string {
  const canonicalJson = JSON.stringify(payload, (_key, val: unknown) => {
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      const obj = val as Record<string, unknown>;
      return Object.keys(obj)
        .sort()
        .reduce<Record<string, unknown>>((acc, k) => {
          acc[k] = obj[k];
          return acc;
        }, {});
    }
    return val;
  });
  return createHash('sha256').update(canonicalJson).digest('hex');
}

export function buildAuditBundle(report: CliReport, headers: Record<string, string>): AuditBundle {
  // Always guarantee case-insensitive redaction of Set-Cookie and sensitive headers
  const cleanHeaders = redactHeaders(headers);

  const payload: Omit<AuditBundle, 'integrityChecksum' | 'integrityHash'> = {
    bundleVersion: '1.0.0',
    generatedAt: report.generatedAt,
    target: report.target,
    score: report.score,
    grade: report.grade,
    qualityScore: report.qualityScore,
    qualityGrade: report.qualityGrade,
    scoreVersion: report.scoreVersion,
    findings: report.findings,
    redactedHeaders: cleanHeaders,
    subdomainTrust: report.subdomainTrust,
  };
  const integrityChecksum = computeBundleChecksum(payload);

  return {
    ...payload,
    integrityChecksum,
    integrityHash: integrityChecksum,
  };
}

export function verifyAuditBundle(bundle: AuditBundle): boolean {
  const payload: Record<string, unknown> = { ...bundle };
  delete payload.integrityChecksum;
  delete payload.integrityHash;
  const expected = computeBundleChecksum(payload as unknown as Omit<AuditBundle, 'integrityChecksum' | 'integrityHash'>);
  return bundle.integrityChecksum === expected;
}

export function shouldFail(findings: Finding[], failOn: string): boolean {
  const threshold = severityOrder.indexOf(failOn as typeof severityOrder[number]);
  return threshold >= 0 && findings.some((finding) => {
    const findingSeverity = severityOrder.indexOf(finding.severity as typeof severityOrder[number]);
    return findingSeverity >= 0 && findingSeverity <= threshold;
  });
}

interface CliOptions {
  input?: string | undefined;
  har?: string | undefined;
  url?: string | undefined;
  diff?: string | undefined;
  bundle: boolean;
  format: 'json' | 'markdown' | 'sarif';
  failOn: string;
  help: boolean;
}

function parseArguments(args: string[]): CliOptions {
  const options: CliOptions = {
    bundle: false,
    format: 'json',
    failOn: 'high',
    help: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--bundle') options.bundle = true;
    else if (
      argument === '--input' ||
      argument === '--har' ||
      argument === '--url' ||
      argument === '--diff' ||
      argument === '--format' ||
      argument === '--fail-on'
    ) {
      const value = args[index + 1];
      if (value === undefined || value.length === 0 || value.startsWith('--')) throw new Error(`${argument} requires a value.`);
      index += 1;
      if (argument === '--input') options.input = value;
      else if (argument === '--har') options.har = value;
      else if (argument === '--url') options.url = value;
      else if (argument === '--diff') options.diff = value;
      else if (argument === '--format') {
        if (value !== 'json' && value !== 'markdown' && value !== 'sarif') throw new Error('--format must be json, markdown, or sarif.');
        options.format = value;
      } else options.failOn = value;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options;
}

async function loadInput(options: { input?: string | undefined; har?: string | undefined; url?: string | undefined }): Promise<CliInput> {
  if (options.input !== undefined) {
    const parsed: unknown = JSON.parse(await readFile(resolve(options.input), 'utf8'));
    const input = requireRecord(parsed, 'Input file');
    if (typeof input.url !== 'string') throw new Error('Input JSON requires a url string.');
    if (input.status !== undefined && typeof input.status !== 'number') throw new Error('Input status must be a number.');
    if (typeof input.headers !== 'object' || input.headers === null || Array.isArray(input.headers)) {
      throw new Error('Input JSON requires a headers object.');
    }
    return input as unknown as CliInput;
  }

  if (options.har !== undefined) {
    if (options.url === undefined) throw new Error('--har requires --url to select the captured request to audit.');
    const parsed: unknown = JSON.parse(await readFile(resolve(options.har), 'utf8'));
    return selectHarInput(parsed, options.url);
  }

  if (options.url === undefined) throw new Error('Provide exactly one of --url or --input.');
  const target = new URL(options.url);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error('Only http:// and https:// targets can be audited.');
  }
  const response = await fetch(target, { signal: AbortSignal.timeout(15_000) });
  const headers = redactResponseHeaders(response.headers);
  return { url: response.url, status: response.status, headers, cookies: [] };
}

const usage = `ACULYX CLI
Header & Cookie Security Checker

Usage:
  npm run aculyx -- --url https://example.com [--format json|markdown|sarif] [--fail-on critical|high|medium|low|info|never]
  npm run aculyx -- --input audit.json [--format json|markdown|sarif] [--fail-on ...]
  npm run aculyx -- --har capture.har --url https://example.com/path [--format json|markdown|sarif] [--fail-on ...]
  npm run aculyx -- --input current.json --diff baseline.json [--format json|markdown]
  npm run aculyx -- --input audit.json --bundle

Legacy alias:
  npm run seccheck -- [args]

Input JSON: { "url": "https://example.com", "status": 200, "headers": {}, "cookies": [] }
URL mode makes one explicit HTTP request and follows redirects. JSON and HAR input modes are offline; HAR mode selects the most recent exact URL match.
Cookie inputs must contain attributes only; cookie values are rejected.\n`;
const helpExitCodes = `Exit codes:
  0  No finding met --fail-on (or in --diff mode, no new regression met --fail-on).
  1  At least one finding met or exceeded --fail-on.
  2  Invalid arguments/input or a scan error.
Default --fail-on is high, so critical and high findings return 1.\n`;

async function main(args: string[]): Promise<void> {
  const options = parseArguments(args);
  if (options.help) {
    process.stdout.write(`${usage}\n${helpExitCodes}`);
    return;
  }
  const hasInput = options.input !== undefined;
  const hasHar = options.har !== undefined;
  const hasUrl = options.url !== undefined;
  if (hasInput && hasHar) throw new Error('Choose either --input or --har, not both.');
  if (hasHar && !hasUrl) throw new Error('--har requires --url to select the captured request to audit.');
  if (hasInput === hasUrl) throw new Error('Provide exactly one of --url or --input.');
  const validFailureLevels: readonly string[] = [...severityOrder, 'never'];
  if (!validFailureLevels.includes(options.failOn)) {
    throw new Error('--fail-on must be critical, high, medium, low, info, or never.');
  }

  const rawInput = await loadInput(options);
  const report = buildCliReport(rawInput);

  if (options.bundle) {
    const bundle = buildAuditBundle(report, rawInput.headers);
    process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
    return;
  }

  if (options.diff !== undefined) {
    const baselineParsed: unknown = JSON.parse(await readFile(resolve(options.diff), 'utf8'));
    const baselineReport = requireRecord(baselineParsed, 'Baseline report') as unknown as CliReport;
    const diff = computeFindingDiff(baselineReport, report);
    if (options.format === 'markdown') {
      const md = [
        `# ACULYX Regression Diff: ${diff.target}`,
        '',
        `**Baseline Score:** ${diff.baselineScore ?? 'N/A'} -> **Current Score:** ${diff.currentScore} (Delta: ${diff.scoreDelta ?? 0})`,
        '',
        `## Regressions (New Findings): ${diff.regressions.length}`,
        ...(diff.regressions.length === 0 ? ['No new regressions detected.'] : diff.regressions.map((f) => `- [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.title}`)),
        '',
        `## Resolved (Fixed Findings): ${diff.fixes.length}`,
        ...(diff.fixes.length === 0 ? ['No previously flagged findings were resolved.'] : diff.fixes.map((f) => `- [FIXED] ${f.ruleId}: ${f.title}`)),
        '',
        ...(diff.changed.length > 0 ? [
          `## Modified Findings: ${diff.changed.length}`,
          ...diff.changed.map((c) => `- [${c.before.severity.toUpperCase()} -> ${c.after.severity.toUpperCase()}] ${c.after.ruleId}: ${c.after.title}`),
          '',
        ] : []),
        `## Persistent Findings: ${diff.unchanged.length}`,
      ];
      if (diff.warnings && diff.warnings.length > 0) {
        md.splice(2, 0, '', ...diff.warnings.map(w => `> [!WARNING]\n> ${w}`));
      }
      process.stdout.write(`${md.join('\n')}\n`);
    } else {
      process.stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
    }
    if (shouldFail(diff.regressions, options.failOn)) process.exitCode = 1;
    return;
  }

  const output = options.format === 'sarif'
    ? formatSarif(report)
    : options.format === 'markdown'
      ? formatMarkdown(report)
      : report;
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);

  if (shouldFail(report.findings, options.failOn)) process.exitCode = 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void main(process.argv.slice(2)).catch((error: unknown) => {
    process.stderr.write(`ACULYX CLI: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  });
}