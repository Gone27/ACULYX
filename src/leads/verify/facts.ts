/**
 * Detection-time fact extraction.
 *
 * Detectors mask secrets immediately, so a later verification pass can no longer look at the raw value.
 * To still make evidence-based judgements (checksum, entropy, "is this inside an example snippet?")
 * we compute a few NON-SENSITIVE derived facts while the raw text is still in memory, and keep only those.
 * The raw value never leaves this module.
 */
import type { Lead, LeadFacts } from '../types';
import { maskSecret } from '../sieve/mask';
import { validateCrc32Base62Token } from './checksums';

const PREVIEW_RE = /^(.{1,8})\.\.\.(.{1,4}) \(len (\d+)\) \[([0-9a-f]{16})\]$/;
const MAX_SCAN_STEPS = 4000;
const CONTEXT_WINDOW = 80;

const EXAMPLE_CONTEXT_RE =
  /(?:\bexample\b|\bsample\b|\bplaceholder\b|\bdummy\b|\bfake\b|\blorem\b|\bchange[_-]?me\b|\breplace[_ -]?(?:me|with|this)\b|\byour[_ -]?(?:api[_ -]?)?(?:key|token|secret)\b|\be\.g\.|\bfor (?:testing|demo)\b|\bdocs?\.|\bREADME\b|\bxxx+)/i;

export function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of str) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Finds the raw string a masked preview was produced from by re-hashing candidate substrings of `code`.
 * Cheap pre-filters (prefix, length, suffix) keep the SHA-256 count tiny.
 */
export function locateRawFromPreview(code: string, preview: string): { raw: string; index: number } | undefined {
  const m = PREVIEW_RE.exec(preview);
  if (m === null) return undefined;
  const head = m[1];
  const tail = m[2];
  const lenStr = m[3];
  if (head === undefined || tail === undefined || lenStr === undefined) return undefined;
  const len = Number(lenStr);
  if (!Number.isFinite(len) || len < 7 || len > 4096) return undefined;

  let from = 0;
  for (let steps = 0; steps < MAX_SCAN_STEPS; steps++) {
    const i = code.indexOf(head, from);
    if (i < 0) return undefined;
    from = i + 1;
    if (i + len > code.length) return undefined;
    const cand = code.slice(i, i + len);
    if (!cand.endsWith(tail)) continue;
    if (maskSecret(cand) === preview) return { raw: cand, index: i };
  }
  return undefined;
}

function isInComment(code: string, index: number): boolean {
  const lineStart = code.lastIndexOf('\n', index - 1) + 1;
  const linePrefix = code.slice(lineStart, index).trimStart();
  if (linePrefix.startsWith('//') || linePrefix.startsWith('*') || linePrefix.startsWith('#')) return true;
  const open = code.lastIndexOf('<!--', index);
  if (open >= 0 && code.indexOf('-->', open) >= index) return true;
  const blockOpen = code.lastIndexOf('/*', index);
  if (blockOpen >= 0 && code.indexOf('*/', blockOpen) >= index) return true;
  return false;
}

function jwtFacts(raw: string): Pick<LeadFacts, 'jwtExpired' | 'jwtHasExp' | 'jwtAlg'> {
  const out: Pick<LeadFacts, 'jwtExpired' | 'jwtHasExp' | 'jwtAlg'> = {};
  const parts = raw.split('.');
  const decode = (seg: string | undefined): Record<string, unknown> | null => {
    if (seg === undefined || seg.length === 0) return null;
    try {
      let b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      const json = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('utf8');
      const v: unknown = JSON.parse(json);
      return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  };
  const header = decode(parts[0]);
  const payload = decode(parts[1]);
  if (header !== null && typeof header.alg === 'string') out.jwtAlg = header.alg.slice(0, 16).replace(/[^\w-]/g, '');
  if (payload !== null) {
    if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
      out.jwtHasExp = true;
      out.jwtExpired = payload.exp * 1000 < Date.now();
    } else {
      out.jwtHasExp = false;
    }
  }
  return out;
}

export function computeSecretFacts(raw: string, code: string, index: number): LeadFacts {
  const facts: LeadFacts = {
    length: raw.length,
    entropyBits: Math.round(shannonEntropy(raw) * 100) / 100,
    checksumValid: validateCrc32Base62Token(raw),
    inComment: isInComment(code, index),
  };

  // Context is judged on the SAME LINE only, so an unrelated "example" comment two lines away cannot taint a real key.
  const lineStart = code.lastIndexOf('\n', index - 1) + 1;
  const endIdx = index + raw.length;
  const nl = code.indexOf('\n', endIdx);
  const lineEnd = nl < 0 ? code.length : nl;
  const before = code.slice(Math.max(lineStart, index - CONTEXT_WINDOW), index);
  const after = code.slice(endIdx, Math.min(lineEnd, endIdx + CONTEXT_WINDOW));
  facts.exampleContext = EXAMPLE_CONTEXT_RE.test(before) || EXAMPLE_CONTEXT_RE.test(after);

  let count = 0;
  let pos = code.indexOf(raw);
  while (pos >= 0 && count < 50) {
    count++;
    pos = code.indexOf(raw, pos + raw.length);
  }
  facts.occurrences = count;

  if (raw.startsWith('eyJ')) Object.assign(facts, jwtFacts(raw));
  return facts;
}

/**
 * Post-pass used by detectSecrets: attaches derived facts to each lead whose masked preview can be traced
 * back to raw text in `code`. Leads that cannot be traced are left untouched (verification then relies on
 * the lead's own tier/needs only).
 */
export function attachSecretFacts(leads: Lead[], code: string): void {
  for (const lead of leads) {
    if (lead.facts !== undefined) continue;
    const found = locateRawFromPreview(code, lead.evidence.preview);
    if (found === undefined) continue;
    lead.facts = computeSecretFacts(found.raw, code, found.index);
  }
}
