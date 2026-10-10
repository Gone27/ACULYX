import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

const RFC1918_REGEX = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/;
const INTERNAL_HOST_REGEX = /\b[a-zA-Z0-9_\-.]+\.(?:internal|corp|local|svc\.cluster\.local|lan)\b/i;

const CSP_BYPASS_DOMAINS = [
  'herokuapp.com',
  'appspot.com',
  'github.io',
  'netlify.app',
  'vercel.app',
  'cloudfront.net',
  's3.amazonaws.com',
  'cdnjs.cloudflare.com',
  'unpkg.com',
];

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectHeaderLeads(
  headers: Record<string, string>,
  url: string,
  requestOrigin: string | null = null,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (!headers) return leads;

  // Normalize header keys to lowercase
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  // 1. COR-001 & COR-002: CORS Misconfigurations
  const acao = lowerHeaders['access-control-allow-origin'];
  const acac = lowerHeaders['access-control-allow-credentials'];
  const acam = lowerHeaders['access-control-allow-methods'];
  const aceh = lowerHeaders['access-control-expose-headers'];
  const vary = lowerHeaders['vary'];

  if (acao) {
    const isCredentialsTrue = acac?.trim().toLowerCase() === 'true';
    const reflectsOrigin = requestOrigin && acao.trim() === requestOrigin;
    const isNullOrigin = acao.trim() === 'null';
    const isHttpAllowed = acao.startsWith('http://');

    if ((reflectsOrigin || isNullOrigin || isHttpAllowed) && isCredentialsTrue) {
      leads.push({
        id: nextLeadId('COR-EXPLOIT'),
        ruleId: 'COR-001',
        family: 'F6',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: isNullOrigin
          ? 'CORS Misconfiguration: null Origin Allowed with Credentials'
          : 'CORS Misconfiguration: Arbitrary Origin Reflection with Credentials',
        needs: ['verify if authenticated responses contain confidential user data'],
        doesNotProve: ['unauthorized cross-origin data theft without authenticated session'],
        evidence: {
          preview: maskSecret(`ACAO: ${acao}, ACAC: ${acac}`),
          location: maskLocation(url),
          context: `ACAO reflects: ${acao}, credentials allowed`,
        },
        tags: ['cors', 'cors-reflection', 'cors-misconfig'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
        remediation: 'Do not dynamically reflect untrusted Origin values when ACAC is true. Use a strict origin whitelist.',
      });
    }

    if (reflectsOrigin && (!vary || !vary.toLowerCase().includes('origin'))) {
      leads.push({
        id: nextLeadId('COR-NOVARY'),
        ruleId: 'COR-001',
        family: 'F6',
        tier: 'strong',
        potential: 'medium',
        confidence: 0.85,
        title: 'Dynamic ACAO Header Disclosed Without Vary: Origin',
        needs: ['test web cache poisoning for CORS responses'],
        doesNotProve: ['cache poisoning without caching intermediary'],
        evidence: {
          preview: maskSecret(`ACAO: ${acao}`),
          location: maskLocation(url),
        },
        tags: ['cors', 'cors-cache-poisoning'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }

    // COR-002: Methods and exposed auth headers
    if (acam && isCredentialsTrue && /(PUT|DELETE|PATCH)/i.test(acam)) {
      leads.push({
        id: nextLeadId('COR-METHODS'),
        ruleId: 'COR-002',
        family: 'F6',
        tier: 'observed',
        potential: 'medium',
        confidence: 0.9,
        title: 'Credentialed CORS Permits State-Changing Methods (PUT/DELETE/PATCH)',
        needs: ['verify preflight requirement on endpoints'],
        doesNotProve: ['cross-origin data modification'],
        evidence: {
          preview: maskSecret(`ACAM: ${acam}`),
          location: maskLocation(url),
        },
        tags: ['cors', 'cors-methods'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }

    if (aceh && /(authorization|cookie|set-cookie|x-auth-token)/i.test(aceh)) {
      leads.push({
        id: nextLeadId('COR-EXPOSE'),
        ruleId: 'COR-002',
        family: 'F6',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'CORS Exposes Sensitive Authorization Headers to Scripts',
        needs: ['verify if JavaScript can read authorization header value cross-origin'],
        doesNotProve: ['credential theft'],
        evidence: {
          preview: maskSecret(`ACEH: ${aceh}`),
          location: maskLocation(url),
        },
        tags: ['cors', 'exposed-headers'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }
  }

  // 2. CSP-101: Bypass Domains in CSP
  const csp = lowerHeaders['content-security-policy'] || lowerHeaders['content-security-policy-report-only'];
  if (csp) {
    const matchedBypassDomains = CSP_BYPASS_DOMAINS.filter(d => csp.includes(d));
    if (matchedBypassDomains.length > 0) {
      leads.push({
        id: nextLeadId('CSP-BYPASS'),
        ruleId: 'CSP-101',
        family: 'F6',
        tier: 'strong',
        potential: 'medium',
        confidence: 0.8,
        title: `CSP Policy Allowlist Contains User-Controllable / CDN Host: ${matchedBypassDomains[0]}`,
        needs: ['verify if script-gadget or uploaded JSONP can be referenced'],
        doesNotProve: ['CSP execution bypass without injectable script tag'],
        evidence: {
          preview: maskSecret(matchedBypassDomains.join(', ')),
          location: maskLocation(url),
          extractedNames: matchedBypassDomains,
        },
        tags: ['csp', 'csp-bypass'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }
  }

  // 3. CAC-001: Authenticated-Looking Response with Public Caching
  const cacheControl = lowerHeaders['cache-control'];
  const hasAuth = lowerHeaders['authorization'] || lowerHeaders['set-cookie'];
  if (cacheControl && hasAuth) {
    if (/(public|s-maxage)/i.test(cacheControl) && !/no-store/i.test(cacheControl)) {
      leads.push({
        id: nextLeadId('CAC-AUTH'),
        ruleId: 'CAC-001',
        family: 'F6',
        tier: 'strong',
        potential: 'medium',
        confidence: 0.85,
        title: 'Authenticated Response Marked Publicly Cacheable',
        needs: ['test shared proxy / CDN cache retention for sensitive response'],
        doesNotProve: ['cache deception without shared cache intermediary'],
        evidence: {
          preview: maskSecret(cacheControl),
          location: maskLocation(url),
          context: `Cache-Control: ${cacheControl}`,
        },
        tags: ['caching', 'cacheable-auth'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }
  }

  // 4. INF-001: Internal RFC1918 / Private Hostname Disclosure
  for (const [headerName, headerVal] of Object.entries(lowerHeaders)) {
    const rfcMatch = headerVal.match(RFC1918_REGEX);
    const internalHostMatch = headerVal.match(INTERNAL_HOST_REGEX);

    if (rfcMatch || internalHostMatch) {
      const matchVal = (rfcMatch ? rfcMatch[0] : internalHostMatch?.[0]) || '';
      leads.push({
        id: nextLeadId('INF-IP'),
        ruleId: 'INF-001',
        family: 'F6',
        tier: 'observed',
        potential: 'low',
        confidence: 0.95,
        title: `Internal Network Address Disclosed in Header: ${headerName}`,
        needs: ['correlate internal IP with cloud SSRF leads'],
        doesNotProve: ['direct routability to internal IP'],
        evidence: {
          preview: maskSecret(`${headerName}: ${matchVal}`),
          location: maskLocation(url),
          context: `Disclosed in header '${headerName}'`,
          extractedNames: [matchVal],
        },
        tags: ['internal-ip', 'rfc1918', 'network-disclosure'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }
  }

  // 5. INF-002: Infrastructure Disclosures (Server-Timing, Via, X-Backend, X-Jenkins)
  const infraHeaders = ['server-timing', 'via', 'x-backend-server', 'x-debug-token', 'x-jenkins', 'x-powered-by'];
  for (const ih of infraHeaders) {
    if (lowerHeaders[ih]) {
      leads.push({
        id: nextLeadId('INF-HEADER'),
        ruleId: 'INF-002',
        family: 'F6',
        tier: 'observed',
        potential: 'info',
        confidence: 1.0,
        title: `Infrastructure Header Disclosed: ${ih}`,
        needs: ['reconnaissance only'],
        doesNotProve: ['vulnerability'],
        evidence: {
          preview: maskSecret(lowerHeaders[ih]),
          location: maskLocation(url),
        },
        tags: ['infrastructure', 'fingerprint'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }
  }

  return leads;
}
