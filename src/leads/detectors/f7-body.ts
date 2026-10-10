import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

const SENSITIVE_JSON_KEYS = /^(password|password_hash|passwd|hash|secret|token|ssn|social_security|dob|date_of_birth|role|isadmin|is_admin|internal_.*|private_key)$/i;

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectBodyLeads(
  body: string,
  contentType: string,
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (!body || typeof body !== 'string') return leads;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  // 1. ERR-001: Stack Traces & Debug Pages
  const errorSignatures = [
    { name: 'Python Traceback / Werkzeug', regex: /Traceback \(most recent call last\):|Werkzeug Debugger/i },
    { name: 'Java Stack Trace', regex: /\bat [a-zA-Z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)/ },
    { name: 'Laravel Error', regex: /Illuminate\\|Whoops! There was an error\./i },
    { name: 'Spring Whitelabel Error', regex: /Whitelabel Error Page/i },
    { name: 'ASP.NET YSOD', regex: /Server Error in ['\/].*Application|Yellow Screen of Death/i },
    { name: 'PHP Fatal Error / Warning', regex: /(?:Fatal error|Parse error|Warning):\s+.*in\s+.*\.php\s+on\s+line\s+\d+/i },
    { name: 'Django Debug', regex: /You're seeing this error because you have <code>DEBUG = True<\/code>/i },
  ];

  for (const sig of errorSignatures) {
    if (sig.regex.test(body)) {
      leads.push({
        id: nextLeadId('ERR-STACK'),
        ruleId: 'ERR-001',
        family: 'F7',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: `Detailed Debug Error Page / Stack Trace Disclosed (${sig.name})`,
        needs: ['review revealed source paths, framework versions, or internal queries'],
        doesNotProve: ['remote code execution'],
        evidence: {
          preview: maskSecret(`Disclosed ${sig.name}`),
          location: maskLocation(url),
          context: `Detected ${sig.name} in response body`,
        },
        tags: ['stack-trace', 'debug-page', 'error-disclosure'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url: (maskLocation(url) as string) || url,
        sourceSensor: 'S1',
        remediation: 'Disable debug mode and implement generic error pages in production.',
      });
      break; // Only one ERR-001 per response
    }
  }

  // 2. API-001: Excess Data Exposure in JSON Responses
  if (contentType.toLowerCase().includes('application/json') || body.trim().startsWith('{') || body.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(body);
      const sensitiveKeysFound = new Set<string>();

      const inspectObject = (obj: unknown, depth = 0) => {
        if (!obj || typeof obj !== 'object' || depth > 5) return;
        if (Array.isArray(obj)) {
          for (let i = 0; i < Math.min(obj.length, 5); i++) {
            inspectObject(obj[i], depth + 1);
          }
          return;
        }
        for (const [key, val] of Object.entries(obj)) {
          if (SENSITIVE_JSON_KEYS.test(key.trim())) {
            sensitiveKeysFound.add(key.trim());
          }
          if (typeof val === 'object' && val !== null) {
            inspectObject(val, depth + 1);
          }
        }
      };

      inspectObject(parsed);

      if (sensitiveKeysFound.size > 0) {
        const keyList = Array.from(sensitiveKeysFound);
        leads.push({
          id: nextLeadId('API-EXPOSURE'),
          ruleId: 'API-001',
          family: 'F7',
          tier: 'observed',
          potential: 'high',
          confidence: 0.9,
          title: `Excess Data Exposure: Sensitive JSON Properties Disclosed (${keyList.join(', ')})`,
          needs: ['verify if requesting user role is authorized to view these fields'],
          doesNotProve: ['privilege escalation without auth matrix verification'],
          evidence: {
            preview: maskSecret(`Found keys: ${keyList.join(', ')}`),
            location: maskLocation(url),
            extractedNames: keyList,
            context: `API returned ${keyList.length} sensitive property names. Raw values redacted.`,
          },
          tags: ['excessive-data', 'api-exposure', 'pii-exposure'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url: (maskLocation(url) as string) || url,
          sourceSensor: 'S1',
          remediation: 'Use explicit DTO/serializer allowlists rather than serializing internal entities directly.',
        });
      }
    } catch {
      // Body was not valid JSON, ignore
    }
  }

  // 3. TECH-001: Banner fingerprints
  if (body.includes('"cluster_name"') && body.includes('"version"')) {
    leads.push({
      id: nextLeadId('TECH-ELASTIC'),
      ruleId: 'TECH-001',
      family: 'F7',
      tier: 'observed',
      potential: 'info',
      confidence: 1.0,
      title: 'Elasticsearch Cluster Banner Disclosed',
      needs: ['reconnaissance only'],
      doesNotProve: ['unauthenticated Elasticsearch access'],
      evidence: {
        preview: maskSecret('Elasticsearch cluster info'),
        location: maskLocation(url),
      },
      tags: ['banner', 'elasticsearch'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: (maskLocation(url) as string) || url,
      sourceSensor: 'S1',
    });
  }

  return leads;
}
