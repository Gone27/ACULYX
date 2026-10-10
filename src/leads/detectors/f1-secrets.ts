import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

export function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of str) {
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const PLACEHOLDER_PATTERNS = [
  /YOUR_/i,
  /EXAMPLE/i,
  /xxxx+/i,
  /123456/i,
  /test/i,
  /dummy/i,
  /SAMPLE/i,
  /CHANGE_ME/i,
  /<[^>]+>/,
  /(.)\1{5,}/, // repeated char 6+ times
];

export function isPlaceholder(val: string): boolean {
  for (const pattern of PLACEHOLDER_PATTERNS) {
    if (pattern.test(val)) return true;
  }
  return false;
}

function parseJwtHeader(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    let b64 = parts[0].replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    const json = typeof atob !== 'undefined'
      ? atob(b64)
      : Buffer.from(b64, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectSecrets(
  code: string,
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (!code || typeof code !== 'string') return leads;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  // 1. PUBLIC-BY-DESIGN IDENTIFIERS (classify as info, NEVER secret)
  const stripePkMatches = code.match(/\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g);
  if (stripePkMatches) {
    for (const match of stripePkMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('PUB-STRIPE'),
        ruleId: 'SEC-001-PUB',
        family: 'F1',
        tier: 'observed',
        potential: 'info',
        confidence: 1.0,
        title: 'Stripe Publishable Key Identified',
        needs: [],
        doesNotProve: ['secret exposure', 'unauthorized access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Public client-side publishable key',
        },
        tags: ['stripe', 'public-key', 'observed'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: 'Publishable keys are intended for browser usage; verify no secret key is exposed.',
      });
    }
  }

  const mapboxMatches = code.match(/\bpk\.[0-9a-zA-Z\-_]{30,}\b/g);
  if (mapboxMatches) {
    for (const match of mapboxMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('PUB-MAPBOX'),
        ruleId: 'SEC-001-PUB',
        family: 'F1',
        tier: 'observed',
        potential: 'info',
        confidence: 1.0,
        title: 'Mapbox Public Access Token Identified',
        needs: [],
        doesNotProve: ['secret exposure'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Public client map token',
        },
        tags: ['mapbox', 'public-key', 'observed'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  const sentryMatches = code.match(/\bhttps:\/\/[0-9a-f]{32}@[^/]+\/[0-9]+\b/g);
  if (sentryMatches) {
    for (const match of sentryMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('PUB-SENTRY'),
        ruleId: 'SEC-001-PUB',
        family: 'F1',
        tier: 'observed',
        potential: 'info',
        confidence: 1.0,
        title: 'Sentry DSN Public Identifier',
        needs: [],
        doesNotProve: ['secret exposure'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Sentry DSN client configuration',
        },
        tags: ['sentry', 'dsn', 'observed'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // 2. SEC-001: VENDOR-PREFIXED SECRETS
  // AWS Access Key ID
  const awsMatches = code.match(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g);
  if (awsMatches) {
    for (const match of awsMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-AWS'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'AWS Access Key ID Exposure',
        needs: ['verify if corresponding secret key is accessible or permissions active'],
        doesNotProve: ['active AWS IAM permissions without secret access key'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: `Found AWS Key ID ${match.slice(0, 4)}...`,
        },
        tags: ['aws', 'secret', 'credentials'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: 'Immediately rotate this AWS credential in IAM and revoke exposed access keys.',
      });
    }
  }

  // GCP API Key
  const gcpMatches = code.match(/\bAIza[0-9A-Za-z\-_]{35}\b/g);
  if (gcpMatches) {
    for (const match of gcpMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-GCP'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 0.95,
        title: 'Google Cloud Platform API Key Detected',
        needs: ['audit API key restrictions in Google Cloud Console'],
        doesNotProve: ['unrestricted Google Cloud service access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'GCP AIza API Key',
        },
        tags: ['gcp', 'google', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: 'Apply HTTP referrer / API restrictions and rotate the exposed GCP key.',
      });
    }
  }

  // Google OAuth Client Secret
  const gocspxMatches = code.match(/\bGOCSPX-[0-9A-Za-z\-_]{28}\b/g);
  if (gocspxMatches) {
    for (const match of gocspxMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-GOCSPX'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'Google OAuth Client Secret Exposure',
        needs: ['confirm OAuth client ID pairing'],
        doesNotProve: ['immediate account takeover without OAuth code exchange'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Google OAuth Client Secret GOCSPX',
        },
        tags: ['google', 'oauth', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Stripe Live Secret / Restricted Key
  const stripeSecretMatches = code.match(/\b[rs]k_live_[0-9a-zA-Z]{24,}\b/g);
  if (stripeSecretMatches) {
    for (const match of stripeSecretMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-STRIPE'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'Stripe Live Secret Key Exposure',
        needs: ['test Stripe API balance/charges scope'],
        doesNotProve: ['active Stripe account access without verification'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Stripe live secret key',
        },
        tags: ['stripe', 'secret', 'payment'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Slack tokens and webhooks
  const slackMatches = code.match(/\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g);
  if (slackMatches) {
    for (const match of slackMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-SLACK'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'Slack Token Detected',
        needs: ['verify slack auth.test scope'],
        doesNotProve: ['active Slack workspace access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['slack', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  const slackWebhookMatches = code.match(/https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,12}\/B[0-9A-Z]{8,12}\/[0-9A-Za-z]{24}/g);
  if (slackWebhookMatches) {
    for (const match of slackWebhookMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-SLACK-WEBHOOK'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 1.0,
        title: 'Slack Incoming Webhook URL Detected',
        needs: ['check channel destination'],
        doesNotProve: ['unauthorized messaging capability'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['slack', 'webhook', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // GitHub tokens
  const ghMatches = code.match(/\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b/g);
  if (ghMatches) {
    for (const match of ghMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-GITHUB'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'GitHub Personal Access Token Exposure',
        needs: ['verify token scopes against GitHub API'],
        doesNotProve: ['write access to critical repositories'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['github', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  const ghPatMatches = code.match(/\bgithub_pat_[0-9a-zA-Z_]{82}\b/g);
  if (ghPatMatches) {
    for (const match of ghPatMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-GH-PAT'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'GitHub Fine-Grained Personal Access Token Exposure',
        needs: ['verify repository permissions'],
        doesNotProve: ['repo ownership'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['github', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // GitLab Personal Access Token
  const gitlabMatches = code.match(/\bglpat-[0-9a-zA-Z\-_]{20,}\b/g);
  if (gitlabMatches) {
    for (const match of gitlabMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-GITLAB'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'GitLab Personal Access Token Exposure',
        needs: ['check GitLab user privileges'],
        doesNotProve: ['admin group access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['gitlab', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // SendGrid API Key
  const sendgridMatches = code.match(/\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/g);
  if (sendgridMatches) {
    for (const match of sendgridMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-SENDGRID'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'SendGrid API Key Exposure',
        needs: ['verify mail send permissions'],
        doesNotProve: ['domain spoofing permission'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['sendgrid', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Twilio API Key
  const twilioMatches = code.match(/\bSK[0-9a-fA-F]{32}\b/g);
  if (twilioMatches) {
    for (const match of twilioMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-TWILIO'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'Twilio API Key Exposure',
        needs: ['verify Twilio SID correlation'],
        doesNotProve: ['SMS dispatch access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['twilio', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Shopify
  const shopifyMatches = code.match(/\bshpat_[0-9a-fA-F]{32}\b/g);
  if (shopifyMatches) {
    for (const match of shopifyMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-SHOPIFY'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'Shopify Admin Access Token Exposure',
        needs: ['verify store scope'],
        doesNotProve: ['merchant account access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['shopify', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // npm access token
  const npmMatches = code.match(/\bnpm_[0-9a-zA-Z]{36}\b/g);
  if (npmMatches) {
    for (const match of npmMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-NPM'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'npm Access Token Exposure',
        needs: ['verify package publish permissions'],
        doesNotProve: ['package ownership'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['npm', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // 3. SEC-002: INFRASTRUCTURE SECRETS & KEYS
  // PEM Private Key
  const pemMatch = code.match(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/);
  if (pemMatch) {
    leads.push({
      id: nextLeadId('SEC-PEM'),
      ruleId: 'SEC-002',
      family: 'F1',
      tier: 'observed',
      potential: 'critical',
      confidence: 1.0,
      title: 'PEM Private Key Material Block Detected',
      needs: ['identify matching public key or host binding'],
      doesNotProve: ['active server decryption capability'],
      evidence: {
        preview: maskSecret(pemMatch[0]),
        location: maskLocation(url),
        context: 'PEM block header',
      },
      tags: ['private-key', 'crypto', 'secret'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
    });
  }

  // Database Connection URI
  const dbMatches = code.match(/\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^\s"'`<>]+/g);
  if (dbMatches) {
    for (const match of dbMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-DB'),
        ruleId: 'SEC-002',
        family: 'F1',
        tier: 'strong',
        potential: 'high',
        confidence: 0.9,
        title: 'Database Connection String with Credentials Detected',
        needs: ['verify network reachability of database host'],
        doesNotProve: ['public routability of database port'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Database connection URI',
        },
        tags: ['database', 'secret', 'uri'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Azure SAS
  const azureSasMatches = code.match(/sv=[^&"'\s]+&sig=[^&"'\s]+/g);
  if (azureSasMatches) {
    for (const match of azureSasMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-AZURE'),
        ruleId: 'SEC-002',
        family: 'F1',
        tier: 'strong',
        potential: 'high',
        confidence: 0.85,
        title: 'Azure Shared Access Signature (SAS) Token Detected',
        needs: ['verify storage container permissions'],
        doesNotProve: ['unrestricted blob read/write'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['azure', 'secret', 'sas'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // 4. SEC-003: GENERIC CONTEXT SECRETS (High Entropy assignments)
  const genericAssignRegex = /(?:secret|token|password|apiKey|api_key)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{16,})["']/gi;
  let assignMatch: RegExpExecArray | null;
  while ((assignMatch = genericAssignRegex.exec(code)) !== null) {
    const val = assignMatch[1];
    if (isPlaceholder(val)) continue;
    // Discard standard library or common words
    if (val.length < 16) continue;
    const entropy = calculateEntropy(val);
    if (entropy > 3.2) {
      leads.push({
        id: nextLeadId('SEC-GEN'),
        ruleId: 'SEC-003',
        family: 'F1',
        tier: 'weak',
        potential: 'high',
        confidence: 0.6,
        title: 'High-Entropy Secret Assignment Detected',
        needs: ['manual confirmation of secret purpose'],
        doesNotProve: ['production credential status'],
        evidence: {
          preview: maskSecret(val),
          location: maskLocation(url),
          context: `High entropy (${entropy.toFixed(2)}) assignment`,
        },
        tags: ['generic', 'secret', 'entropy'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // 5. SEC-004: JWT IN STATIC SOURCE
  const jwtRegex = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}\b/g;
  const jwtMatches = code.match(jwtRegex);
  if (jwtMatches) {
    for (const token of jwtMatches) {
      if (isPlaceholder(token)) continue;
      const header = parseJwtHeader(token);
      const alg = header?.alg ? String(header.alg) : 'unknown';
      leads.push({
        id: nextLeadId('SEC-JWT'),
        ruleId: 'SEC-004',
        family: 'F1',
        tier: 'observed',
        potential: 'medium',
        confidence: 0.8,
        title: `Static JWT Token Exposure (${alg})`,
        needs: ['verify expiration and audience claims'],
        doesNotProve: ['unexpired session state'],
        evidence: {
          preview: maskSecret(token),
          location: maskLocation(url),
          context: `JWT alg: ${alg}, claims inspected in memory`,
        },
        tags: ['jwt', 'token', 'auth'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  return leads;
}
