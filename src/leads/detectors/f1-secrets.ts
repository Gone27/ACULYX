import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

export function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of str) {
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isPlaceholder(val: string): boolean {
  const trimmed = val.trim();
  if (trimmed.length === 0) return true;
  if (/<[^>]+>/.test(trimmed)) return true;
  if (/^(.)\1{5,}$/.test(trimmed)) return true;

  if (trimmed.startsWith('xox')) {
    // Slack tokens legitimately use numeric workspace and user IDs (e.g. xoxb-1234567890-...)
    return /xox[baprs]-(?:xxxx|dummy|SAMPLE|YOUR_|CHANGE_ME)/i.test(trimmed) || /^(.)\1{6,}$/.test(trimmed);
  }

  // Exact full-string placeholder tokens or obvious placeholder phrases
  if (
    /^(?:your[_-]?(?:api[_-]?)?(?:key|token|secret)|example[_-]?(?:key|token|secret)?|sample[_-]?(?:key|token|secret)?|dummy[_-]?(?:key|token|secret)?|change[_-]?me|placeholder|test|xxxx+|0000+|1234567890|12345678|123456)$/i.test(
      trimmed
    )
  ) {
    return true;
  }

  // Token-level check: split into words. If ALL words are placeholder words, it's a placeholder.
  // Real staging passwords (like 'test_pass_2024!' or 'admin_123456') are preserved!
  const tokens = trimmed.toLowerCase().split(/[-_.\s/:]+/).filter(Boolean);
  if (
    tokens.length > 0 &&
    tokens.every((t) =>
      /^(?:your|api|key|token|secret|example|sample|dummy|changeme|placeholder|test|xxxx+|0000+|123456)$/.test(t)
    )
  ) {
    return true;
  }

  // If the value itself contains an obvious non-production marker word (standalone),
  // classify as placeholder to reduce noise on dev/staging configs.
  if (/(?:^|[-_.])(?:test|demo|fake|mock|dummy|staging|placeholder|sample)(?:[-_.]|$)/i.test(trimmed)) {
    return true;
  }

  return false;
}

function parseJwtHeader(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length < 2 || parts.length > 3) return null;
    const headerPart = parts[0];
    if (headerPart === undefined || headerPart.length === 0) return null;
    let b64 = headerPart.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    const json = typeof atob !== 'undefined'
      ? atob(b64)
      : Buffer.from(b64, 'base64').toString('utf8');
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function nextLeadId(prefix: string): string {
  const uid = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '').slice(0, 12)
    : Math.random().toString(36).slice(2, 14);
  return `LD-${prefix}-${uid}`;
}

export function detectSecrets(
  code: string,
  rawUrl: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (!code || typeof code !== 'string') return leads;

  const url = (maskLocation(rawUrl) as string) || rawUrl;
  const origin = (() => {
    try {
      return new URL(rawUrl).origin;
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

  const mapboxMatches = code.match(/\bpk\.[0-9a-zA-Z\-_]{30,}(?=[^0-9a-zA-Z\-_]|$)/g);
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
  const gcpMatches = code.match(/\bAIza[0-9A-Za-z\-_]{35}(?=[^0-9A-Za-z\-_]|$)/g);
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
  const gocspxMatches = code.match(/\bGOCSPX-[0-9A-Za-z\-_]{24,35}(?=[^0-9A-Za-z\-_]|$)/g);
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
  const slackMatches = code.match(/\bxox[baprs]-[0-9a-zA-Z-]{10,80}\b/g);
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
        url: maskLocation(url),
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
  const gitlabMatches = code.match(/\bglpat-[0-9a-zA-Z\-_]{20,}(?=[^0-9a-zA-Z\-_]|$)/g);
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
  const sendgridMatches = code.match(/\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}(?=[^0-9A-Za-z\-_]|$)/g);
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

  // OpenAI API Key
  const openaiMatches = code.match(/\b(?:sk-(?:live-)?[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{40,}|sk-svcacct-[a-zA-Z0-9_-]{40,}|sk-[a-zA-Z0-9]{48})(?=[^a-zA-Z0-9_-]|$)/g);
  if (openaiMatches) {
    for (const match of openaiMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-OPENAI'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'OpenAI API Secret Key Exposure',
        needs: ['verify OpenAI organization and billing scope'],
        doesNotProve: ['active funded API credits'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'OpenAI API key',
        },
        tags: ['openai', 'ai', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: 'Revoke and rotate the exposed OpenAI secret key in the OpenAI platform dashboard.',
      });
    }
  }

  // Anthropic API Key
  const anthropicMatches = code.match(/\bsk-ant-(?:api03-)?[a-zA-Z0-9_-]{32,}(?=[^a-zA-Z0-9_-]|$)/g);
  if (anthropicMatches) {
    for (const match of anthropicMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-ANTHROPIC'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'Anthropic Claude API Key Exposure',
        needs: ['verify Anthropic API credits and tier'],
        doesNotProve: ['active console access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Anthropic API key',
        },
        tags: ['anthropic', 'ai', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: 'Revoke and regenerate the exposed Anthropic API key via the Anthropic Console.',
      });
    }
  }

  // Discord Webhook URL
  const discordWebhookMatches = code.match(/https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,21}\/[A-Za-z0-9_-]{60,}/g);
  if (discordWebhookMatches) {
    for (const match of discordWebhookMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-DISCORD-WEBHOOK'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 1.0,
        title: 'Discord Incoming Webhook URL Detected',
        needs: ['verify target channel destination'],
        doesNotProve: ['unauthorized messaging capability'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['discord', 'webhook', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Telegram Bot Token
  const telegramMatches = code.match(/\b\d{8,11}:[A-Za-z0-9_-]{35}(?=[^A-Za-z0-9_-]|$)/g);
  if (telegramMatches) {
    for (const match of telegramMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-TELEGRAM'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'Telegram Bot API Token Exposure',
        needs: ['verify getMe response for bot username and permissions'],
        doesNotProve: ['channel admin access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Telegram bot token',
        },
        tags: ['telegram', 'bot', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: 'Revoke the bot token using BotFather on Telegram.',
      });
    }
  }

  // Mailgun API Key
  const mailgunMatches = code.match(/\bkey-[0-9a-zA-Z]{32}\b/g);
  if (mailgunMatches) {
    for (const match of mailgunMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-MAILGUN'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'high',
        confidence: 0.95,
        title: 'Mailgun API Key Exposure',
        needs: ['verify domain email sending permissions'],
        doesNotProve: ['active domain reputation'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['mailgun', 'email', 'secret'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // DigitalOcean Personal Access Token
  const doMatches = code.match(/\bdop_v1_[a-f0-9]{64}\b/g);
  if (doMatches) {
    for (const match of doMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-DIGITALOCEAN'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: 'critical',
        confidence: 1.0,
        title: 'DigitalOcean Personal Access Token Exposure',
        needs: ['verify droplet/cluster management permissions'],
        doesNotProve: ['account ownership'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
        },
        tags: ['digitalocean', 'cloud', 'secret'],
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
  // PEM / PGP Private Key Material
  const pemMatch = code.match(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----/);
  if (pemMatch) {
    leads.push({
      id: nextLeadId('SEC-PEM'),
      ruleId: 'SEC-002',
      family: 'F1',
      tier: 'observed',
      potential: 'critical',
      confidence: 1.0,
      title: 'Private Key Material Block Detected (PEM / PGP)',
      needs: ['identify matching public key or host binding'],
      doesNotProve: ['active server decryption capability'],
      evidence: {
        preview: maskSecret(pemMatch[0]),
        location: maskLocation(url),
        context: 'Private Key block header',
      },
      tags: ['private-key', 'crypto', 'secret'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
    });
  }

  // Database / Queue Connection URI (MongoDB, PostgreSQL, MySQL, Redis, AMQP)
  const dbMatches = code.match(/\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis(?:s)?|amqp(?:s)?):\/\/[^\s"'`<>]+/g);
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
        title: 'Database / Queue Connection String with Credentials Detected',
        needs: ['verify network reachability of service host'],
        doesNotProve: ['public routability of database port'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Connection URI with embedded credentials',
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

  // Basic Auth Credentials in URL
  const basicAuthMatches = code.match(/\bhttps?:\/\/[a-zA-Z0-9_.-]+:(?:(?!\/\/)[^@\s"'`<>]{6,})@[a-zA-Z0-9_.-]+\.[a-zA-Z]{2,}/g);
  if (basicAuthMatches) {
    for (const match of basicAuthMatches) {
      if (isPlaceholder(match)) continue;
      leads.push({
        id: nextLeadId('SEC-BASICAUTH'),
        ruleId: 'SEC-002',
        family: 'F1',
        tier: 'strong',
        potential: 'high',
        confidence: 0.9,
        title: 'Embedded Basic Authentication Credentials in URL',
        needs: ['verify endpoint responsiveness to embedded credentials'],
        doesNotProve: ['privileged user access'],
        evidence: {
          preview: maskSecret(match),
          location: maskLocation(url),
          context: 'Embedded URL user:password authentication',
        },
        tags: ['basic-auth', 'credentials', 'secret'],
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

  // AWS Secret Access Key assignment
  const awsSecretRegex = /(?:aws_secret_access_key|aws_secret_key|secret_key|secretAccessKey)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi;
  let awsSecMatch: RegExpExecArray | null;
  while ((awsSecMatch = awsSecretRegex.exec(code)) !== null) {
    const val = awsSecMatch[1];
    if (val !== undefined && val.length > 0 && !isPlaceholder(val)) {
      leads.push({
        id: nextLeadId('SEC-AWS-SECRET'),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'strong',
        potential: 'critical',
        confidence: 0.95,
        title: 'AWS Secret Access Key Exposure',
        needs: ['pair with AWS Access Key ID and test STS get-caller-identity'],
        doesNotProve: ['active IAM permissions'],
        evidence: {
          preview: maskSecret(val),
          location: maskLocation(url),
          context: 'AWS Secret Key assignment',
        },
        tags: ['aws', 'secret', 'iam'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // 3b. Discord bot token — needs per-segment entropy validation
  // Format: <snowflake_user_id>.<timestamp_b64>.<hmac>
  // The HMAC segment (3rd) must have high entropy; snowflake IDs are 17-19 digits encoded as base64
  const discordBotRe = /\b([MNO][A-Za-z0-9_-]{23,25})\.([A-Za-z0-9_-]{6})\.([A-Za-z0-9_-]{27,40})\b/g;
  for (const m of code.matchAll(discordBotRe)) {
    const full = m[0] ?? '';
    const hmacSeg = m[3] ?? '';
    if (full.length === 0 || isPlaceholder(full)) continue;
    // Require high entropy in the HMAC segment (should be truly random)
    if (calculateEntropy(hmacSeg) < 4.0) continue;
    leads.push({
      id: nextLeadId('SEC-DISCORD'),
      ruleId: 'SEC-001',
      family: 'F1',
      tier: 'observed',
      potential: 'high',
      confidence: 0.85,
      title: 'Discord Bot Token Exposure',
      needs: ['verify the credential is live and its scope'],
      doesNotProve: ['that the credential is currently valid'],
      evidence: { preview: maskSecret(full), location: maskLocation(url), context: 'Discord Bot Token' },
      tags: ['discord', 'secret'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
      remediation: 'Reset the bot token in the Discord developer portal.',
    });
  }

  // 3c. Additional vendor formats (review additions)
  const simple: Array<{ id: string; title: string; re: RegExp; potential: Lead['potential']; tags: string[]; remediation: string; group?: number }> = [
    { id: 'SEC-GH-FINE', title: 'GitHub Fine-Grained Personal Access Token Exposure', re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g, potential: 'critical', tags: ['github', 'secret'], remediation: 'Revoke the token in GitHub settings and rotate it.' },
    { id: 'SEC-HF', title: 'Hugging Face Access Token Exposure', re: /\bhf_[A-Za-z0-9]{30,}\b/g, potential: 'high', tags: ['huggingface', 'secret'], remediation: 'Revoke the token in Hugging Face settings and rotate it.' },
    { id: 'SEC-TWILIO-AUTH', title: 'Twilio Auth Token Exposure (context match)', re: /\b(?:twilio[\w.-]{0,20}|auth_?token)["']?\s*[:=,]\s*["']([0-9a-f]{32})["']/gi, potential: 'high', tags: ['twilio', 'secret'], remediation: 'Rotate the Twilio Auth Token and move it server-side.', group: 1 },
    { id: 'SEC-BEARER', title: 'Hard-coded Bearer Credential in Source', re: /\bAuthorization["']?\s*[:=]\s*["'`]Bearer\s+([A-Za-z0-9._~+/=-]{32,})["'`]/gi, potential: 'high', tags: ['bearer', 'auth', 'secret'], remediation: 'Remove the static credential from client code and issue per-user tokens.', group: 1 },
  ];
  for (const rule of simple) {
    for (const m of code.matchAll(rule.re)) {
      const match = rule.group !== undefined ? (m[rule.group] ?? '') : m[0];
      if (match.length === 0 || isPlaceholder(match)) continue;
      // For bearer tokens, require higher entropy
      if (rule.id === 'SEC-BEARER' && calculateEntropy(match) < 3.5) continue;
      leads.push({
        id: nextLeadId(rule.id),
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: rule.potential,
        confidence: 0.9,
        title: rule.title,
        needs: ['verify the credential is live and its scope'],
        doesNotProve: ['that the credential is currently valid'],
        evidence: { preview: maskSecret(match), location: maskLocation(url), context: rule.title },
        tags: rule.tags,
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
        remediation: rule.remediation,
      });
    }
  }

  // 4. SEC-003: GENERIC CONTEXT SECRETS (Quoted JSON keys, assignments, template literals)
  const genericAssignRegex = /(?:["']?)((?:[a-zA-Z0-9_$-]+[-_])?(?:secret|token|passw(?:or)?d|api[-_]?key|private[-_]?key|client[-_]?secret|signing[-_]?key|encryption[-_]?key)[a-zA-Z0-9_$-]*)(?:["']?)\s*[:=]\s*["'`]([^"'`\r\n]{8,})["'`]/gi;
  let assignMatch: RegExpExecArray | null;
  while ((assignMatch = genericAssignRegex.exec(code)) !== null) {
    const keyName = assignMatch[1];
    const val = assignMatch[2];
    if (val === undefined || val.length === 0 || isPlaceholder(val)) continue;
    if (val.length < 8) continue;

    // Guard against URLs, paths, endpoints, and configuration parameters
    const keyLower = (keyName ?? '').toLowerCase();
    if (
      keyLower.endsWith('_url') ||
      keyLower.endsWith('_uri') ||
      keyLower.endsWith('_endpoint') ||
      keyLower.endsWith('_path') ||
      keyLower.endsWith('_type') ||
      keyLower.endsWith('_name') ||
      keyLower.endsWith('_format') ||
      keyLower.endsWith('_param') ||
      keyLower.endsWith('_header') ||
      keyLower.endsWith('_prefix') ||
      keyLower.endsWith('_suffix')
    ) {
      continue;
    }
    const valTrim = val.trim();
    if (
      valTrim.startsWith('http://') ||
      valTrim.startsWith('https://') ||
      valTrim.startsWith('//') ||
      valTrim.startsWith('/') ||
      valTrim.startsWith('./') ||
      valTrim.startsWith('../') ||
      valTrim.startsWith('data:')
    ) {
      continue;
    }
    // High-entropy secret tokens do not contain spaces or tabs
    if (valTrim.includes(' ') || valTrim.includes('\t')) {
      continue;
    }

    const entropy = calculateEntropy(valTrim);
    if ((valTrim.length >= 16 && entropy > 2.8) || (valTrim.length >= 8 && entropy > 3.0)) {
      leads.push({
        id: nextLeadId('SEC-GEN'),
        ruleId: 'SEC-003',
        family: 'F1',
        tier: 'weak',
        potential: 'high',
        confidence: 0.65,
        title: `High-Entropy Secret Assignment Detected (${keyName ?? 'key'})`,
        needs: ['manual confirmation of secret purpose'],
        doesNotProve: ['production credential status'],
        evidence: {
          preview: maskSecret(valTrim),
          location: maskLocation(url),
          context: `Key: ${keyName ?? 'secret'}, high entropy (${entropy.toFixed(2)}) assignment`,
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

  // 5. SEC-004: JWT IN STATIC SOURCE (including unsigned alg=none tokens with empty signature)
  const jwtRegex = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_\-+/=]*)?/g;
  const jwtMatches = code.match(jwtRegex);
  if (jwtMatches) {
    for (const token of jwtMatches) {
      if (isPlaceholder(token)) continue;
      const header = parseJwtHeader(token);
      const alg = typeof header?.alg === 'string' && header.alg.length > 0 ? header.alg : 'unknown';
      const sigPart = token.split('.')[2];
      const isUnsigned = alg.toLowerCase() === 'none' || token.endsWith('.') || sigPart === undefined || sigPart.length === 0;
      const potential = isUnsigned ? 'high' : 'medium';
      const title = isUnsigned
        ? 'Unsigned / alg=none Static JWT Token Disclosed'
        : `Static JWT Token Exposure (${alg})`;

      leads.push({
        id: nextLeadId('SEC-JWT'),
        ruleId: 'SEC-004',
        family: 'F1',
        tier: 'observed',
        potential,
        confidence: isUnsigned ? 0.95 : 0.8,
        title,
        needs: ['verify expiration and audience claims'],
        doesNotProve: ['unexpired session state'],
        evidence: {
          preview: maskSecret(token),
          location: maskLocation(url),
          context: `JWT alg: ${alg}, isUnsigned: ${String(isUnsigned)}, claims inspected in memory`,
        },
        tags: ['jwt', 'token', 'auth', ...(isUnsigned ? ['alg-none', 'unsigned'] : [])],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url: maskLocation(url),
        sourceSensor: 'S2',
      });
    }
  }

  return leads;
}
