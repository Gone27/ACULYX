import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

export interface FormInputDesc {
  name?: string;
  type?: string;
  value?: string;
}

export interface FormDesc {
  action?: string;
  method?: string;
  inputs?: FormInputDesc[];
}

export interface AuthDetectionContext {
  url: string;
  forms?: FormDesc[];
  storageKeys?: string[];
}

const CSRF_INPUT_NAMES = /^(csrf|_csrf|csrf_token|xsrf|xsrf_token|authenticity_token|__requestverificationtoken|token|nonce|csrfmiddlewaretoken)$/i;

const PRIVILEGED_INPUT_NAMES = /^(role|isadmin|is_admin|admin|privilege|permissions|access_level|group)$/i;

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectAuthLeads(
  context: AuthDetectionContext,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  const { url, forms = [], storageKeys = [] } = context;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  // 1. AUTH-001: OAuth Parameters Analysis
  try {
    const parsedUrl = new URL(url);
    const params = parsedUrl.searchParams;

    const responseType = params.get('response_type');
    const redirectUri = params.get('redirect_uri');
    const hasState = params.has('state');
    const hasCodeChallenge = params.has('code_challenge');

    const isOauthEndpoint =
      responseType !== null ||
      parsedUrl.pathname.includes('/oauth') ||
      parsedUrl.pathname.includes('/authorize') ||
      redirectUri !== null;

    if (isOauthEndpoint) {
      if (responseType === 'token') {
        leads.push({
          id: nextLeadId('AUTH-IMPLICIT'),
          ruleId: 'AUTH-001',
          family: 'F4',
          tier: 'observed',
          potential: 'high',
          confidence: 0.95,
          title: 'OAuth Implicit Flow (response_type=token) Detected',
          needs: ['verify if token is returned in URL fragment and susceptible to token leakage'],
          doesNotProve: ['token interception'],
          evidence: {
            preview: maskSecret(`response_type=token redirect_uri=${redirectUri || 'none'}`),
            location: maskLocation(url),
            context: 'OAuth authorization request with implicit token grant',
          },
          tags: ['oauth', 'oauth-flow', 'implicit-grant'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S1',
          remediation: 'Migrate to OAuth 2.1 authorization code flow with PKCE.',
        });
      }

      if (!hasState && (responseType || redirectUri)) {
        leads.push({
          id: nextLeadId('AUTH-NOSTATE'),
          ruleId: 'AUTH-001',
          family: 'F4',
          tier: 'strong',
          potential: 'medium',
          confidence: 0.85,
          title: 'OAuth Authorization Request Missing State Parameter',
          needs: ['test CSRF on OAuth callback endpoint'],
          doesNotProve: ['account takeover via OAuth CSRF'],
          evidence: {
            preview: maskSecret(url),
            location: maskLocation(url),
            context: 'OAuth authorization request without state parameter',
          },
          tags: ['oauth', 'oauth-flow', 'missing-state'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S1',
        });
      }

      if (responseType === 'code' && !hasCodeChallenge) {
        leads.push({
          id: nextLeadId('AUTH-NOPKCE'),
          ruleId: 'AUTH-001',
          family: 'F4',
          tier: 'weak',
          potential: 'low',
          confidence: 0.7,
          title: 'OAuth Authorization Flow Missing PKCE code_challenge',
          needs: ['verify if client is a public client (SPA/mobile) requiring PKCE'],
          doesNotProve: ['auth code interception'],
          evidence: {
            preview: maskSecret(url),
            location: maskLocation(url),
          },
          tags: ['oauth', 'missing-pkce'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S1',
        });
      }
    }
  } catch {
    // Ignore URL parse error
  }

  // 2. AUTH-002: State-Changing Forms without Anti-CSRF Token
  for (const form of forms) {
    const method = (form.method || 'GET').toUpperCase();
    if (method === 'POST') {
      const inputs = form.inputs || [];
      const hasCsrf = inputs.some(i => i.name && CSRF_INPUT_NAMES.test(i.name.trim()));

      if (!hasCsrf) {
        leads.push({
          id: nextLeadId('AUTH-CSRF'),
          ruleId: 'AUTH-002',
          family: 'F4',
          tier: 'strong',
          potential: 'medium',
          confidence: 0.8,
          title: 'State-Changing POST Form Without Anti-CSRF Token',
          needs: ['verify cookie SameSite attribute and custom request headers'],
          doesNotProve: ['cross-site request forgery without session cookie analysis'],
          evidence: {
            preview: maskSecret(`form action=${form.action || 'self'} method=POST inputs=${inputs.length}`),
            location: maskLocation(url),
            context: `POST form target: ${form.action || url}`,
            extractedNames: inputs.map(i => i.name).filter(Boolean) as string[],
          },
          tags: ['csrf', 'missing-csrf', 'state-changing-form'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S3',
          remediation: 'Implement anti-CSRF token verification or SameSite=Strict/Lax cookie policy.',
        });
      }
    }

    // 3. AUTH-003: Insecure Form Inputs / Password over HTTP / Hidden Privilege fields
    const inputs = form.inputs || [];
    for (const input of inputs) {
      if (input.type === 'password' && url.startsWith('http://')) {
        leads.push({
          id: nextLeadId('AUTH-CLEARTEXT'),
          ruleId: 'AUTH-003',
          family: 'F4',
          tier: 'observed',
          potential: 'high',
          confidence: 1.0,
          title: 'Password Input Submitted Over Unencrypted HTTP',
          needs: ['verify form action protocol'],
          doesNotProve: ['network eavesdropping active'],
          evidence: {
            preview: maskSecret(input.name || 'password'),
            location: maskLocation(url),
          },
          tags: ['cleartext-credentials', 'http-insecure'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S3',
        });
      }

      if (input.name && PRIVILEGED_INPUT_NAMES.test(input.name.trim())) {
        leads.push({
          id: nextLeadId('AUTH-ROLEFIELD'),
          ruleId: 'AUTH-003',
          family: 'F4',
          tier: 'weak',
          potential: 'medium',
          confidence: 0.65,
          title: `Privileged Input Field in Form: ${input.name}`,
          needs: ['test client-side privilege tampering on form submission'],
          doesNotProve: ['mass-assignment or privilege escalation vulnerability'],
          evidence: {
            preview: maskSecret(input.name),
            location: maskLocation(url),
            extractedNames: [input.name],
          },
          tags: ['privilege-field', 'mass-assignment'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S3',
        });
      }
    }
  }

  // 4. AUTH-004: Token / Auth Keys in Web Storage (Store Key Name Only!)
  for (const key of storageKeys) {
    if (
      /^(jwt|token|access_token|auth_token|id_token|session_token|bearer)$/i.test(key) ||
      key.toLowerCase().includes('token') ||
      key.toLowerCase().includes('auth')
    ) {
      leads.push({
        id: nextLeadId('AUTH-STORAGE'),
        ruleId: 'AUTH-004',
        family: 'F4',
        tier: 'observed',
        potential: 'low',
        confidence: 0.9,
        title: `Authentication Token Found in Web Storage: ${key}`,
        needs: ['verify XSS blast radius for stored token'],
        doesNotProve: ['token leakage or XSS presence'],
        evidence: {
          preview: maskSecret(key),
          location: maskLocation(url),
          extractedNames: [key],
          context: `Storage key: ${key} (INVARIANT: value never accessed or stored)`,
        },
        tags: ['web-storage', 'token-storage'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S3',
      });
    }
  }

  return leads;
}
