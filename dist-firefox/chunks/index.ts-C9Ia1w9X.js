import { S as SessionStorage, K as KEEPALIVE_ALARM, a as KEEPALIVE_PERIOD_MINUTES, M as MAX_EVIDENCE_LENGTH, G as GRADE_THRESHOLDS, b as SCORE_VERSION, P as POPUP_PORT_NAME, c as SIDEPANEL_PORT_NAME, d as PortRegistry, p as portSend, L as LocalStorage, B as BADGE_COLORS, R as RESTRICTED_SCHEMES } from "./messaging-IbeZtfR1.js";
import { r as reportPageSignals } from "./service-worker-detection-B9LeGWmi.js";
const tabStates = /* @__PURE__ */ new Map();
function initLifecycle() {
  void chrome.alarms.create(KEEPALIVE_ALARM, {
    periodInMinutes: KEEPALIVE_PERIOD_MINUTES
  });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === KEEPALIVE_ALARM) ;
  });
}
async function hydrateFromSession() {
  const all = await SessionStorage.getAllTabStates();
  for (const state of all) {
    tabStates.set(state.tabId, state);
  }
}
const CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
const BIDI_OVERRIDE_RE = /[\u200B-\u200D\u202A-\u202E\u2066-\u2069\uFEFF]/g;
function sanitizeEvidence(raw) {
  let s = raw.slice(0, MAX_EVIDENCE_LENGTH).replace(CONTROL_CHAR_RE, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).replace(BIDI_OVERRIDE_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  if (raw.length > MAX_EVIDENCE_LENGTH) {
    s += ` … [${raw.length - MAX_EVIDENCE_LENGTH} chars truncated]`;
  }
  return s;
}
function normalizeHeaders(raw) {
  const map = {};
  for (const { name, value } of raw) {
    if (value != null) {
      map[name.toLowerCase()] = value;
    }
  }
  return map;
}
function extractSetCookieHeaders(raw) {
  return raw.filter((h) => h.name.toLowerCase() === "set-cookie" && h.value != null).map((h) => h.value);
}
function headersDiffer(a, b) {
  const keysA = Object.keys(a).sort();
  const keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return true;
  for (let i = 0; i < keysA.length; i++) {
    const k = keysA[i];
    if (k !== keysB[i]) return true;
    if (a[k] !== b[k]) return true;
  }
  return false;
}
function parseCspDirectives(csp) {
  const directives = /* @__PURE__ */ new Map();
  for (const part of csp.split(";")) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    const spaceIdx = trimmed.indexOf(" ");
    if (spaceIdx === -1) {
      directives.set(trimmed.toLowerCase(), "");
    } else {
      const name = trimmed.slice(0, spaceIdx).toLowerCase();
      const value = trimmed.slice(spaceIdx + 1).trim();
      directives.set(name, value);
    }
  }
  return directives;
}
function originFromUrl(url) {
  try {
    const u = new URL(url);
    return u.origin === "null" ? null : u.origin;
  } catch {
    return null;
  }
}
const SENSITIVE_COOKIE_RE = /(^|[-_])(session|sess|auth|token|jwt|sid|login|user|sso|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|credential|secret|password|access[-_]?token|id[-_]?token)([-_]|$)/i;
const NON_SENSITIVE_COOKIE_RE = /(^|[-_])(ga|gid|gat|gcl|fbp|fbc|theme|dark|light|lang|locale|country|currency|timezone|tz|sidebar|banner|notice|consent|cookie_consent|optout|optimizely|amplitude|intercom|csrf|xsrf|csrftoken)([-_]|$)/i;
function isSensitiveCookie(name) {
  if (name.startsWith("__Host-") || name.startsWith("__Secure-")) return true;
  if (NON_SENSITIVE_COOKIE_RE.test(name)) return false;
  return SENSITIVE_COOKIE_RE.test(name);
}
const NONCE_RE = /'nonce-[A-Za-z0-9+/=_-]+'/i;
const HASH_RE = /'sha(256|384|512)-[A-Za-z0-9+/=_-]+'/i;
function hasCspBypassProtection(sourceList) {
  const hasNonce = NONCE_RE.test(sourceList);
  const hasHash = HASH_RE.test(sourceList);
  const hasStrictDynamic = sourceList.includes("'strict-dynamic'");
  const isModernStrict = hasNonce || hasHash || hasStrictDynamic;
  return { hasNonce, hasHash, hasStrictDynamic, isModernStrict };
}
const captureMap = /* @__PURE__ */ new Map();
function detectHstsUpgrade(raw) {
  return raw.some(
    (h) => h.name.toLowerCase() === "non-authoritative-reason" && h.value.toUpperCase() === "HSTS"
  );
}
function toRawHeaders(headers) {
  return headers.map((h) => ({ name: h.name, value: h.value ?? "" }));
}
function registerCaptureListeners(onHopComplete2) {
  const filter = { urls: ["<all_urls>"] };
  const extraInfoSpec = ["responseHeaders", "extraHeaders"];
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.type !== "main_frame" || details.tabId < 0) return;
      const raw = details.responseHeaders ?? [];
      const partial = {
        tabId: details.tabId,
        url: details.url,
        status: details.statusCode,
        headersReceived: normalizeHeaders(raw),
        rawHeadersReceived: toRawHeaders(raw),
        headersStarted: null,
        rawHeadersStarted: [],
        fromCache: false,
        // not available at this stage
        wasRedirected: false,
        timestamp: details.timeStamp,
        redirectCount: 0
      };
      captureMap.set(details.requestId, partial);
    },
    filter,
    extraInfoSpec
  );
  chrome.webRequest.onResponseStarted.addListener(
    (details) => {
      if (details.type !== "main_frame" || details.tabId < 0) return;
      const raw = details.responseHeaders ?? [];
      const normalised = normalizeHeaders(raw);
      const rawHeaders = toRawHeaders(raw);
      let partial = captureMap.get(details.requestId);
      if (!partial) {
        partial = {
          tabId: details.tabId,
          url: details.url,
          status: details.statusCode,
          headersReceived: null,
          rawHeadersReceived: [],
          headersStarted: null,
          rawHeadersStarted: [],
          fromCache: details.fromCache ?? false,
          wasRedirected: false,
          timestamp: details.timeStamp,
          redirectCount: 0
        };
      }
      partial.headersStarted = normalised;
      partial.rawHeadersStarted = rawHeaders;
      partial.fromCache = details.fromCache ?? false;
      partial.status = details.statusCode;
      partial.url = details.url;
      const canonicalRaw = rawHeaders;
      const canonicalNormalised = normalised;
      const differ = partial.headersReceived !== null ? headersDiffer(partial.headersReceived, canonicalNormalised) : false;
      const hop = {
        requestId: details.requestId,
        url: details.url,
        status: details.statusCode,
        headers: canonicalNormalised,
        rawHeaders: canonicalRaw,
        fromCache: partial.fromCache,
        isHstsUpgrade: detectHstsUpgrade(canonicalRaw),
        capturedAt: "onResponseStarted",
        headersDiffer: differ,
        timestamp: partial.timestamp,
        redirectCount: partial.redirectCount
      };
      captureMap.delete(details.requestId);
      void onHopComplete2(details.tabId, hop);
    },
    filter,
    extraInfoSpec
  );
  chrome.webRequest.onBeforeRedirect.addListener(
    (details) => {
      if (details.type !== "main_frame" || details.tabId < 0) return;
      const existing = captureMap.get(details.requestId);
      if (existing) {
        existing.wasRedirected = true;
        existing.redirectCount += 1;
        existing.status = details.statusCode;
        existing.url = details.redirectUrl;
        captureMap.set(details.requestId, existing);
      } else {
        const raw = details.responseHeaders ?? [];
        captureMap.set(details.requestId, {
          tabId: details.tabId,
          url: details.redirectUrl,
          status: details.statusCode,
          headersReceived: normalizeHeaders(raw),
          rawHeadersReceived: toRawHeaders(raw),
          headersStarted: null,
          rawHeadersStarted: [],
          fromCache: false,
          wasRedirected: true,
          timestamp: details.timeStamp,
          redirectCount: 1
        });
      }
    },
    filter,
    extraInfoSpec
  );
}
const REF_SUBDOMAIN = "https://portswigger.net/web-security/host-header/exploiting#password-reset-poisoning-via-dangling-markup";
const REF_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS";
const REF_COOKIE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value";
const REF_COOKIE_TOSS = "https://datatracker.ietf.org/doc/html/rfc6265#section-8.6";
const REF_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy";
const REF_COOP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy";
const REF_OAC = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster";
const TWO_PART_TLDS = /* @__PURE__ */ new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "net.uk",
  "me.uk",
  "ltd.uk",
  "plc.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "asn.au",
  "id.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "govt.nz",
  "ac.nz",
  "geek.nz",
  "school.nz",
  "co.jp",
  "ne.jp",
  "or.jp",
  "go.jp",
  "ac.jp",
  "ed.jp",
  "lg.jp",
  "co.in",
  "net.in",
  "org.in",
  "gen.in",
  "firm.in",
  "ind.in",
  "nic.in",
  "ac.in",
  "edu.in",
  "gov.in",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "edu.br",
  "ind.br",
  "com.sg",
  "edu.sg",
  "gov.sg",
  "net.sg",
  "org.sg",
  "com.mx",
  "edu.mx",
  "gob.mx",
  "org.mx",
  "net.mx",
  "co.za",
  "org.za",
  "gov.za",
  "net.za",
  "ac.za",
  "com.tr",
  "net.tr",
  "org.tr",
  "gov.tr",
  "edu.tr",
  "com.tw",
  "org.tw",
  "gov.tw",
  "edu.tw",
  "net.tw",
  "com.hk",
  "org.hk",
  "gov.hk",
  "edu.hk",
  "net.hk",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "edu.cn"
]);
function registrableDomain(hostname) {
  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname === "localhost") {
    return null;
  }
  const parts = hostname.toLowerCase().split(".");
  if (parts.length < 2) return null;
  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join(".");
    if (TWO_PART_TLDS.has(lastTwo) || /^[a-z0-9\-]+\.(co|com|net|org|gov|edu|ac|gob)\.[a-z]{2}$/.test(parts.slice(-3).join("."))) {
      return parts.slice(-3).join(".");
    }
  }
  return parts.slice(-2).join(".");
}
function isSubdomain(hostname) {
  const reg = registrableDomain(hostname);
  if (reg == null || hostname === reg) return false;
  if (hostname === `www.${reg}`) return false;
  return hostname.length > reg.length + 1 && hostname.endsWith(`.${reg}`);
}
function cspTokens(src) {
  return src.split(/\s+/).filter((t) => t.length > 0);
}
function cspAllowsSubdomain(sourceList, registrable) {
  for (const token of cspTokens(sourceList)) {
    const bare = token.replace(/^https?:\/\//, "");
    if (bare === `*.${registrable}` || bare === registrable) return true;
    if (bare.endsWith(`.${registrable}`) && !bare.startsWith("*")) return true;
  }
  return false;
}
function resolveEffective$1(directives, directive) {
  return directives.get(directive) ?? directives.get("default-src");
}
function checkSubdomainTrust(finalHop, cookies) {
  const findings = [];
  const vectors = [];
  let hostname = "";
  try {
    hostname = new URL(finalHop.url).hostname;
  } catch {
    return { findings, hasEscalationPath: false, vectors };
  }
  const regDomain = registrableDomain(hostname);
  if (regDomain == null) {
    return { findings, hasEscalationPath: false, vectors };
  }
  const pageIsSubdomain = isSubdomain(hostname);
  const cspValue = finalHop.headers["content-security-policy"] ?? "";
  const corsOrigin = finalHop.headers["access-control-allow-origin"] ?? "";
  const corsCredsRaw = finalHop.headers["access-control-allow-credentials"] ?? "";
  const varyHeader = finalHop.headers["vary"] ?? "";
  const coopHeader = finalHop.headers["cross-origin-opener-policy"] ?? "";
  const oacHeader = finalHop.headers["origin-agent-cluster"] ?? "";
  const xfo = finalHop.headers["x-frame-options"] ?? "";
  const directives = cspValue.length > 0 ? parseCspDirectives(cspValue) : /* @__PURE__ */ new Map();
  const effectiveScriptSrc = resolveEffective$1(directives, "script-src");
  const frameAncestors = directives.get("frame-ancestors") ?? "";
  let hasEscalationPath = false;
  const broadCookies = [];
  for (const cookie of cookies) {
    const d = cookie.domain;
    const normalised = d.startsWith(".") ? d.slice(1) : d;
    if (normalised === regDomain || d === `.${regDomain}`) {
      if (isSensitiveCookie(cookie.name) || cookie.httpOnly) {
        broadCookies.push(cookie.name);
      }
    }
  }
  const cookieTrustPresent = broadCookies.length > 0;
  if (cookieTrustPresent) hasEscalationPath = true;
  vectors.push({
    id: "SUB-001",
    label: "Cookie scope spans all subdomains",
    detail: cookieTrustPresent ? `${broadCookies.length} sensitive cookie(s) scoped to .${regDomain}: ${broadCookies.slice(0, 3).map((n) => `"${n}"`).join(", ")}${broadCookies.length > 3 ? " …" : ""}` : `No domain-wide sensitive cookies detected (all session cookies host-only or isolated)`,
    risk: "critical",
    present: cookieTrustPresent
  });
  if (cookieTrustPresent) {
    findings.push({
      ruleId: "SUB-001",
      category: "cookie",
      severity: "critical",
      title: `Sensitive cookie(s) scoped to .${regDomain} — subdomain compromise exposes main-domain session`,
      impact: `An attacker who compromises any subdomain on ${regDomain} can access these session cookies and impersonate users on the apex domain.`,
      evidence: sanitizeEvidence(
        `Domain-wide sensitive cookies: ${broadCookies.slice(0, 5).join(", ")}`
      ),
      recommendation: "Set authentication and session cookies without the Domain attribute (host-only) or restrict to Domain=<specific-subdomain>. Avoid Domain=.example.com for session/auth cookies.",
      reference: REF_COOKIE
    });
  }
  const unshieldedSensitiveCookies = [];
  for (const cookie of cookies) {
    if (isSensitiveCookie(cookie.name) && !cookie.name.startsWith("__Host-")) {
      unshieldedSensitiveCookies.push(cookie.name);
    }
  }
  const cookieTossingRisk = unshieldedSensitiveCookies.length > 0;
  if (cookieTossingRisk) hasEscalationPath = true;
  vectors.push({
    id: "SUB-005",
    label: "Cookie Tossing / Shadowing Risk (Missing __Host- prefix)",
    detail: cookieTossingRisk ? `Sensitive cookie(s) lack __Host- prefix: ${unshieldedSensitiveCookies.slice(0, 3).join(", ")}. A compromised subdomain can inject Domain=.${regDomain} cookies to hijack sessions.` : "All sensitive cookies use __Host- prefix or none detected",
    risk: "medium",
    present: cookieTossingRisk
  });
  if (cookieTossingRisk) {
    findings.push({
      ruleId: "SUB-005",
      category: "cookie",
      severity: "medium",
      title: `Sensitive session cookie(s) lack __Host- prefix — vulnerable to Cookie Tossing from subdomains`,
      impact: `An attacker controlling any subdomain can overwrite or shadow main-domain session cookies by setting Domain=.${regDomain} cookies (Cookie Tossing).`,
      evidence: sanitizeEvidence(
        `Unprefixed sensitive cookies: ${unshieldedSensitiveCookies.slice(0, 5).join(", ")}`
      ),
      recommendation: "Prefix sensitive session cookies with __Host- (e.g. __Host-session=...) so browsers reject subdomains attempting to shadow or overwrite cookies for the main domain (RFC 6265bis §4.1.3).",
      reference: REF_COOKIE_TOSS
    });
  }
  let cspSubdomainTrust = false;
  let cspEvidence = "";
  if (effectiveScriptSrc !== void 0) {
    const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);
    if (!isModernStrict) {
      const tokens = cspTokens(effectiveScriptSrc);
      const dangerous = tokens.filter((t) => {
        const bare = t.replace(/^https?:\/\//, "");
        return bare === `*.${regDomain}` || bare === regDomain;
      });
      if (dangerous.length > 0) {
        cspSubdomainTrust = true;
        hasEscalationPath = true;
        cspEvidence = dangerous.join(" ");
      }
    }
  } else if (cspValue.length === 0) {
    cspSubdomainTrust = true;
    hasEscalationPath = true;
    cspEvidence = "(no CSP — all origins trusted implicitly)";
  }
  const subdomainTrustDetail = effectiveScriptSrc != null ? `script-src is scoped to explicit hosts (no wildcard subdomain trust for ${regDomain})` : `CSP present but script-src not found`;
  vectors.push({
    id: "SUB-002",
    label: "CSP trusts scripts from subdomains",
    detail: cspSubdomainTrust ? `Subdomain script source(s): ${cspEvidence}` : subdomainTrustDetail,
    risk: "critical",
    present: cspSubdomainTrust
  });
  if (cspSubdomainTrust && cspEvidence) {
    findings.push({
      ruleId: "SUB-002",
      category: "header",
      severity: "critical",
      title: `CSP script-src trusts wildcard *.${regDomain} — allows XSS pivot from any ${regDomain} subdomain`,
      impact: `An attacker who finds an XSS bug or hosts files on any ${regDomain} subdomain can execute scripts with full permissions on the main domain.`,
      evidence: sanitizeEvidence(cspEvidence),
      recommendation: `Replace wildcard subdomain source (*.${regDomain}) with explicit allowlisted hostnames or nonces/hashes.`,
      reference: REF_CSP
    });
  }
  let corsTrustPresent = false;
  let corsDetail = "";
  const corsWithCreds = corsCredsRaw?.toLowerCase().trim() === "true";
  if (corsOrigin.length > 0) {
    if (corsOrigin === "*") {
      corsTrustPresent = true;
      corsDetail = "Access-Control-Allow-Origin: *";
      if (corsWithCreds) corsDetail += " + Credentials: true (critical misconfiguration)";
    } else {
      try {
        const allowedHostname = new URL(corsOrigin).hostname;
        const allowedReg = registrableDomain(allowedHostname);
        if (allowedReg === regDomain && allowedHostname !== hostname) {
          corsTrustPresent = true;
          corsDetail = `Access-Control-Allow-Origin: ${corsOrigin} (trusts subdomain of same root)`;
          if (corsWithCreds) corsDetail += "; Access-Control-Allow-Credentials: true";
        }
      } catch {
      }
    }
  } else if (varyHeader.toLowerCase().includes("origin")) {
    corsTrustPresent = true;
    corsDetail = "Vary: Origin detected — server dynamically reflects requested Origin (frequent subdomain trust)";
  }
  if (corsTrustPresent) hasEscalationPath = true;
  vectors.push({
    id: "SUB-003",
    label: "CORS allows subdomain / wildcard origins",
    detail: corsTrustPresent ? corsDetail : corsOrigin.length > 0 ? `Access-Control-Allow-Origin: ${corsOrigin.slice(0, 80)} (no cross-subdomain trust detected)` : "No CORS header present",
    risk: "high",
    present: corsTrustPresent
  });
  if (corsTrustPresent) {
    findings.push({
      ruleId: "SUB-003",
      category: "cors",
      severity: "high",
      title: `CORS policy trusts subdomain origin — cross-subdomain API data exposure possible`,
      impact: "Compromised or attacker-controlled subdomains can send authenticated AJAX requests to your private APIs and read sensitive user data across origins.",
      evidence: sanitizeEvidence(corsDetail),
      recommendation: "Set Access-Control-Allow-Origin to an explicit allowlist of known origins. Never reflect the Origin request header without strict validation.",
      reference: REF_CORS
    });
  }
  let postMsgTrustPresent = false;
  let postMsgDetail = "";
  const frameableBySubdomain = xfo.length === 0 && (frameAncestors.length === 0 || frameAncestors.includes("*") || frameAncestors.length > 0 && cspAllowsSubdomain(frameAncestors, regDomain));
  if (frameableBySubdomain) {
    postMsgTrustPresent = true;
    postMsgDetail = frameAncestors ? `frame-ancestors: ${frameAncestors.slice(0, 80)}` : xfo ? `X-Frame-Options: ${xfo}` : "No frame-ancestors directive and no X-Frame-Options — page can be framed by any origin";
    hasEscalationPath = true;
  }
  vectors.push({
    id: "SUB-004",
    label: "postMessage / framing trust open to subdomains",
    detail: postMsgTrustPresent ? postMsgDetail : `Framing is restricted (${frameAncestors.length > 0 ? "frame-ancestors" : "X-Frame-Options"} present)`,
    risk: "high",
    present: postMsgTrustPresent
  });
  if (postMsgTrustPresent) {
    findings.push({
      ruleId: "SUB-004",
      category: "header",
      severity: "high",
      title: "Page can be framed by subdomains — postMessage confusion / clickjacking pivot possible",
      impact: "Subdomains can embed this page in an iframe to sniff postMessage data or perform clickjacking attacks on authenticated actions.",
      evidence: sanitizeEvidence(postMsgDetail),
      recommendation: `Add "Content-Security-Policy: frame-ancestors 'self'" or "X-Frame-Options: SAMEORIGIN" to prevent untrusted subdomains from embedding this page.`,
      reference: REF_CSP
    });
  }
  const coopMissing = coopHeader.length === 0 || !coopHeader.toLowerCase().includes("same-origin");
  if (coopMissing) {
    hasEscalationPath = true;
  }
  vectors.push({
    id: "SUB-006",
    label: "Cross-Origin-Opener-Policy (COOP) missing",
    detail: coopMissing ? coopHeader.length > 0 ? `COOP: ${coopHeader} (not same-origin)` : "COOP header absent — subdomains can manipulate window.opener" : `COOP is strict (${coopHeader})`,
    risk: "medium",
    present: coopMissing
  });
  if (coopMissing) {
    findings.push({
      ruleId: "SUB-006",
      category: "header",
      severity: "medium",
      title: "Missing Cross-Origin-Opener-Policy (COOP) — subdomains can access window.opener",
      impact: "Untrusted subdomains opened in new tabs or windows can access window.opener and silently redirect the parent tab to a phishing clone (Reverse Tabnabbing).",
      evidence: sanitizeEvidence(coopHeader.length > 0 ? coopHeader : "(header absent)"),
      recommendation: 'Set "Cross-Origin-Opener-Policy: same-origin" to isolate the top-level browsing context and prevent malicious subdomains from manipulating window.opener.',
      reference: REF_COOP
    });
  }
  const oacMissing = oacHeader.length === 0 || !oacHeader.includes("?1");
  vectors.push({
    id: "SUB-007",
    label: "Origin-Agent-Cluster missing (document.domain relaxation risk)",
    detail: oacMissing ? "Origin-Agent-Cluster: ?1 missing — legacy document.domain relaxation can bridge subdomains" : "Origin-Agent-Cluster: ?1 is active",
    risk: "low",
    present: oacMissing
  });
  if (oacMissing) {
    findings.push({
      ruleId: "SUB-007",
      category: "header",
      severity: "low",
      title: "Missing Origin-Agent-Cluster header — document.domain relaxation possible",
      impact: "Subdomains can alter document.domain to match the main domain, breaking Same-Origin-Policy boundaries and reading DOM content directly.",
      evidence: sanitizeEvidence(oacHeader.length > 0 ? oacHeader : "(header absent)"),
      recommendation: 'Add "Origin-Agent-Cluster: ?1" to prevent document.domain relaxation and enforce origin isolation.',
      reference: REF_OAC
    });
  }
  if (pageIsSubdomain && !hasEscalationPath) {
    vectors.push({
      id: "SUB-008",
      label: "Subdomain Isolated (No Escalation Path to Main Domain)",
      detail: `This page (${hostname}) is a subdomain, but no cookie scope, CSP wildcard, CORS, framing, or opener trust bridges to ${regDomain} were found.`,
      risk: "info",
      present: false
    });
    findings.push({
      ruleId: "SUB-008",
      category: "header",
      severity: "info",
      title: `Subdomain Isolated — no trust bridge to main domain detected`,
      impact: "This subdomain has no cookie, CSP, CORS, or framing trust bridges to the main domain; any security flaw found here remains strictly contained.",
      evidence: sanitizeEvidence(
        `${hostname} is isolated from ${regDomain}`
      ),
      recommendation: "No action required. Vulnerabilities on this subdomain remain isolated and cannot jump to the main domain based on current security controls.",
      reference: REF_SUBDOMAIN
    });
  }
  return { findings, hasEscalationPath, vectors };
}
function parseCookieName(setCookieHeader) {
  const eqIdx = setCookieHeader.indexOf("=");
  if (eqIdx === -1) return setCookieHeader.trim();
  return setCookieHeader.slice(0, eqIdx).trim();
}
function parseCookieHeaderMetadata(setCookieHeader) {
  const parts = setCookieHeader.split(";").map((part) => part.trim());
  const name = parseCookieName(setCookieHeader);
  let path = null;
  let domainAttributePresent = false;
  for (const attribute of parts.slice(1)) {
    const separator = attribute.indexOf("=");
    const attributeName = (separator === -1 ? attribute : attribute.slice(0, separator)).trim().toLowerCase();
    if (attributeName === "path" && separator !== -1) {
      path = attribute.slice(separator + 1).trim();
    }
    if (attributeName === "domain") domainAttributePresent = true;
  }
  return { name, path, domainAttributePresent };
}
function mapSameSite(chromeSameSite) {
  switch (chromeSameSite) {
    case "strict":
      return "strict";
    case "lax":
      return "lax";
    case "no_restriction":
      return "none";
    case "unspecified":
    default:
      return "";
  }
}
function isThirdPartyCookie(pageHostname, cookieDomain) {
  const normalised = (cookieDomain.startsWith(".") ? cookieDomain.slice(1) : cookieDomain).toLowerCase();
  const pageDomain = registrableDomain(pageHostname);
  const cookieRegistrableDomain = registrableDomain(normalised);
  if (pageDomain !== null && cookieRegistrableDomain !== null) {
    return pageDomain !== cookieRegistrableDomain;
  }
  const normalisedPage = pageHostname.toLowerCase();
  return normalisedPage !== normalised && !normalisedPage.endsWith(`.${normalised}`);
}
async function correlateCookies(_tabId, tabUrl, setCookieHeaders) {
  const headerMetadata = setCookieHeaders.map(parseCookieHeaderMetadata);
  const headerSetNames = new Set(headerMetadata.map((item) => item.name));
  let urlScopedCookies;
  try {
    urlScopedCookies = await chrome.cookies.getAll({ url: tabUrl });
  } catch {
    return [];
  }
  let pageHostname;
  try {
    pageHostname = new URL(tabUrl).hostname;
  } catch {
    pageHostname = "";
  }
  const records = urlScopedCookies.map(
    (cookie) => {
      const setByJs = headerSetNames.has(cookie.name) ? false : null;
      const matchingHeaders = headerMetadata.filter((item) => item.name === cookie.name);
      const matchingPath = matchingHeaders.find((item) => item.path === cookie.path);
      const headerMatch = matchingPath ?? (matchingHeaders.length === 1 ? matchingHeaders[0] : void 0);
      const thirdParty = isThirdPartyCookie(pageHostname, cookie.domain);
      const partitioned = cookie.partitionKey != null;
      const expiresAt = cookie.session ? null : Math.round(cookie.expirationDate ?? 0) * 1e3;
      return {
        name: cookie.name,
        domain: cookie.domain,
        domainAttributePresent: setByJs === null ? null : headerMatch?.domainAttributePresent ?? false,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: mapSameSite(cookie.sameSite),
        session: cookie.session,
        expiresAt,
        partitioned,
        setByJs,
        isThirdParty: thirdParty
        // cookie.value is intentionally NOT accessed here.
      };
    }
  );
  return records;
}
const REFERENCE$7 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security";
const HSTS_HEADER = "strict-transport-security";
const HSTS_MIN_MAX_AGE = 31536e3;
function checkHsts(finalHop) {
  if (!finalHop.url.startsWith("https://")) {
    return [];
  }
  const findings = [];
  const headerValue = finalHop.headers[HSTS_HEADER];
  if (headerValue === void 0) {
    findings.push({
      ruleId: "HSTS-001",
      category: "transport",
      severity: "high",
      title: "Strict-Transport-Security header is missing",
      impact: "An attacker on the same network (e.g. public Wi-Fi) can downgrade the connection to unencrypted HTTP and intercept passwords or session cookies (SSL Stripping).",
      evidence: sanitizeEvidence("(header absent)"),
      recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to all HTTPS responses.',
      reference: REFERENCE$7
    });
    return findings;
  }
  const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(headerValue);
  const maxAge = maxAgeMatch !== null ? parseInt(maxAgeMatch[1] ?? "0", 10) : 0;
  if (maxAge < HSTS_MIN_MAX_AGE) {
    findings.push({
      ruleId: "HSTS-002",
      category: "transport",
      severity: "medium",
      title: "Strict-Transport-Security max-age is below the recommended minimum (1 year)",
      impact: "A short expiration allows browsers to silently revert to unencrypted HTTP if a user revisits after the window expires.",
      evidence: sanitizeEvidence(headerValue),
      recommendation: `Increase max-age to at least ${HSTS_MIN_MAX_AGE} (1 year). Current value: ${maxAge}.`,
      reference: REFERENCE$7
    });
  }
  if (!/includeSubDomains/i.test(headerValue)) {
    findings.push({
      ruleId: "HSTS-003",
      category: "transport",
      severity: "low",
      title: "Strict-Transport-Security is missing the includeSubDomains directive",
      impact: "Subdomains are not forced to HTTPS, leaving them vulnerable to unencrypted network eavesdropping and cookie injection.",
      evidence: sanitizeEvidence(headerValue),
      recommendation: 'Add the "includeSubDomains" directive to ensure all subdomains are protected.',
      reference: REFERENCE$7
    });
  }
  return findings;
}
const REFERENCE$6 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy";
const CSP_HEADER = "content-security-policy";
function resolveEffective(directives, directive) {
  return directives.get(directive) ?? directives.get("default-src");
}
function sourceTokens(sourceList) {
  return sourceList.split(/\s+/).filter((t) => t.length > 0);
}
function hasWildcardSource(sourceList, isModernStrict) {
  if (isModernStrict) return false;
  const tokens = sourceTokens(sourceList);
  return tokens.some(
    (token) => token === "*" || token === "http:" || token === "https:"
  );
}
function checkCsp(finalHop, metaCspFound = false) {
  const findings = [];
  const cspValue = finalHop.headers[CSP_HEADER];
  if (cspValue === void 0) {
    if (metaCspFound) {
      findings.push({
        ruleId: "CSP-008",
        category: "header",
        severity: "info",
        title: "CSP detected in a meta tag; policy details are not evaluated",
        impact: "A meta CSP can enforce some policy directives, but it cannot replace response-header protections such as frame-ancestors and may take effect later in document parsing.",
        evidence: sanitizeEvidence('<meta http-equiv="Content-Security-Policy">'),
        recommendation: "Also send Content-Security-Policy as an HTTP response header for complete coverage. This report does not assess the meta policy contents.",
        reference: REFERENCE$6
      });
    } else {
      findings.push({
        ruleId: "CSP-001",
        category: "header",
        severity: "high",
        title: "Content-Security-Policy header is missing",
        impact: "Without a CSP, any Cross-Site Scripting (XSS) vulnerability can execute malicious scripts, steal login cookies, or take over user accounts.",
        evidence: sanitizeEvidence("(header absent)"),
        recommendation: `Add a Content-Security-Policy header. Start with a strict base policy such as "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'".`,
        reference: REFERENCE$6
      });
    }
    return { findings, directives: /* @__PURE__ */ new Map() };
  }
  const directives = parseCspDirectives(cspValue);
  const effectiveScriptSrc = resolveEffective(directives, "script-src");
  if (effectiveScriptSrc !== void 0) {
    const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);
    if (effectiveScriptSrc.includes("'unsafe-inline'")) {
      if (isModernStrict) {
        findings.push({
          ruleId: "CSP-002",
          category: "header",
          severity: "info",
          title: "CSP script-src includes 'unsafe-inline' as a legacy fallback (safely ignored due to nonce/strict-dynamic)",
          impact: "Older browsers may allow inline scripts, but modern browsers safely ignore this fallback because a nonce or strict-dynamic is present.",
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation: "No action needed for modern browsers. 'unsafe-inline' is ignored by CSP Level 3 browsers when a nonce or 'strict-dynamic' is present.",
          reference: REFERENCE$6
        });
      } else {
        findings.push({
          ruleId: "CSP-002",
          category: "header",
          severity: "high",
          title: "CSP script-src contains 'unsafe-inline'",
          impact: "Injected HTML tags (like <script> or event handlers) can execute arbitrary JavaScript directly inside victim browsers.",
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation: "Remove 'unsafe-inline' and use nonces or hashes to allow specific inline scripts.",
          reference: REFERENCE$6
        });
      }
    }
    if (effectiveScriptSrc.includes("'unsafe-eval'")) {
      findings.push({
        ruleId: "CSP-003",
        category: "header",
        severity: "high",
        title: "CSP script-src contains 'unsafe-eval'",
        impact: "Allows dynamic code execution via eval() and new Function(), enabling attackers who control string inputs to run arbitrary JavaScript.",
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation: "Remove 'unsafe-eval'. Refactor code that uses eval(), new Function(), or similar dynamic evaluation.",
        reference: REFERENCE$6
      });
    }
    if (hasWildcardSource(effectiveScriptSrc, isModernStrict)) {
      findings.push({
        ruleId: "CSP-004",
        category: "header",
        severity: "medium",
        title: "CSP script-src contains an overly broad wildcard or scheme-only source",
        impact: "Open wildcard sources allow scripts to be loaded and executed from any external host on the web.",
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation: "Replace wildcard or scheme-only sources (*, http:, https:) with explicit allowlisted hostnames or use nonces/hashes.",
        reference: REFERENCE$6
      });
    }
  }
  if (!directives.has("frame-ancestors")) {
    const xfo = finalHop.headers["x-frame-options"]?.trim().toUpperCase();
    const hasValidXfo = xfo === "DENY" || xfo === "SAMEORIGIN";
    findings.push({
      ruleId: "CSP-005",
      category: "header",
      severity: hasValidXfo ? "info" : "medium",
      title: hasValidXfo ? "CSP is missing 'frame-ancestors' (mitigated by X-Frame-Options)" : "CSP is missing the 'frame-ancestors' directive",
      impact: hasValidXfo ? "Legacy browsers without XFO support could potentially embed this page, but modern browsers are protected by X-Frame-Options." : "Malicious websites can embed your site in an invisible iframe to trick users into clicking buttons they cannot see (Clickjacking).",
      evidence: sanitizeEvidence(cspValue),
      recommendation: `Add "frame-ancestors 'none'" (or "'self'") to control which origins may embed this page.`,
      reference: REFERENCE$6
    });
  }
  const effectiveObjectSrc = resolveEffective(directives, "object-src");
  if (effectiveObjectSrc === void 0 || !sourceTokens(effectiveObjectSrc).includes("'none'")) {
    findings.push({
      ruleId: "CSP-006",
      category: "header",
      severity: "medium",
      title: "CSP object-src is absent or not restricted to 'none'",
      impact: "Allows plugins (Flash, Java applets, PDF objects) to load untrusted resources that can bypass standard script constraints.",
      evidence: sanitizeEvidence(effectiveObjectSrc ?? "(directive absent)"),
      recommendation: `Add "object-src 'none'" to block plugin-based content (Flash, Java applets, etc.).`,
      reference: REFERENCE$6
    });
  }
  if (!directives.has("base-uri")) {
    findings.push({
      ruleId: "CSP-007",
      category: "header",
      severity: "low",
      title: "CSP is missing the 'base-uri' directive",
      impact: "An attacker injecting a <base> tag can redirect all relative script, image, and form action URLs to an external phishing/exfiltration server.",
      evidence: sanitizeEvidence(cspValue),
      recommendation: `Add "base-uri 'none'" (or "'self'") to prevent base-tag injection attacks.`,
      reference: REFERENCE$6
    });
  }
  return { findings, directives };
}
const REFERENCE$5 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options";
const XFO_HEADER = "x-frame-options";
const VALID_VALUES = /* @__PURE__ */ new Set(["DENY", "SAMEORIGIN"]);
function checkXfo(finalHop, cspDirectives) {
  if (cspDirectives.has("frame-ancestors")) {
    return [];
  }
  const rawValue = finalHop.headers[XFO_HEADER];
  if (rawValue === void 0) {
    return [
      {
        ruleId: "XFO-001",
        category: "header",
        severity: "medium",
        title: "X-Frame-Options header is missing",
        impact: "Attackers can frame your site in an invisible iframe and overlay malicious decoy elements to hijack clicks and actions (Clickjacking).",
        evidence: sanitizeEvidence("(header absent)"),
        recommendation: 'Add "X-Frame-Options: DENY" (or SAMEORIGIN) to prevent clickjacking. Alternatively, use CSP frame-ancestors.',
        reference: REFERENCE$5
      }
    ];
  }
  const normalised = rawValue.trim().toUpperCase();
  if (!VALID_VALUES.has(normalised)) {
    return [
      {
        ruleId: "XFO-001",
        category: "header",
        severity: "medium",
        title: "X-Frame-Options header has an unrecognised value",
        impact: "Unrecognized values (such as deprecated ALLOW-FROM) are ignored by modern browsers, leaving the site vulnerable to iframe embedding and Clickjacking.",
        evidence: sanitizeEvidence(rawValue),
        recommendation: 'Set X-Frame-Options to either "DENY" or "SAMEORIGIN". The value "ALLOW-FROM" is deprecated and not supported in most browsers.',
        reference: REFERENCE$5
      }
    ];
  }
  return [];
}
const REFERENCE$4 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options";
const XCTO_HEADER = "x-content-type-options";
function checkXcto(finalHop) {
  const rawValue = finalHop.headers[XCTO_HEADER];
  if (rawValue === void 0) {
    return [
      {
        ruleId: "XCTO-001",
        category: "header",
        severity: "medium",
        title: "X-Content-Type-Options header is missing",
        impact: 'Browsers may guess ("sniff") response types, executing user-uploaded text or image files as malicious JavaScript (MIME-confusion XSS).',
        evidence: sanitizeEvidence("(header absent)"),
        recommendation: 'Add "X-Content-Type-Options: nosniff" to prevent MIME-type sniffing attacks.',
        reference: REFERENCE$4
      }
    ];
  }
  if (rawValue.trim().toLowerCase() !== "nosniff") {
    return [
      {
        ruleId: "XCTO-001",
        category: "header",
        severity: "medium",
        title: "X-Content-Type-Options header has an invalid value",
        impact: "Browsers do not recognize invalid values and fall back to content sniffing, re-opening MIME confusion attack vectors.",
        evidence: sanitizeEvidence(rawValue),
        recommendation: 'Set X-Content-Type-Options to exactly "nosniff". No other values are recognised by browsers.',
        reference: REFERENCE$4
      }
    ];
  }
  return [];
}
const REFERENCE$3 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy";
const REFERRER_HEADER = "referrer-policy";
const WEAK_POLICIES = /* @__PURE__ */ new Set([
  "unsafe-url",
  "no-referrer-when-downgrade",
  // browser default — effectively "no policy set"
  ""
  // explicit empty value
]);
function checkReferrer(finalHop) {
  const rawValue = finalHop.headers[REFERRER_HEADER];
  if (rawValue === void 0) {
    return [
      {
        ruleId: "REF-001",
        category: "header",
        severity: "low",
        title: "Referrer-Policy header is missing",
        impact: "Modern browsers default to strict-origin-when-cross-origin, but older browsers may leak full URL query parameters (tokens, IDs, search terms) to external sites in the Referer header.",
        evidence: sanitizeEvidence("(header absent)"),
        recommendation: 'Set Referrer-Policy to "strict-origin-when-cross-origin" or stricter to limit referrer leakage to third-party sites.',
        reference: REFERENCE$3
      }
    ];
  }
  const trimmedValue = rawValue.trim().toLowerCase();
  if (WEAK_POLICIES.has(trimmedValue)) {
    return [
      {
        ruleId: "REF-001",
        category: "header",
        severity: "low",
        title: "Referrer-Policy is set to a weak or privacy-leaking value",
        impact: "Transmits the full URL path and sensitive query parameters to third-party destinations when links are clicked.",
        evidence: sanitizeEvidence(rawValue),
        recommendation: 'Replace the current value with "strict-origin-when-cross-origin" or "no-referrer" to minimise referrer leakage.',
        reference: REFERENCE$3
      }
    ];
  }
  return [];
}
const REFERENCE$2 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection";
function checkDeprecated(finalHop) {
  const findings = [];
  const xssProtection = finalHop.headers["x-xss-protection"];
  if (xssProtection !== void 0) {
    findings.push({
      ruleId: "DEP-001",
      category: "header",
      severity: "info",
      title: "X-XSS-Protection is deprecated and should be removed",
      impact: "This legacy browser auditor is obsolete and can introduce client-side side-channel leaks or bypasses in older browsers. Modern security relies on CSP.",
      evidence: sanitizeEvidence(xssProtection),
      recommendation: "Remove this header and rely on Content-Security-Policy instead.",
      reference: REFERENCE$2
    });
  }
  return findings;
}
const REFERENCE$1 = "https://owasp.org/www-project-secure-headers/#server";
const LEAKY_HEADERS = [
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-aspnetmvc-version",
  "x-generator"
];
const VERSION_PATTERN = /[0-9]+\.[0-9]+/;
function isLeaky(value) {
  return VERSION_PATTERN.test(value);
}
function checkInfoLeak(finalHop) {
  const findings = [];
  for (const headerName of LEAKY_HEADERS) {
    const value = finalHop.headers[headerName];
    if (value !== void 0 && isLeaky(value)) {
      findings.push({
        ruleId: "LEAK-001",
        category: "header",
        severity: "low",
        title: `Version string in ${headerName} response header`,
        impact: "Broadcasting software and framework versions assists attackers in looking up known CVE exploits targeted specifically at your technology stack.",
        evidence: sanitizeEvidence(value),
        recommendation: "Remove or redact this header at your web server / reverse proxy.",
        reference: REFERENCE$1
      });
    }
  }
  return findings;
}
const REFERENCE = "https://owasp.org/www-project-secure-headers/#cache-control";
const CACHE_CONTROL_HEADER = "cache-control";
function checkCacheCookie(finalHop) {
  const setCookieHeaders = finalHop.rawHeaders.filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value);
  if (setCookieHeaders.length === 0) {
    return [];
  }
  const sensitiveCookies = setCookieHeaders.filter((headerVal) => {
    const name = headerVal.split("=")[0]?.trim() ?? "";
    const hasHttpOnly = /;\s*httponly/i.test(headerVal);
    return hasHttpOnly || isSensitiveCookie(name);
  });
  if (sensitiveCookies.length === 0) {
    return [];
  }
  const cacheControlValue = finalHop.headers[CACHE_CONTROL_HEADER];
  if (cacheControlValue === void 0) {
    return [
      {
        ruleId: "CACHE-001",
        category: "header",
        severity: "medium",
        title: "Cache-Control: no-store missing on a response that sets sensitive cookies",
        impact: "Responses setting authentication cookies may be stored by intermediate web caches or proxy servers, exposing user session tokens to unauthorized parties.",
        evidence: sanitizeEvidence("(header absent)"),
        recommendation: 'Add "Cache-Control: no-store" to responses that set authentication or session cookies.',
        reference: REFERENCE
      }
    ];
  }
  const normalised = cacheControlValue.toLowerCase();
  if (normalised.includes("no-store")) {
    return [];
  }
  if (normalised.includes("private") || normalised.includes("no-cache")) {
    return [
      {
        ruleId: "CACHE-001",
        category: "header",
        severity: "info",
        title: "Cache-Control allows local caching for response with sensitive cookies (mitigated by private/no-cache)",
        impact: 'Intermediate proxy/CDN caching is prevented by "private", but local browser storage persists the response, which could be exposed on shared kiosk computers.',
        evidence: sanitizeEvidence(cacheControlValue),
        recommendation: 'Shared CDN caching is prevented by "private", but consider "no-store" if shared/public computers are in scope.',
        reference: REFERENCE
      }
    ];
  }
  return [
    {
      ruleId: "CACHE-001",
      category: "header",
      severity: "medium",
      title: "Cache-Control: no-store missing on a response that sets sensitive cookies",
      impact: "Sensitive authentication tokens and responses can be cached by shared CDN or proxy servers, allowing other users to retrieve session data.",
      evidence: sanitizeEvidence(cacheControlValue),
      recommendation: 'Add "Cache-Control: no-store" to responses setting sensitive session cookies.',
      reference: REFERENCE
    }
  ];
}
const REF_COOKIES = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies";
const REF_PREFIX = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes";
const REF_SAMESITE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite";
function checkSecure(cookie, isHttps) {
  if (!isHttps) return null;
  if (cookie.secure) return null;
  const sensitive = isSensitiveCookie(cookie.name);
  return {
    ruleId: "COOK-001",
    category: "cookie",
    severity: sensitive ? "high" : "low",
    title: `${sensitive ? "Sensitive cookie" : "Cookie"} "${sanitizeEvidence(cookie.name)}" is missing the Secure flag`,
    impact: "The cookie can be transmitted across unencrypted HTTP links, allowing network eavesdroppers to intercept session tokens or user data in cleartext.",
    evidence: sanitizeEvidence(cookie.name),
    recommendation: "Add the Secure attribute so the cookie is never sent over plain HTTP.",
    reference: REF_COOKIES
  };
}
function checkHttpOnly(cookie) {
  if (cookie.httpOnly) return null;
  if (cookie.setByJs === true) return null;
  if (!isSensitiveCookie(cookie.name)) return null;
  return {
    ruleId: "COOK-002",
    category: "cookie",
    severity: "medium",
    title: `Sensitive cookie "${sanitizeEvidence(cookie.name)}" is missing the HttpOnly flag`,
    impact: "This sensitive session cookie is readable by JavaScript via document.cookie, meaning any Cross-Site Scripting (XSS) attack can immediately steal it.",
    evidence: sanitizeEvidence(cookie.name),
    recommendation: "Add HttpOnly so this sensitive session/auth cookie cannot be read by JavaScript (mitigates XSS cookie theft).",
    reference: REF_COOKIES
  };
}
function checkSameSiteNone(cookie) {
  if (cookie.sameSite !== "none") return null;
  if (cookie.secure) return null;
  return {
    ruleId: "COOK-003",
    category: "cookie",
    severity: "high",
    title: `Cookie "${sanitizeEvidence(cookie.name)}" uses SameSite=None without Secure`,
    impact: "SameSite=None permits cross-site requests to send this cookie, but omitting Secure allows it to travel unencrypted, violating modern browser security standards.",
    evidence: sanitizeEvidence(cookie.name),
    recommendation: "Add the Secure attribute or change SameSite to Strict or Lax.",
    reference: REF_SAMESITE
  };
}
function checkSameSiteMissing(cookie) {
  if (cookie.sameSite !== "") return null;
  return {
    ruleId: "COOK-004",
    category: "cookie",
    severity: "info",
    title: `Cookie "${sanitizeEvidence(cookie.name)}" has no explicit SameSite attribute (defaults to Lax in modern browsers)`,
    impact: "Modern browsers automatically enforce SameSite=Lax for this cookie, though older clients without Lax-by-default support may still attach it to cross-site requests.",
    evidence: sanitizeEvidence(cookie.name),
    recommendation: "Modern browsers (Chrome 80+, Firefox, Safari) enforce SameSite=Lax by default. Explicitly setting SameSite=Lax or Strict is recommended for defense-in-depth on legacy clients.",
    reference: REF_SAMESITE
  };
}
function checkHostPrefix(cookie) {
  if (!cookie.name.startsWith("__Host-")) return null;
  const violations = [];
  if (!cookie.secure) violations.push("Secure flag missing");
  if (cookie.path !== "/") violations.push(`Path is "${cookie.path}" (must be /)`);
  if (cookie.domainAttributePresent === true) {
    violations.push("Domain attribute must be absent");
  }
  if (violations.length === 0) return null;
  return {
    ruleId: "COOK-005",
    category: "cookie",
    severity: "high",
    title: `Cookie "${sanitizeEvidence(cookie.name)}" violates __Host- prefix requirements`,
    impact: "Failing __Host- prefix requirements breaks browser isolation guarantees, allowing subdomains or subpaths to overwrite or shadow the main session cookie.",
    evidence: sanitizeEvidence(violations.join("; ")),
    recommendation: "Fix the cookie so it has Secure=true, Path=/, and no Domain attribute.",
    reference: REF_PREFIX
  };
}
function checkSecurePrefix(cookie) {
  if (!cookie.name.startsWith("__Secure-")) return null;
  if (cookie.secure) return null;
  return {
    ruleId: "COOK-006",
    category: "cookie",
    severity: "high",
    title: `Cookie "${sanitizeEvidence(cookie.name)}" violates __Secure- prefix requirements`,
    impact: "The __Secure- prefix explicitly promises the cookie will only be sent over HTTPS. Omitting Secure causes browsers to reject the cookie or allow plaintext transmission.",
    evidence: sanitizeEvidence(cookie.name),
    recommendation: "Add the Secure attribute — the __Secure- prefix requires it.",
    reference: REF_PREFIX
  };
}
function checkCookies(cookies, isHttps) {
  const findings = [];
  for (const cookie of cookies) {
    const secure = checkSecure(cookie, isHttps);
    const httpOnly = checkHttpOnly(cookie);
    const sameNone = checkSameSiteNone(cookie);
    const sameMiss = checkSameSiteMissing(cookie);
    const host = checkHostPrefix(cookie);
    const secPfx = checkSecurePrefix(cookie);
    if (secure !== null) findings.push(secure);
    if (httpOnly !== null) findings.push(httpOnly);
    if (sameNone !== null) findings.push(sameNone);
    if (sameMiss !== null) findings.push(sameMiss);
    if (host !== null) findings.push(host);
    if (secPfx !== null) findings.push(secPfx);
  }
  return findings;
}
const rules = {
  "HSTS-001": {
    penalty: 20,
    rationale: "OWASP ASVS 9.2.1 — HSTS required on all HTTPS responses"
  },
  "HSTS-002": {
    penalty: 5,
    rationale: "max-age below 1 year weakens HSTS guarantees"
  },
  "HSTS-003": {
    penalty: 3,
    rationale: "includeSubDomains missing — subdomains are unprotected"
  },
  "CSP-001": {
    penalty: 20,
    rationale: "OWASP ASVS 14.4.3 — CSP required"
  },
  "CSP-002": {
    penalty: 15,
    rationale: "unsafe-inline allows inline XSS attacks"
  },
  "CSP-003": {
    penalty: 10,
    rationale: "unsafe-eval allows eval()-based code injection"
  },
  "CSP-004": {
    penalty: 5,
    rationale: "Wildcard source allows script from any host"
  },
  "CSP-005": {
    penalty: 5,
    rationale: "frame-ancestors absent — clickjacking risk"
  },
  "CSP-006": {
    penalty: 5,
    rationale: "object-src not restricted — plugin injection risk"
  },
  "CSP-007": {
    penalty: 3,
    rationale: "base-uri absent — base-tag injection risk"
  },
  "XCTO-001": {
    penalty: 8,
    rationale: "MIME sniffing enables content-type confusion attacks"
  },
  "XFO-001": {
    penalty: 8,
    rationale: "Clickjacking protection missing"
  },
  "REF-001": {
    penalty: 5,
    rationale: "Weak referrer policy leaks URL to third parties"
  },
  "DEP-001": {
    penalty: 0,
    rationale: "X-XSS-Protection is deprecated — informational only"
  },
  "LEAK-001": {
    penalty: 3,
    rationale: "Version disclosure aids targeted exploitation"
  },
  "CACHE-001": {
    penalty: 5,
    rationale: "Cached cookie-setting responses expose session data"
  },
  "COOK-001": {
    penalty: 10,
    rationale: "OWASP ASVS 3.4.1 — Secure flag required on HTTPS"
  },
  "COOK-002": {
    penalty: 7,
    rationale: "OWASP ASVS 3.4.2 — HttpOnly prevents JS cookie theft"
  },
  "COOK-003": {
    penalty: 10,
    rationale: "RFC 6265bis §8.8 — SameSite=None requires Secure"
  },
  "COOK-004": {
    penalty: 0,
    rationale: "Informational — modern browsers default missing SameSite to Lax automatically"
  },
  "COOK-005": {
    penalty: 10,
    rationale: "RFC 6265bis §4.1.3 — __Host- prefix requires Secure+Path=/+no Domain"
  },
  "COOK-006": {
    penalty: 10,
    rationale: "RFC 6265bis §4.1.3 — __Secure- prefix requires Secure flag"
  },
  "SUB-001": {
    penalty: 15,
    rationale: "Domain-wide cookie scope lets subdomain attacker steal main-domain session"
  },
  "SUB-002": {
    penalty: 10,
    rationale: "CSP wildcard subdomain trust allows XSS pivot from any compromised subdomain"
  },
  "SUB-003": {
    penalty: 12,
    rationale: "CORS trusts subdomain origin — credentialed API data exposed cross-subdomain"
  },
  "SUB-004": {
    penalty: 10,
    rationale: "Page frameable by subdomains — postMessage confusion / clickjacking pivot"
  },
  "SUB-005": {
    penalty: 8,
    rationale: "Sensitive cookies lack __Host- prefix — vulnerable to Cookie Tossing from subdomains"
  },
  "SUB-006": {
    penalty: 4,
    rationale: "Missing Cross-Origin-Opener-Policy allows window.opener manipulation from subdomains"
  },
  "SUB-007": {
    penalty: 2,
    rationale: "Missing Origin-Agent-Cluster allows document.domain relaxation cross-subdomain"
  },
  "SUB-008": {
    penalty: 0,
    rationale: "Informational — Subdomain isolated with no trust bridges to main domain"
  }
};
const weights = {
  rules
};
const WEIGHTS = weights;
const CATEGORY_CAPS = {
  cookie: 25,
  // A site can never lose more than 25 points solely from cookie issues
  transport: 25,
  // Transport issues (HSTS, etc.) capped at 25 points
  header: 55,
  // Header issues capped at 55 points
  cors: 20
  // CORS issues capped at 20 points
};
function computeScore(findings, fromCache = false) {
  let score = 100;
  const breakdown = [];
  const findingsByRule = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    if (finding.severity === "pass" || finding.severity === "info") {
      continue;
    }
    const list = findingsByRule.get(finding.ruleId) ?? [];
    list.push(finding);
    findingsByRule.set(finding.ruleId, list);
  }
  const deductionsByCategory = /* @__PURE__ */ new Map();
  for (const [ruleId, ruleFindings] of findingsByRule.entries()) {
    const first = ruleFindings[0];
    if (!first) continue;
    const weightConfig = WEIGHTS.rules[ruleId];
    let basePenalty = weightConfig?.penalty ?? 0;
    if (fromCache && (ruleId.startsWith("CSP-001") || ruleId.startsWith("HSTS-001") || ruleId.startsWith("XFO-001") || ruleId.startsWith("CACHE-001"))) {
      basePenalty = Math.round(basePenalty * 0.5);
    }
    let appliedPenalty = basePenalty;
    if (ruleFindings.length > 1 && basePenalty > 0) {
      appliedPenalty = Math.min(Math.round(basePenalty * 1.25), basePenalty + 5);
    }
    const category = first.category ?? "header";
    const currentCatDeduction = deductionsByCategory.get(category) ?? 0;
    const catCap = CATEGORY_CAPS[category] ?? 100;
    const allowableDeduction = Math.max(0, Math.min(appliedPenalty, catCap - currentCatDeduction));
    deductionsByCategory.set(category, currentCatDeduction + allowableDeduction);
    score -= allowableDeduction;
    const countSuffix = ruleFindings.length > 1 ? ` (${ruleFindings.length} items affected)` : "";
    const cacheSuffix = fromCache && basePenalty !== (weightConfig?.penalty ?? 0) ? " [cached — unverified]" : "";
    breakdown.push({
      ruleId,
      title: `${first.title}${countSuffix}${cacheSuffix}`,
      severity: first.severity,
      weight: weightConfig?.penalty ?? 0,
      penalty: allowableDeduction
    });
  }
  const clampedScore = Math.max(0, Math.min(100, score));
  const gradeEntry = GRADE_THRESHOLDS.find(
    (entry) => clampedScore >= entry.min
  );
  const grade = gradeEntry?.grade ?? "F";
  return {
    score: clampedScore,
    grade,
    breakdown,
    scoreVersion: SCORE_VERSION
  };
}
function runRules(input) {
  const { hops } = input;
  const emptySubdomainTrust = { hasEscalationPath: false, vectors: [] };
  if (hops.length === 0) {
    return {
      findings: [],
      score: 100,
      grade: "A",
      breakdown: [],
      scoreVersion: "",
      subdomainTrust: emptySubdomainTrust
    };
  }
  const finalHop = hops[hops.length - 1];
  if (finalHop === void 0) {
    return { findings: [], score: 100, grade: "A", breakdown: [], scoreVersion: "", subdomainTrust: emptySubdomainTrust };
  }
  const findings = [];
  findings.push(...checkHsts(finalHop));
  const { findings: cspFindings, directives } = checkCsp(finalHop, input.metaCspFound);
  findings.push(...cspFindings);
  findings.push(...checkXfo(finalHop, directives));
  findings.push(...checkXcto(finalHop));
  findings.push(...checkReferrer(finalHop));
  findings.push(...checkDeprecated(finalHop));
  findings.push(...checkInfoLeak(finalHop));
  findings.push(...checkCacheCookie(finalHop));
  const isHttps = finalHop.url.startsWith("https://");
  findings.push(...checkCookies(input.cookies, isHttps));
  const subdomainResult = checkSubdomainTrust(finalHop, input.cookies);
  findings.push(...subdomainResult.findings);
  const findingsWithSource = findings.map((finding) => ({
    ...finding,
    sourceUrl: finalHop.url
  }));
  const { score, grade, breakdown, scoreVersion } = computeScore(findingsWithSource, finalHop.fromCache);
  return {
    findings: findingsWithSource,
    score,
    grade,
    breakdown,
    scoreVersion,
    subdomainTrust: {
      hasEscalationPath: subdomainResult.hasEscalationPath,
      vectors: subdomainResult.vectors
    }
  };
}
const portRegistry = new PortRegistry();
const pendingServiceWorkerReports = /* @__PURE__ */ new Map();
const pendingMetaCspReports = /* @__PURE__ */ new Set();
function recomputeTabState(tabId, state) {
  const result = runRules({
    hops: state.hops,
    cookies: state.cookies,
    origin: state.origin,
    metaCspFound: state.coverage.metaCspFound
  });
  state.findings = result.findings;
  state.score = result.score;
  state.grade = result.grade;
  state.scoreBreakdown = result.breakdown;
  state.scoreVersion = result.scoreVersion;
  state.subdomainTrust = result.subdomainTrust;
  state.updatedAt = Date.now();
  tabStates.set(tabId, state);
  void SessionStorage.setTabState(state);
  if (state.monitoredByUser && state.origin) {
    void LocalStorage.recordOriginHistory(state.origin, {
      timestamp: state.updatedAt,
      score: state.score,
      grade: state.grade
    });
  }
  setBadgeForTab(tabId, state.grade);
  portRegistry.broadcast(tabId, { type: "TAB_STATE_UPDATE", state });
}
function isRestrictedUrl(url) {
  return RESTRICTED_SCHEMES.some((scheme) => url.startsWith(scheme));
}
function setBadgeForTab(tabId, grade) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  const color = BADGE_COLORS[grade];
  const text = grade === "?" ? "?" : grade;
  chrome.action.setBadgeText({ text, tabId }).catch(() => void 0);
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => void 0);
}
function createDefaultTabState(tabId, url) {
  const origin = originFromUrl(url) ?? url;
  const serviceWorkerReport = pendingServiceWorkerReports.get(tabId);
  const coverage = {
    hopsExpected: 1,
    hopsCaptured: 0,
    hasCache: false,
    hasServiceWorker: serviceWorkerReport?.status === "controlled",
    serviceWorkerStatus: serviceWorkerReport?.status ?? "unknown",
    serviceWorkerUrl: serviceWorkerReport?.serviceWorkerUrl ?? null,
    isRestricted: isRestrictedUrl(url),
    metaCspFound: pendingMetaCspReports.has(tabId)
  };
  return {
    tabId,
    origin,
    url,
    hops: [],
    cookies: [],
    findings: [],
    grade: "F",
    score: 0,
    scoreVersion: "",
    scoreBreakdown: [],
    coverage,
    subdomainTrust: { hasEscalationPath: false, vectors: [] },
    monitoredByUser: false,
    updatedAt: Date.now()
  };
}
async function onHopComplete(tabId, hop) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  const state = tabStates.get(tabId) ?? createDefaultTabState(tabId, hop.url);
  state.url = hop.url;
  state.origin = originFromUrl(hop.url) ?? hop.url;
  if (isRestrictedUrl(hop.url)) {
    state.coverage.isRestricted = true;
    tabStates.set(tabId, state);
    setBadgeForTab(tabId, "?");
    return;
  }
  const origin = state.origin;
  if (!origin || origin === hop.url) return;
  const permitted = await new Promise(
    (resolve) => chrome.permissions.contains({ origins: [`${origin}/*`] }, resolve)
  );
  if (!permitted) {
    state.coverage.isRestricted = false;
    setBadgeForTab(tabId, "?");
    return;
  }
  state.coverage.metaCspFound ||= pendingMetaCspReports.has(tabId);
  state.monitoredByUser = true;
  state.hops = [...state.hops, hop];
  state.coverage.hopsExpected = Math.max(
    state.coverage.hopsExpected,
    state.hops.reduce((count, item) => count + 1 + (item.redirectCount ?? 0), 0)
  );
  state.coverage.hopsCaptured = state.hops.length;
  state.coverage.hasCache = state.coverage.hasCache || hop.fromCache;
  const setCookieValues = extractSetCookieHeaders(hop.rawHeaders);
  const correlatedCookies = await correlateCookies(tabId, hop.url, setCookieValues);
  state.cookies = correlatedCookies;
  recomputeTabState(tabId, state);
}
chrome.webNavigation.onBeforeNavigate.addListener(
  (details) => {
    if (details.frameId !== 0) return;
    const { tabId } = details;
    pendingServiceWorkerReports.delete(tabId);
    pendingMetaCspReports.delete(tabId);
    tabStates.delete(tabId);
    SessionStorage.removeTabState(tabId).catch(() => void 0);
    for (const [requestId, partial] of captureMap.entries()) {
      if (partial.tabId === tabId) {
        captureMap.delete(requestId);
      }
    }
    setBadgeForTab(tabId, "?");
  }
);
function injectPageSignals(tabId, url) {
  const origin = originFromUrl(url);
  if (origin === null || origin.length === 0) return;
  chrome.permissions.contains({ origins: [`${origin}/*`] }, (permitted) => {
    if (!permitted) return;
    void chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: reportPageSignals
    }).catch(() => void 0);
  });
}
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  injectPageSignals(details.tabId, details.url);
});
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  injectPageSignals(details.tabId, details.url);
});
chrome.cookies.onChanged.addListener(
  (changeInfo) => {
    if (changeInfo.removed) return;
    const affectedDomain = changeInfo.cookie.domain.replace(/^\./, "");
    for (const [tabId, state] of tabStates.entries()) {
      const tabHostname = (() => {
        try {
          return new URL(state.url).hostname;
        } catch {
          return "";
        }
      })();
      if (!tabHostname.endsWith(affectedDomain)) continue;
      void (async () => {
        try {
          const correlatedCookies = await correlateCookies(tabId, state.url, []);
          state.cookies = correlatedCookies;
          recomputeTabState(tabId, state);
        } catch {
        }
      })();
    }
  }
);
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
  pendingMetaCspReports.delete(tabId);
  SessionStorage.removeTabState(tabId).catch(() => void 0);
});
chrome.runtime.onConnect.addListener((port) => {
  const isPopup = port.name === POPUP_PORT_NAME;
  const isSidePanel = port.name === SIDEPANEL_PORT_NAME;
  if (!isPopup && !isSidePanel) return;
  const senderTabId = port.sender?.tab?.id;
  if (senderTabId !== void 0) {
    portRegistry.register(port, senderTabId);
    const current = tabStates.get(senderTabId);
    if (current) {
      const response = {
        type: "STATE_RESPONSE",
        state: current
      };
      portSend(port, response);
    }
  }
  port.onMessage.addListener((msg) => {
    if (msg.type === "REQUEST_STATE") {
      const resolvedTabId = msg.tabId ?? senderTabId;
      if (resolvedTabId === void 0) return;
      portRegistry.register(port, resolvedTabId);
      const stateForTab = tabStates.get(resolvedTabId);
      const response = {
        type: "STATE_RESPONSE",
        state: stateForTab ?? null
      };
      portSend(port, response);
    }
  });
});
chrome.runtime.onMessage.addListener(
  (message, _sender, sendResponse) => {
    if (message.type === "REQUEST_STATE") {
      const stateForTab = message.tabId !== void 0 ? tabStates.get(message.tabId) ?? null : null;
      const response = {
        type: "STATE_RESPONSE",
        state: stateForTab
      };
      sendResponse(response);
      return false;
    }
    if (message.type === "PERMISSIONS_CHANGED") {
      void (async () => {
        try {
          const settings = await LocalStorage.getSettings();
          const settingsMsg = {
            type: "SETTINGS_CHANGED",
            settings
          };
          portRegistry.broadcastAll(settingsMsg);
        } catch {
        }
      })();
      return false;
    }
    if (message.type === "SETTINGS_CHANGED") {
      portRegistry.broadcastAll(message);
      sendResponse(message);
      return false;
    }
    if (message.type === "SERVICE_WORKER_STATUS") {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== void 0) {
        const report = {
          status: message.status,
          serviceWorkerUrl: message.serviceWorkerUrl
        };
        pendingServiceWorkerReports.set(senderTabId, report);
        const state = tabStates.get(senderTabId);
        if (state) {
          state.coverage.serviceWorkerStatus = report.status;
          state.coverage.serviceWorkerUrl = report.serviceWorkerUrl;
          state.coverage.hasServiceWorker = report.status === "controlled";
          recomputeTabState(senderTabId, state);
        }
      }
      return false;
    }
    if (message.type === "META_CSP_FOUND") {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== void 0) {
        pendingMetaCspReports.add(senderTabId);
        const state = tabStates.get(senderTabId);
        if (state && !state.coverage.metaCspFound) {
          state.coverage.metaCspFound = true;
          recomputeTabState(senderTabId, state);
        }
      }
      return false;
    }
    return false;
  }
);
void (async () => {
  await hydrateFromSession();
  initLifecycle();
  registerCaptureListeners((tabId, hop) => {
    void onHopComplete(tabId, hop);
  });
})();
//# sourceMappingURL=index.ts-C9Ia1w9X.js.map
