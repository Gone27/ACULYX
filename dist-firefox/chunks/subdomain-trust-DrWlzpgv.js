//#region src/rules/utils.ts
var CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
var BIDI_OVERRIDE_RE = /[\u200B-\u200D\u202A-\u202E\u2066-\u2069\uFEFF]/g;
/**
* Sanitise an evidence string for safe storage and display.
* Uses only textContent-safe characters — no HTML escaping needed,
* but we still escape the dangerous control/BiDi chars.
*/
function sanitizeEvidence(raw) {
	let s = raw.slice(0, 500).replace(CONTROL_CHAR_RE, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).replace(BIDI_OVERRIDE_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
	if (raw.length > 500) s += ` … [${raw.length - 500} chars truncated]`;
	return s;
}
/** Find conflicting repeated values among security-sensitive response headers. */
function checkDuplicateHeaders(hop) {
	const names = [
		"strict-transport-security",
		"x-frame-options",
		"referrer-policy",
		"x-content-type-options",
		"x-xss-protection"
	];
	const findings = [];
	for (const name of names) {
		const values = hop.rawHeaders.filter((header) => header.name.toLowerCase() === name).map((header) => header.value.trim());
		if (values.length < 2 || new Set(values).size < 2) continue;
		findings.push({
			ruleId: "DUP-001",
			category: "header",
			severity: "info",
			title: `Conflicting duplicate ${name} headers`,
			impact: "Browsers and intermediaries may interpret conflicting repeated policy values differently.",
			evidence: sanitizeEvidence(`${name}: ${values.join(" | ")}`),
			recommendation: "Configure the server or proxy to emit one authoritative value for this header.",
			reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
		});
	}
	return findings;
}
/**
* Build a lowercase-keyed header map from the raw WebRequest header array.
* For most headers last-value-wins; Set-Cookie is handled separately by the
* correlate module since it's always multi-valued.
*/
function normalizeHeaders(raw) {
	const map = {};
	for (const { name, value } of raw) if (value != null) map[name.toLowerCase()] = value;
	return map;
}
/**
* Collect every Set-Cookie header value as a raw string array.
* The webRequest API may present them as a single joined header or
* as multiple entries depending on Chrome version.
*/
function extractSetCookieHeaders(raw) {
	return raw.filter((h) => h.name.toLowerCase() === "set-cookie" && h.value != null).map((h) => h.value);
}
/**
* Compare two header maps and return true if they differ in any key or value.
* Used to detect modifications made by other extensions between
* onHeadersReceived and onResponseStarted.
*/
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
/**
* Parse a raw CSP string into a directive map.
* Keys are directive names (lowercase), values are the raw source-list string.
* This is a best-effort linear-time parser — not a full evaluator.
* For thorough analysis, use csp-evaluator on top of this.
*/
function parseCspDirectives(csp) {
	const directives = /* @__PURE__ */ new Map();
	for (const part of csp.split(";")) {
		const trimmed = part.trim();
		if (trimmed.length === 0) continue;
		const spaceIdx = trimmed.indexOf(" ");
		if (spaceIdx === -1) directives.set(trimmed.toLowerCase(), "");
		else {
			const name = trimmed.slice(0, spaceIdx).toLowerCase();
			const value = trimmed.slice(spaceIdx + 1).trim();
			directives.set(name, value);
		}
	}
	return directives;
}
/** Extract the scheme+host+port origin from a URL string, or null on failure. */
function originFromUrl(url) {
	try {
		const u = new URL(url);
		return u.origin === "null" ? null : u.origin;
	} catch {
		return null;
	}
}
var SENSITIVE_COOKIE_RE = /(^|[-_])(session|sess|auth|token|jwt|sid|login|sso|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|credential|secret|password|access[-_]?token|id[-_]?token)([-_]|$)/i;
var NON_SENSITIVE_COOKIE_RE = /(^|[-_])(ga|gid|gat|gcl|fbp|fbc|theme|dark|light|lang|locale|country|currency|timezone|tz|sidebar|banner|notice|consent|cookie_consent|optout|optimizely|amplitude|intercom|csrf|xsrf|csrftoken)([-_]|$)/i;
/**
* Returns true when a cookie's name indicates it is likely an authentication,
* session, or authorization token that requires strict security flags (HttpOnly, Secure).
*
* Harmless client-side cookies (analytics, UI preferences, language, CSRF tokens that
* need JS reading in double-submit patterns) return false.
*/
function isSensitiveCookie(name, alwaysSensitive = [], alwaysIgnore = []) {
	if (alwaysIgnore.includes(name)) return {
		isSensitive: false,
		reason: "override"
	};
	if (alwaysSensitive.includes(name)) return {
		isSensitive: true,
		reason: "override"
	};
	if (name.startsWith("__Host-") || name.startsWith("__Secure-")) return {
		isSensitive: true,
		reason: "prefix"
	};
	if (NON_SENSITIVE_COOKIE_RE.test(name)) return {
		isSensitive: false,
		reason: "regex"
	};
	return {
		isSensitive: SENSITIVE_COOKIE_RE.test(name),
		reason: "regex"
	};
}
var NONCE_RE = /'nonce-[A-Za-z0-9+/=_-]+'/i;
var HASH_RE = /'sha(256|384|512)-[A-Za-z0-9+/=_-]+'/i;
/**
* Checks whether a script-src source-list employs modern CSP Level 3 safeguards
* (nonces, hashes, or 'strict-dynamic').
*
* In CSP Level 3:
*  - If 'nonce-...' or 'sha...' is present, browsers ignore 'unsafe-inline'.
*  - If 'strict-dynamic' is present, browsers ignore 'unsafe-inline' and host sources (e.g. https:).
*/
function hasCspBypassProtection(sourceList) {
	const hasNonce = NONCE_RE.test(sourceList);
	const hasHash = HASH_RE.test(sourceList);
	const hasStrictDynamic = sourceList.includes("'strict-dynamic'");
	return {
		hasNonce,
		hasHash,
		hasStrictDynamic,
		isModernStrict: hasNonce || hasHash || hasStrictDynamic
	};
}
var SENSITIVE_PARAM_NAMES = /* @__PURE__ */ new Set([
	"token",
	"access_token",
	"id_token",
	"refresh_token",
	"auth",
	"authentication",
	"api_key",
	"apikey",
	"key",
	"secret",
	"password",
	"passwd",
	"pwd",
	"session",
	"sessionid",
	"sessid",
	"sig",
	"signature",
	"code",
	"ticket",
	"credential",
	"pass",
	"passphrase",
	"user_pass"
]);
var SENSITIVE_PATH_KEYWORDS = /* @__PURE__ */ new Set([
	"reset",
	"token",
	"tokens",
	"auth",
	"password",
	"passwords",
	"passwd",
	"pwd",
	"invite",
	"invites",
	"invitation",
	"verify",
	"verification",
	"confirm",
	"confirmation",
	"session",
	"sessions",
	"secret",
	"secrets",
	"key",
	"keys",
	"apikey",
	"otp",
	"code",
	"codes",
	"recovery"
]);
var COMMON_SAFE_SUBPATHS = /* @__PURE__ */ new Set([
	"login",
	"logout",
	"signin",
	"signout",
	"signup",
	"register",
	"status",
	"check",
	"user",
	"users",
	"me",
	"profile",
	"settings",
	"account",
	"callback",
	"refresh",
	"new",
	"edit",
	"delete",
	"update",
	"create",
	"view",
	"list"
]);
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var JWT_RE = /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/;
var LONG_OPAQUE_RE = /^[a-zA-Z0-9_.-]{20,}$/;
/**
* Redacts sensitive path segments (tokens, UUIDs, JWTs, opaque hashes, and parameters following
* keywords like /reset/ or /token/) from URL paths to prevent credential persistence in storage/UI.
*/
function redactUrlPath(pathname) {
	const segments = pathname.split("/");
	for (let i = 0; i < segments.length; i++) {
		const seg = segments[i];
		if (seg === void 0 || seg.length === 0) continue;
		if (UUID_RE.test(seg)) {
			segments[i] = "[id]";
			continue;
		}
		if (JWT_RE.test(seg)) {
			segments[i] = "[token]";
			continue;
		}
		const prev = i > 0 ? segments[i - 1]?.toLowerCase() : void 0;
		if (prev !== void 0 && SENSITIVE_PATH_KEYWORDS.has(prev)) {
			if (!COMMON_SAFE_SUBPATHS.has(seg.toLowerCase())) {
				segments[i] = "[token]";
				continue;
			}
		}
		if (LONG_OPAQUE_RE.test(seg)) {
			segments[i] = "[token]";
			continue;
		}
	}
	return segments.join("/");
}
var SENSITIVE_PARAM_WORD_TOKENS = /* @__PURE__ */ new Set([
	"token",
	"tokens",
	"secret",
	"secrets",
	"key",
	"keys",
	"apikey",
	"apikeys",
	"auth",
	"oauth",
	"passwd",
	"password",
	"passwords",
	"pwd",
	"pass",
	"passphrase",
	"credential",
	"credentials",
	"session",
	"signature"
]);
var SENSITIVE_PARAM_PATTERN = /^(?:api|secret|access|app|client|user|auth|private)?(?:key|token|secret|password|pwd)$/i;
var SENSITIVE_TOKEN_SUFFIX_PATTERN = /^(?:access|refresh|id|csrf|xsrf|session)?token$/i;
var SENSITIVE_PASS_PATTERN = /^(?:pass(word|wd)?|pwd)$/i;
/**
* Checks whether a query parameter name represents sensitive credential data
* (API keys, secrets, tokens, passwords, sessions) while avoiding false positives
* on harmless names like keyword, author, passenger, compass, or bypass.
*/
function isSensitiveParamName(name) {
	const lower = name.toLowerCase();
	if (SENSITIVE_PARAM_NAMES.has(lower)) return true;
	const tokens = name.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/);
	for (const t of tokens) if (SENSITIVE_PARAM_WORD_TOKENS.has(t)) return true;
	if (SENSITIVE_PARAM_PATTERN.test(lower) || SENSITIVE_TOKEN_SUFFIX_PATTERN.test(lower) || SENSITIVE_PASS_PATTERN.test(lower)) return true;
	return false;
}
/**
* Redacts common sensitive query parameters and sensitive URL path tokens
* to prevent credentials, API keys, and session tokens from being persisted in storage or displayed in the UI.
*/
function redactUrlQueryParams(rawUrl) {
	try {
		const url = new URL(rawUrl);
		url.pathname = redactUrlPath(url.pathname);
		for (const key of Array.from(url.searchParams.keys())) if (isSensitiveParamName(key)) url.searchParams.set(key, "[redacted]");
		return url.href;
	} catch {
		return rawUrl;
	}
}
//#endregion
//#region src/rules/headers/subdomain-trust.ts
var REF_SUBDOMAIN = "https://portswigger.net/web-security/host-header/exploiting#password-reset-poisoning-via-dangling-markup";
var REF_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS";
var REF_COOKIE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value";
var REF_COOKIE_TOSS = "https://datatracker.ietf.org/doc/html/rfc6265#section-8.6";
var REF_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy";
var REF_COOP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy";
var REF_OAC = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster";
var TWO_PART_TLDS = /* @__PURE__ */ new Set([
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
/**
* Derive the eTLD+1 (registrable domain) from a hostname.
* Handles both standard TLDs (example.com) and two-part eTLDs (example.co.uk).
* Returns null for IP addresses and localhost.
*/
function registrableDomain(hostname) {
	if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname === "localhost") return null;
	const parts = hostname.toLowerCase().split(".");
	if (parts.length < 2) return null;
	if (parts.length >= 3) {
		const lastTwo = parts.slice(-2).join(".");
		if (TWO_PART_TLDS.has(lastTwo) || /^[a-z0-9\-]+\.(co|com|net|org|gov|edu|ac|gob)\.[a-z]{2}$/.test(parts.slice(-3).join("."))) return parts.slice(-3).join(".");
	}
	return parts.slice(-2).join(".");
}
/**
* Returns true when `hostname` is a true subdomain of its registrable domain
* (ignoring the standard 'www' prefix which acts as the apex site).
*/
function isSubdomain(hostname) {
	const reg = registrableDomain(hostname);
	if (reg == null || hostname === reg) return false;
	if (hostname === `www.${reg}`) return false;
	return hostname.length > reg.length + 1 && hostname.endsWith(`.${reg}`);
}
/**
* Split a CSP source-list on whitespace, return tokens.
*/
function cspTokens(src) {
	return src.split(/\s+/).filter((t) => t.length > 0);
}
/**
* Returns true when a CSP source-list token allows script execution from
* an arbitrary subdomain of `registrable` (eTLD+1).
*/
function cspAllowsSubdomain(sourceList, registrable) {
	for (const token of cspTokens(sourceList)) {
		const bare = token.replace(/^https?:\/\//, "");
		if (bare === `*.${registrable}` || bare === registrable) return true;
		if (bare.endsWith(`.${registrable}`) && !bare.startsWith("*")) return true;
	}
	return false;
}
/**
* Resolve effective source-list for `directive`, falling back to default-src.
*/
function resolveEffective(directives, directive) {
	return directives.get(directive) ?? directives.get("default-src");
}
/**
* Analyse the final hop's headers + cookies for subdomain→main-domain
* escalation paths.
*
* @param finalHop - The authoritative response hop.
* @param cookies  - Cookie metadata for the page.
*/
function checkSubdomainTrust(finalHop, cookies, alwaysSensitive = [], alwaysIgnore = []) {
	const findings = [];
	const vectors = [];
	let hostname = "";
	try {
		hostname = new URL(finalHop.url).hostname;
	} catch {
		return {
			findings,
			hasEscalationPath: false,
			vectors
		};
	}
	const regDomain = registrableDomain(hostname);
	if (regDomain == null) return {
		findings,
		hasEscalationPath: false,
		vectors
	};
	const pageIsSubdomain = isSubdomain(hostname);
	const cspValue = finalHop.headers["content-security-policy"] ?? "";
	const corsOrigin = finalHop.headers["access-control-allow-origin"] ?? "";
	const corsCredsRaw = finalHop.headers["access-control-allow-credentials"] ?? "";
	const varyHeader = finalHop.headers["vary"] ?? "";
	const coopHeader = finalHop.headers["cross-origin-opener-policy"] ?? "";
	const oacHeader = finalHop.headers["origin-agent-cluster"] ?? "";
	const xfo = finalHop.headers["x-frame-options"] ?? "";
	const directives = cspValue.length > 0 ? parseCspDirectives(cspValue) : /* @__PURE__ */ new Map();
	const effectiveScriptSrc = resolveEffective(directives, "script-src");
	const frameAncestors = directives.get("frame-ancestors") ?? "";
	let hasEscalationPath = false;
	const broadCookies = [];
	for (const cookie of cookies) {
		const d = cookie.domain;
		if ((d.startsWith(".") ? d.slice(1) : d) === regDomain || d === `.${regDomain}`) {
			if (isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore).isSensitive || cookie.httpOnly && cookie.session) broadCookies.push(cookie.name);
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
	if (cookieTrustPresent) findings.push({
		ruleId: "SUB-001",
		category: "cookie",
		severity: "critical",
		title: `Sensitive cookie(s) scoped to .${regDomain} — subdomain compromise exposes main-domain session`,
		impact: `An attacker who compromises any subdomain on ${regDomain} can access these session cookies and impersonate users on the apex domain.`,
		evidence: sanitizeEvidence(`Domain-wide sensitive cookies: ${broadCookies.slice(0, 5).join(", ")}`),
		recommendation: "Set authentication and session cookies without the Domain attribute (host-only) or restrict to Domain=<specific-subdomain>. Avoid Domain=.example.com for session/auth cookies.",
		reference: REF_COOKIE
	});
	const unshieldedSensitiveCookies = [];
	for (const cookie of cookies) if (isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore).isSensitive && !cookie.name.startsWith("__Host-")) unshieldedSensitiveCookies.push(cookie.name);
	const cookieTossingRisk = unshieldedSensitiveCookies.length > 0;
	if (cookieTossingRisk) hasEscalationPath = true;
	vectors.push({
		id: "SUB-005",
		label: "Cookie Tossing / Shadowing Risk (Missing __Host- prefix)",
		detail: cookieTossingRisk ? `Sensitive cookie(s) lack __Host- prefix: ${unshieldedSensitiveCookies.slice(0, 3).join(", ")}. A compromised subdomain can inject Domain=.${regDomain} cookies to hijack sessions.` : "All sensitive cookies use __Host- prefix or none detected",
		risk: "medium",
		present: cookieTossingRisk
	});
	if (cookieTossingRisk) findings.push({
		ruleId: "SUB-005",
		category: "cookie",
		severity: "medium",
		title: `Sensitive session cookie(s) lack __Host- prefix — vulnerable to Cookie Tossing from subdomains`,
		impact: `An attacker controlling any subdomain can overwrite or shadow main-domain session cookies by setting Domain=.${regDomain} cookies (Cookie Tossing).`,
		evidence: sanitizeEvidence(`Unprefixed sensitive cookies: ${unshieldedSensitiveCookies.slice(0, 5).join(", ")}`),
		recommendation: "Prefix sensitive session cookies with __Host- (e.g. __Host-session=...) so browsers reject subdomains attempting to shadow or overwrite cookies for the main domain (RFC 6265bis §4.1.3).",
		reference: REF_COOKIE_TOSS
	});
	let cspSubdomainTrust = false;
	let cspEvidence = "";
	if (effectiveScriptSrc !== void 0) {
		const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);
		if (!isModernStrict) {
			const dangerous = cspTokens(effectiveScriptSrc).filter((t) => {
				const bare = t.replace(/^https?:\/\//, "");
				return bare === `*.${regDomain}` || bare === regDomain;
			});
			if (dangerous.length > 0) {
				cspSubdomainTrust = true;
				hasEscalationPath = true;
				cspEvidence = dangerous.join(" ");
			}
		}
	}
	const subdomainTrustDetail = effectiveScriptSrc != null ? `script-src is scoped to explicit hosts (no wildcard subdomain trust for ${regDomain})` : cspValue.length > 0 ? "CSP present but script-src not found" : "No CSP response header; explicit subdomain script trust is not evaluated here";
	vectors.push({
		id: "SUB-002",
		label: "CSP trusts scripts from subdomains",
		detail: cspSubdomainTrust ? `Subdomain script source(s): ${cspEvidence}` : subdomainTrustDetail,
		risk: "critical",
		present: cspSubdomainTrust
	});
	if (cspSubdomainTrust && cspEvidence) findings.push({
		ruleId: "SUB-002",
		category: "header",
		severity: "critical",
		title: `CSP script-src trusts wildcard *.${regDomain} — allows XSS pivot from any ${regDomain} subdomain`,
		impact: `An attacker who finds an XSS bug or hosts files on any ${regDomain} subdomain can execute scripts with full permissions on the main domain.`,
		evidence: sanitizeEvidence(cspEvidence),
		recommendation: `Replace wildcard subdomain source (*.${regDomain}) with explicit allowlisted hostnames or nonces/hashes.`,
		reference: REF_CSP
	});
	let corsTrustPresent = false;
	let corsDetail = "";
	const corsWithCreds = corsCredsRaw?.toLowerCase().trim() === "true";
	if (corsOrigin.length > 0) {
		if (corsOrigin === "*") {
			corsTrustPresent = true;
			corsDetail = "Access-Control-Allow-Origin: *";
			if (corsWithCreds) corsDetail += " + Credentials: true (critical misconfiguration)";
		} else try {
			const allowedHostname = new URL(corsOrigin).hostname;
			if (registrableDomain(allowedHostname) === regDomain && allowedHostname !== hostname) {
				corsTrustPresent = true;
				corsDetail = `Access-Control-Allow-Origin: ${corsOrigin} (trusts subdomain of same root)`;
				if (corsWithCreds) corsDetail += "; Access-Control-Allow-Credentials: true";
			}
		} catch {}
	} else if (varyHeader.toLowerCase().includes("origin")) {
		corsTrustPresent = true;
		corsDetail = "Vary: Origin present with no Access-Control-Allow-Origin header — possible dynamic reflection (heuristic)";
	}
	if (corsTrustPresent) hasEscalationPath = true;
	const varyOnlyHeuristic = corsTrustPresent && corsOrigin.length === 0;
	vectors.push({
		id: varyOnlyHeuristic ? "SUB-003H" : "SUB-003",
		label: varyOnlyHeuristic ? "CORS Vary: Origin heuristic" : "CORS allows subdomain / wildcard origins",
		detail: corsTrustPresent ? corsDetail : corsOrigin.length > 0 ? `Access-Control-Allow-Origin: ${corsOrigin.slice(0, 80)} (no cross-subdomain trust detected)` : "No CORS header present",
		risk: varyOnlyHeuristic ? "medium" : "high",
		present: corsTrustPresent
	});
	if (corsTrustPresent) findings.push({
		ruleId: varyOnlyHeuristic ? "SUB-003H" : "SUB-003",
		category: "cors",
		severity: varyOnlyHeuristic ? "medium" : "high",
		confidence: varyOnlyHeuristic ? "heuristic" : "deterministic",
		title: varyOnlyHeuristic ? "Vary: Origin with no explicit CORS policy — possible dynamic origin reflection (heuristic)" : "CORS policy trusts subdomain origin — cross-subdomain API data exposure possible",
		impact: "Compromised or attacker-controlled subdomains can send authenticated AJAX requests to your private APIs and read sensitive user data across origins.",
		evidence: sanitizeEvidence(corsDetail),
		recommendation: "Set Access-Control-Allow-Origin to an explicit allowlist of known origins. Never reflect the Origin request header without strict validation.",
		reference: REF_CORS
	});
	let postMsgTrustPresent = false;
	let postMsgDetail = "";
	if (xfo.length === 0 && frameAncestors.length > 0 && (frameAncestors.includes("*") || cspAllowsSubdomain(frameAncestors, regDomain))) {
		postMsgTrustPresent = true;
		postMsgDetail = `Explicit subdomain framing trust: ${frameAncestors.slice(0, 80)}`;
		hasEscalationPath = true;
	}
	vectors.push({
		id: "SUB-004",
		label: "postMessage / framing trust open to subdomains",
		detail: postMsgTrustPresent ? postMsgDetail : frameAncestors.length > 0 || xfo.length > 0 ? `Framing is restricted (${frameAncestors.length > 0 ? "frame-ancestors" : "X-Frame-Options"} present)` : "No framing policy detected; covered by CSP-005 and XFO-001",
		risk: "high",
		present: postMsgTrustPresent
	});
	if (postMsgTrustPresent) findings.push({
		ruleId: "SUB-004",
		category: "header",
		severity: "high",
		title: "Page can be framed by subdomains — postMessage confusion / clickjacking pivot possible",
		impact: "Subdomains can embed this page in an iframe to sniff postMessage data or perform clickjacking attacks on authenticated actions.",
		evidence: sanitizeEvidence(postMsgDetail),
		recommendation: "Add \"Content-Security-Policy: frame-ancestors 'self'\" or \"X-Frame-Options: SAMEORIGIN\" to prevent untrusted subdomains from embedding this page.",
		reference: REF_CSP
	});
	const coopMissing = coopHeader.length === 0 || !coopHeader.toLowerCase().includes("same-origin");
	if (coopMissing) hasEscalationPath = true;
	vectors.push({
		id: "SUB-006",
		label: "Cross-Origin-Opener-Policy (COOP) missing",
		detail: coopMissing ? coopHeader.length > 0 ? `COOP: ${coopHeader} (not same-origin)` : "COOP header absent — subdomains can manipulate window.opener" : `COOP is strict (${coopHeader})`,
		risk: "medium",
		present: coopMissing
	});
	if (coopMissing) findings.push({
		ruleId: "SUB-006",
		category: "header",
		severity: "medium",
		title: "Missing Cross-Origin-Opener-Policy (COOP) — subdomains can access window.opener",
		impact: "Untrusted subdomains opened in new tabs or windows can access window.opener and silently redirect the parent tab to a phishing clone (Reverse Tabnabbing).",
		evidence: sanitizeEvidence(coopHeader.length > 0 ? coopHeader : "(header absent)"),
		recommendation: "Set \"Cross-Origin-Opener-Policy: same-origin\" to isolate the top-level browsing context and prevent malicious subdomains from manipulating window.opener.",
		reference: REF_COOP
	});
	const oacMissing = oacHeader.length === 0 || !oacHeader.includes("?1");
	vectors.push({
		id: "SUB-007",
		label: "Origin-Agent-Cluster missing (document.domain relaxation risk)",
		detail: oacMissing ? "Origin-Agent-Cluster: ?1 missing — legacy document.domain relaxation can bridge subdomains" : "Origin-Agent-Cluster: ?1 is active",
		risk: "low",
		present: oacMissing
	});
	if (oacMissing) findings.push({
		ruleId: "SUB-007",
		category: "header",
		severity: "low",
		title: "Missing Origin-Agent-Cluster header — document.domain relaxation possible",
		impact: "Subdomains can alter document.domain to match the main domain, breaking Same-Origin-Policy boundaries and reading DOM content directly.",
		evidence: sanitizeEvidence(oacHeader.length > 0 ? oacHeader : "(header absent)"),
		recommendation: "Add \"Origin-Agent-Cluster: ?1\" to prevent document.domain relaxation and enforce origin isolation.",
		reference: REF_OAC
	});
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
			evidence: sanitizeEvidence(`${hostname} is isolated from ${regDomain}`),
			recommendation: "No action required. Vulnerabilities on this subdomain remain isolated and cannot jump to the main domain based on current security controls.",
			reference: REF_SUBDOMAIN
		});
	}
	return {
		findings,
		hasEscalationPath,
		vectors
	};
}
//#endregion
export { hasCspBypassProtection as a, normalizeHeaders as c, redactUrlPath as d, redactUrlQueryParams as f, extractSetCookieHeaders as i, originFromUrl as l, registrableDomain as n, headersDiffer as o, sanitizeEvidence as p, checkDuplicateHeaders as r, isSensitiveCookie as s, checkSubdomainTrust as t, parseCspDirectives as u };

//# sourceMappingURL=subdomain-trust-DrWlzpgv.js.map