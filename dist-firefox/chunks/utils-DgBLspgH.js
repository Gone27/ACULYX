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
* Redact the secret cookie value from a Set-Cookie header string,
* preserving the cookie name and all attributes (Path, Domain, SameSite, Secure, HttpOnly, etc.).
* e.g. "session=V2_CANARY; Path=/; Secure; HttpOnly" -> "session=[REDACTED]; Path=/; Secure; HttpOnly"
*/
function redactSetCookieHeader(headerValue) {
	if (!headerValue) return headerValue;
	const eqIdx = headerValue.indexOf("=");
	const semiIdx = headerValue.indexOf(";");
	if (eqIdx !== -1 && (semiIdx === -1 || eqIdx < semiIdx)) return `${headerValue.slice(0, eqIdx).trim()}=[REDACTED]${semiIdx !== -1 ? headerValue.slice(semiIdx) : ""}`;
	if (semiIdx !== -1) return `${headerValue.slice(0, semiIdx).trim()}=[REDACTED]${headerValue.slice(semiIdx)}`;
	return `${headerValue.trim()}=[REDACTED]`;
}
/**
* Redact secret cookie values from a Cookie request header string.
* e.g. "a=secret1; b=secret2" -> "a=[REDACTED]; b=[REDACTED]"
*/
function redactCookieHeader(headerValue) {
	if (!headerValue) return headerValue;
	return headerValue.split(";").map((part) => {
		const trimmed = part.trim();
		const eqIdx = trimmed.indexOf("=");
		if (eqIdx !== -1) return `${trimmed.slice(0, eqIdx).trim()}=[REDACTED]`;
		return trimmed ? `${trimmed}=[REDACTED]` : "";
	}).filter((s) => s.length > 0).join("; ");
}
/**
* Redact sensitive header values (Set-Cookie, Cookie, Authorization, Proxy-Authorization).
*/
function redactHeaderValue(name, value) {
	const lower = name.toLowerCase();
	if (lower === "set-cookie") return redactSetCookieHeader(value);
	if (lower === "cookie") return redactCookieHeader(value);
	if (lower === "authorization" || lower === "proxy-authorization") return "[REDACTED]";
	return value;
}
/**
* Build a lowercase-keyed header map from the raw WebRequest header array.
* Sensitive values (Set-Cookie, Cookie, Authorization) are automatically redacted.
* For most headers last-value-wins.
*/
function normalizeHeaders(raw) {
	const map = {};
	for (const { name, value } of raw) if (value != null) map[name.toLowerCase()] = redactHeaderValue(name, value);
	return map;
}
/**
* Collect every Set-Cookie header value as a raw string array with values redacted.
* The webRequest API may present them as a single joined header or
* as multiple entries depending on Chrome version.
*/
function extractSetCookieHeaders(raw) {
	return raw.filter((h) => h.name.toLowerCase() === "set-cookie" && h.value != null).map((h) => redactSetCookieHeader(h.value));
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
export { isSensitiveCookie as a, parseCspDirectives as c, redactUrlQueryParams as d, sanitizeEvidence as f, headersDiffer as i, redactHeaderValue as l, extractSetCookieHeaders as n, normalizeHeaders as o, hasCspBypassProtection as r, originFromUrl as s, checkDuplicateHeaders as t, redactUrlPath as u };

//# sourceMappingURL=utils-DgBLspgH.js.map