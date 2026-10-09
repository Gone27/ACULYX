//#region src/shared/scope/normalize.ts
/**
* Normalizes a hostname:
* - Strips trailing dots
* - Converts to lowercase
* - Converts IDNA international domain names to ASCII punycode
*/
function normalizeHostname(rawHost) {
	let cleaned = rawHost.trim().toLowerCase();
	while (cleaned.endsWith(".")) cleaned = cleaned.slice(0, -1);
	if (cleaned.length === 0) throw new Error("Hostname cannot be empty");
	if (cleaned.startsWith("[") && cleaned.endsWith("]")) return cleaned;
	try {
		return new URL(`http://${cleaned}`).hostname;
	} catch {
		return cleaned;
	}
}
/**
* Extracts and normalizes the scheme (e.g. 'https', 'http') from a URL string.
* Returns undefined if no scheme is specified.
*/
function parseScheme(raw) {
	const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.exec(raw.trim());
	if (match && match[0]) return match[0].replace(/:\/\/$/, "").toLowerCase();
}
/**
* Normalizes a scope target (URL, host pattern, or wildcard pattern)
* into a NormalizedScopeTarget structure.
*/
function normalizeScopeTarget(raw) {
	if (typeof raw !== "string" || raw.trim().length === 0) throw new Error("Scope target must be a non-empty string");
	const trimmed = raw.trim();
	const scheme = parseScheme(trimmed);
	let authority = trimmed;
	if (scheme !== void 0) authority = authority.slice(scheme.length + 3);
	const pathIdx = authority.search(/[\/?#]/);
	if (pathIdx !== -1) authority = authority.slice(0, pathIdx);
	const atIdx = authority.lastIndexOf("@");
	if (atIdx !== -1) authority = authority.slice(atIdx + 1);
	let isWildcard = false;
	let hostAndPort = authority;
	if (hostAndPort.startsWith("*.")) {
		isWildcard = true;
		hostAndPort = hostAndPort.slice(2);
		if (hostAndPort.includes("*")) throw new Error(`Invalid wildcard pattern: wildcards cannot contain interior "*" characters. Found: "${raw}"`);
	} else if (hostAndPort.includes("*")) throw new Error(`Invalid wildcard pattern: wildcards must use the explicit "*." prefix (e.g. "*.example.com"). Found: "${raw}"`);
	let port;
	let rawHost = hostAndPort;
	if (hostAndPort.startsWith("[")) {
		const closeBracket = hostAndPort.indexOf("]");
		if (closeBracket === -1) throw new Error(`Malformed IPv6 host: ${hostAndPort}`);
		rawHost = hostAndPort.slice(0, closeBracket + 1);
		const afterBracket = hostAndPort.slice(closeBracket + 1);
		if (afterBracket.startsWith(":")) {
			const portStr = afterBracket.slice(1);
			const parsedPort = Number(portStr);
			if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) throw new Error(`Invalid port number: ${portStr}`);
			port = parsedPort;
		}
	} else {
		const colonIdx = hostAndPort.lastIndexOf(":");
		if (colonIdx !== -1) {
			rawHost = hostAndPort.slice(0, colonIdx);
			const portStr = hostAndPort.slice(colonIdx + 1);
			const parsedPort = Number(portStr);
			if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) throw new Error(`Invalid port number: ${portStr}`);
			port = parsedPort;
		}
	}
	const hostname = normalizeHostname(rawHost);
	return {
		raw,
		...scheme !== void 0 ? { scheme } : {},
		hostname,
		...port !== void 0 ? { port } : {},
		isWildcard
	};
}
//#endregion
export { normalizeScopeTarget as t };

//# sourceMappingURL=normalize-BcYjnt_z.js.map