/**
 * Hostname and Port Normalization for ACULYX Scope Engine.
 *
 * Implements:
 * - IDNA punycode normalization via WHATWG URL parsing
 * - Lowercase normalization
 * - Trailing dot removal
 * - Scheme extraction & preservation
 * - Explicit port preservation (never silently discarded, even for standard ports 80/443)
 * - Wildcard prefix detection (*.domain.com -> hostname: 'domain.com', isWildcard: true)
 */

import type { NormalizedScopeTarget } from './contracts';

/**
 * Normalizes a hostname:
 * - Strips trailing dots
 * - Converts to lowercase
 * - Converts IDNA international domain names to ASCII punycode
 */
export function normalizeHostname(rawHost: string): string {
  let cleaned = rawHost.trim().toLowerCase();
  while (cleaned.endsWith('.')) {
    cleaned = cleaned.slice(0, -1);
  }

  if (cleaned.length === 0) {
    throw new Error('Hostname cannot be empty');
  }

  // IPv6 bracketed address
  if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    return cleaned;
  }

  // Use WHATWG URL host parser to perform UTS #46 / IDNA punycode conversion
  try {
    const u = new URL(`http://${cleaned}`);
    return u.hostname;
  } catch {
    return cleaned;
  }
}

/**
 * Extracts the explicit port from a host or URL string if present.
 * Returns undefined if no explicit port is specified.
 * Throws an Error if an invalid or out-of-range port is specified.
 */
export function extractExplicitPort(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;

  // Find the authority part (strip scheme and path/query/fragment)
  let rest = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  const pathIdx = rest.search(/[\/?#]/);
  if (pathIdx !== -1) {
    rest = rest.slice(0, pathIdx);
  }

  // Strip userinfo if present
  const atIdx = rest.lastIndexOf('@');
  if (atIdx !== -1) {
    rest = rest.slice(atIdx + 1);
  }

  // Check IPv6
  if (rest.startsWith('[')) {
    const closeBracket = rest.indexOf(']');
    if (closeBracket === -1) {
      throw new Error(`Malformed IPv6 host: ${rest}`);
    }
    const afterBracket = rest.slice(closeBracket + 1);
    if (afterBracket.startsWith(':')) {
      const portStr = afterBracket.slice(1);
      const port = Number(portStr);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid port number: ${portStr}`);
      }
      return port;
    }
    return undefined;
  }

  // Standard host:port
  const colonIdx = rest.lastIndexOf(':');
  if (colonIdx !== -1) {
    const portStr = rest.slice(colonIdx + 1);
    const port = Number(portStr);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid port number: ${portStr}`);
    }
    return port;
  }

  return undefined;
}

/**
 * Extracts and normalizes the scheme (e.g. 'https', 'http') from a URL string.
 * Returns undefined if no scheme is specified.
 */
export function parseScheme(raw: string): string | undefined {
  const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.exec(raw.trim());
  if (match && match[0]) {
    return match[0].replace(/:\/\/$/, '').toLowerCase();
  }
  return undefined;
}

/**
 * Normalizes a scope target (URL, host pattern, or wildcard pattern)
 * into a NormalizedScopeTarget structure.
 */
export function normalizeScopeTarget(raw: string): NormalizedScopeTarget {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new Error('Scope target must be a non-empty string');
  }

  const trimmed = raw.trim();
  const scheme = parseScheme(trimmed);

  // Extract authority portion
  let authority = trimmed;
  if (scheme !== undefined) {
    authority = authority.slice(scheme.length + 3);
  }

  // Remove path, query string, and hash fragment
  const pathIdx = authority.search(/[\/?#]/);
  if (pathIdx !== -1) {
    authority = authority.slice(0, pathIdx);
  }

  // Remove userinfo (username:password@)
  const atIdx = authority.lastIndexOf('@');
  if (atIdx !== -1) {
    authority = authority.slice(atIdx + 1);
  }

  // Check for wildcard prefix
  let isWildcard = false;
  let hostAndPort = authority;
  if (hostAndPort.startsWith('*.')) {
    isWildcard = true;
    hostAndPort = hostAndPort.slice(2);
  } else if (hostAndPort.startsWith('*')) {
    isWildcard = true;
    hostAndPort = hostAndPort.slice(1);
    if (hostAndPort.startsWith('.')) {
      hostAndPort = hostAndPort.slice(1);
    }
  }

  // Extract explicit port
  let port: number | undefined;
  let rawHost = hostAndPort;

  if (hostAndPort.startsWith('[')) {
    const closeBracket = hostAndPort.indexOf(']');
    if (closeBracket === -1) {
      throw new Error(`Malformed IPv6 host: ${hostAndPort}`);
    }
    rawHost = hostAndPort.slice(0, closeBracket + 1);
    const afterBracket = hostAndPort.slice(closeBracket + 1);
    if (afterBracket.startsWith(':')) {
      const portStr = afterBracket.slice(1);
      const parsedPort = Number(portStr);
      if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        throw new Error(`Invalid port number: ${portStr}`);
      }
      port = parsedPort;
    }
  } else {
    const colonIdx = hostAndPort.lastIndexOf(':');
    if (colonIdx !== -1) {
      rawHost = hostAndPort.slice(0, colonIdx);
      const portStr = hostAndPort.slice(colonIdx + 1);
      const parsedPort = Number(portStr);
      if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        throw new Error(`Invalid port number: ${portStr}`);
      }
      port = parsedPort;
    }
  }

  const hostname = normalizeHostname(rawHost);

  return {
    raw,
    ...(scheme !== undefined ? { scheme } : {}),
    hostname,
    ...(port !== undefined ? { port } : {}),
    isWildcard,
  };
}
