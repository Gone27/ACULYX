# Contributing to ACULYX

Thank you for your interest in contributing to ACULYX! We welcome contributions that align with our core principles: local-first privacy, fail-closed security, and zero telemetry.

---

## Development Workflow

### 1. Prerequisites
- **Node.js**: `^22.12.0 || >=24.0.0`
- **npm**: `npm ci` is recommended for clean, lockfile-reproducible dependency installation.

### 2. Available Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Starts Vite development server with Hot Module Replacement |
| `npm run build` | Builds Chrome MV3 extension into `dist/` |
| `npm run build:firefox` | Builds Firefox MV3 extension into `dist-firefox/` |
| `npm run build:hunter` | Builds Hunter Edition into `dist-hunter/` |
| `npm run build:all` | Builds all 3 extension distributions in a single coordinated run |
| `npm run typecheck` | Validates TypeScript types (`tsc --noEmit`) |
| `npm run lint` | Runs ESLint across `src/` and `tests/` (enforces zero warnings) |
| `npm test` | Executes full Vitest unit, scope, fuzz, and integration suites |
| `npm run test:artifacts` | Validates compiled syntax and effective manifest security bounds |
| `npm run test:e2e` | Runs Playwright Chromium end-to-end browser runtime tests (Firefox covered via build & package verification) |
| `npm run pack` | Packages all 4 release ZIP archives into dedicated output directories |
| `npm run verify:pack` | Validates RFC 1951 entry paths, manifest invariants, and smoke extractions |

---

## Quality Gate Standards

All pull requests must pass every automated gate before merging:

1. **TypeScript Compilation**: Zero compiler errors with `strict` enabled (`npm run typecheck`).
2. **ESLint**: Zero errors and zero warnings (`npm run lint`).
3. **Automated Testing**: 100% pass rate across Vitest and Playwright suites (`npm test`, `npm run test:artifacts`, `npm run test:e2e`).
4. **Dependency Audit**: Zero vulnerabilities across all severities (`npm audit --audit-level=low`).
5. **Release Integrity**: All 4 release archives package and verify cleanly (`npm run pack`, `npm run verify:pack`).
6. **Privacy Invariants**:
   - Never log, store, or transmit cookie values or authorization credentials (`cookie.value` is ignored).
   - Ensure query parameters and URL fragments are stripped before storage.
   - Outbound network requests are forbidden except for explicit CLI flags or the optional, user-confirmed credential check.
7. **No Synthetic Secret Leaks**: Test tokens must use safe synthetic mocks that do not trigger secret scanning protections.

---

## Responsible Disclosure

If your contribution relates to a security vulnerability or sensitive discovery, please review our [Security Policy](SECURITY.md) and report it privately via our verified security email or GitHub Private Advisories (when enabled).
