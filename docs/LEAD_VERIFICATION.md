# Lead Self-Check (Verdicts) & Active Verification Architecture

Every lead now carries an objective `verdict` separating technical observation, scope authority, and vulnerability viability:

| Verdict Field | Values | Meaning |
|---|---|---|
| `status` | `confirmed` \| `likely` \| `uncertain` \| `informational` \| `false_positive` | Operational composite status. |
| `evidenceStatus` | `observed` \| `reproduced` \| `inconclusive` | Objective observation status from passive analysis or active probing. |
| `scopeStatus` | `in-scope` \| `out-of-scope` \| `unknown` | Authority boundary check against declared targets. |
| `securityAssessment` | `unreviewed` \| `likely` \| `confirmed` \| `informational` \| `false_positive` | Researcher risk viability assessment. |

## Verification Stages

### 1. Passive Verification (Automatic, Zero Traffic)
Implemented in `src/leads/verify/passive.ts`.
- Runs automatically when evaluating leads in `getLeadsState`.
- Incorporates rule evidence tiers, missing prerequisites (`needs`), and source sensor trust.
- **Untrusted Main-World Signals**: Page-reported events (e.g., from `dom-collector.ts` or main-world hooks) are treated as untrusted hypotheses and can **never** be passively confirmed.
- **Scope Authority Separation**: Leads on `unknown` or `out-of-scope` targets retain missing scope validation items and can **never** be marked as confirmed vulnerabilities (status capped at `likely`/`uncertain` and assessment remains `unreviewed`).
- **Cryptographic & Format Calibrations**: Checksum validation confirms format and arithmetic structure matching documented vendor specifications, not vendor issuance or key liveness.
- **Safeguard on Token Expiry**: Decoded JWT claims (e.g., `exp`) are recorded as unverified detection-time facts; expired claims do **not** trigger a `false_positive` veto because keys may remain valid across endpoints or services.

### 2. Active Verification (Strictly Opt-In, Hunter-Gated)
Implemented in `src/leads/verify/active.ts` and triggered by user action in the Sidepanel UI:
- **Preconditions**:
  1. Target is strictly within user's declared `in-scope` rules.
  2. Hunter mode is actively enabled.
  3. Interactive user confirmation via explicit disclosure modal.
  4. Global rate limits and safety guards active.
- **Request Guarantees**:
  - `credentials: 'omit'` (no cookies, ambient credentials, or Authorization headers).
  - `redirect: 'manual'` (HTTP redirects are never followed).
  - Bounded memory read (`readBodyCapped`, default 128 KB max) with streaming abort.
- **Supported Capabilities**:
  - **Source Map (`MAP-001`)**: 1 read-only GET inspecting `application/json` content-type, version 3 schema, and `sources` array. HTML fallback responses and 404s are flagged as false positives. HTTP 401/403 responses return `uncertain` (auth-protected; not retrieved).
  - **Cloud Bucket (`CLD-001`)**: 1 read-only GET with `?max-keys=0` against AWS/GCP bucket endpoints. Anonymous XML directory listing confirms public exposure. Crucially, HTTP 401/403 `AccessDenied` returns `informational` (inconclusive directory check, never false positive), as individual object keys may still permit read access.
  - **CORS Reflection (`COR-001`)**: Up to 4 read-only GET requests testing distinct origins (`null`, `https://evil.tld`, `https://${targetHost}.evil.tld`, `https://evil${targetHost}`). Only flagged when both `Access-Control-Allow-Origin` reflects the untrusted origin and `Access-Control-Allow-Credentials: true`. Full probe plan and all 4 origins are transparently disclosed to user before execution.

## Adding a New Verifier
1. **Passive**: Add rule branch or condition check in `src/leads/verify/passive.ts`.
2. **Active**: Add pure interpreter `interpretXxx(outcome)` + probe planning in `planActiveProbe(lead)` in `src/leads/verify/active.ts`.
3. **Tests**: Add unit test coverage in `tests/leads/verify.test.ts` for all outcomes and planning cases.
