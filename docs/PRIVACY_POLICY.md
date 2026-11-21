# Privacy Policy for ACULYX: Header & Cookie Security Checker

**Effective Date:** September 25, 2026
**Last Updated:** October 24, 2026
**Author & Maintainer:** Dhyan Patel

## 1. Overview & Core Philosophy
ACULYX was engineered from the ground up on a strict **zero-telemetry, zero-exfiltration** privacy architecture. We believe security auditing tools should never compromise the privacy of the person using them.

All security analysis and evaluation is executed **100% locally inside your web browser**.

---

## 2. Information We Do NOT Collect
- **Zero Remote Telemetry:** ACULYX does not have external tracking servers, analytics endpoints, or cloud backends. Extension pages enforce a strict `connect-src` that allows only the extension itself and, for the optional credential liveness check (section 5.1), three vendor APIs. Content scripts make zero network requests and communicate solely through local extension runtime messaging.
- **Never Retains or Exfiltrates Cookie Values:** ACULYX inspects cookie metadata attributes (such as `Secure`, `HttpOnly`, `SameSite`, and prefix naming) for compliance. Cookie objects returned by browser APIs are accessed for metadata only (never `cookie.value`). Raw in-flight headers are automatically sanitized and query strings and fragments are stripped prior to storage.
- **No Personal Identifiers:** We do not collect names, email addresses, IP addresses, search queries, or browsing history.
- **Strict Incognito / Private Window Isolation:** Private and incognito browsing sessions are strictly isolated. Lead Radar findings, S1 query parameter harvesting, reconnaissance memory, and persistent history are never recorded or persisted for incognito tabs. All ephemeral session caches and in-memory triage annotations associated with incognito tabs are immediately wiped when tabs close.

---

## 3. Data Handled Locally on Your Device
When you choose to monitor an origin, ACULYX temporarily processes network headers and cookie attributes locally:
- **HTTP Response Headers:** Evaluated against security standards (HSTS, CSP, X-Content-Type-Options, CORS, etc.) for top-level navigations and in-page API (`xmlhttprequest`/`fetch`) calls on permitted origins.
- **API Endpoint Capture:** In-page API requests (`xmlhttprequest` and `fetch`) to first-party and permitted third-party endpoints are captured to evaluate CORS, MIME-sniffing, and security transport configurations. API endpoint states are strictly bounded (LRU capped at 50 per tab) in session storage. Query strings, auth tokens, and credential material in API URLs are automatically redacted before local display or storage.
- **Lead Radar & Recon Memory:** Discovered attack surface leads and parameters are stored in local session storage and bounded ReconStore (`chrome.storage.local`). Out-of-scope targets and unmonitored origins are strictly excluded from parameter harvesting and persistent recon memory. External scripts, iframes, and forms independently evaluate scope rather than inheriting page scope. All exported leads and hygiene reports undergo recursive canary and token redaction across all serialized fields.
- **Authentication Posture Diffs (Auth-Diff Storage):** When logging in or out of a monitored site, ACULYX detects transitions based on metadata changes (such as sensitive cookie issuance or rotation). It records a high-level posture comparison (`AuthDiffRecord`) in `chrome.storage.local` to track how security headers and grades evolved between unauthenticated and authenticated states.
- **Attack Surface Graph Persistence:** The extension analyzes permitted navigation hops, cookies, and API endpoints to map relationships between the apex domain and affiliated subdomains (`AttackSurfaceGraph`). Persisted graphs in `chrome.storage.local` are strictly bounded (maximum 100 nodes, 150 edges) and pruned during periodic maintenance sweeps.
- **Scope Profiles:** User-configured authorized bug-bounty targets and exclusion patterns are stored in `chrome.storage.local`. Scope rules define matching criteria (`*.example.com`, `host:port`) and are never shared or transmitted off-device.
- **Researcher Triage Notes & Review States:** Triage annotations (`unreviewed`, `needs-manual-verification`, `verified-by-researcher`, `not-reproducible`, `not-a-finding`) and researcher notes are stored in `chrome.storage.local`. Triage notes undergo automated token/cookie redaction and length capping (max 5,000 characters) before persistence. In incognito sessions, triage notes are held strictly in ephemeral in-memory storage and are never written to disk.
- **Evaluation Mode:** An optional user setting ("Evaluation Mode") unlocks exploration of the full accumulated multi-session attack surface graph. Evaluation mode operates entirely locally with no external licensing servers, payment gateways, or network telemetry.
- **Sensitive URL Redaction:** All URL query parameters (`?`) and fragments (`#`) are stripped before storage or export, eliminating inadvertent leaks of OAuth `state`, session tokens, or emails.
- **Local Storage (`chrome.storage.local` & `session`):**
  - User configuration settings (e.g. per-site allowlist, severity filters, evaluation mode).
  - Scope profiles and active bug-bounty target definitions.
  - Researcher triage review states and sanitized notes.
  - Historical domain scores and auth-diff records (pruned according to retention settings).
  - Attack surface graphs (bounded and pruned).
  - Tab state cached in session storage to survive service worker idle cycles.
- **Local Export:** When you click "Export JSON" or "Copy Report", the report is compiled locally in memory and provided directly to you. No external service is contacted.

---

## 4. Permissions Usage & Store Privacy Justifications
ACULYX operates under a strict principle of least privilege:
- **`webRequest`**: Passively reads HTTP response headers to evaluate transport security (HSTS, CSP, X-Frame-Options, CORS, Cache-Control). Does not read request/response bodies or modify network traffic.
- **`webNavigation`**: Detects document navigation completions, redirects, and client-side SPA transitions to recompute security grades for the active tab.
- **`cookies`**: Passively inspects cookie security attributes (`HttpOnly`, `Secure`, `SameSite`, `__Host-`, `__Secure-` prefixes). Cookie values are strictly never accessed, logged, stored, or transmitted (`cookie.value` is ignored).
- **`storage`**: Used exclusively to persist user preferences, scope profiles, researcher triage notes, and bounded score history entirely on the local device.
- **`tabs`**: Queries current tab URL and ID to display per-tab grades, update toolbar action badges, and cleanly free resources when tabs close.
- **`scripting`**: Injects client-side DOM inspection sensors (S2 DOM collector and S3 Main-World hook scripts) into user-monitored tabs to analyze DOM sinks and subresource integrity.
- **`alarms`**: Triggers periodic local cache pruning and data retention cleanup without running background threads.
- **`sidePanel`**: Used in Chromium to host the interactive Attack Surface Graph directly alongside your browser session.
- **`optional_permissions` (`<all_urls>`)**: Never requested upfront. Only requested upon explicit user consent per-site or when all-sites monitoring is deliberately activated.
- **`activeTab`**: Supports interactions with the currently selected tab upon user gesture.

---

## 4.1. Special Sensor Invariants (S1 & S3)
- **Policy-Gated Parameter Harvesting (S1)**: S1 parameter harvesting is strictly gated behind the active URL capture policy and defined bug-bounty scope. If monitoring is paused/off, an origin is not granted, or a host is out-of-scope or unknown, parameter harvesting is completely halted and no host/param data is recorded.
- **Reviewer Note on `eval` in `main-world-hooks.ts` (S3)**: The extension wraps `window.eval` in the page's MAIN execution world strictly as a passive taint-tracking sensor. It observes calls made by the web page to detect unvalidated string execution. ACULYX **never** generates, compiles, or executes dynamic code via `eval()`. The original function is invoked with unmodified arguments, and only a sanitized event type is relayed to the extension.

---

## 5. Third-Party Data Sharing & Outbound Boundaries
We do not sell, rent, monetize, or share your data with advertisers or third parties. There are no third-party tracking pixels, analytics SDKs, telemetry services, or advertising networks in ACULYX.

Data leaves your browser only in two specific, transparent, and user-initiated scenarios:

### 5.1 Optional credential liveness check (off by default)
ACULYX can optionally check whether a credential it found on a page is still accepted by its vendor. This feature is **disabled by default** (`credentialLivenessEnabled: false`) and does nothing until you turn it on and approve each check yourself.

- **What is sent:** one request to one fixed vendor endpoint (`https://api.github.com/user`, `https://api.stripe.com/v1/balance` or `https://slack.com/api/auth.test`), transmitting the candidate credential in the `Authorization` header directly to the vendor that issued it to determine validity and permissions. This is the only case where a credential leaves your browser, and it is transmitted exclusively to that issuing vendor.
- **When:** only after you (1) open the plan, (2) confirm the exact endpoint, (3) state that you are authorized to test this target under its program rules, and (4) grant the vendor host permission. The lead must be **in scope**. Unknown or out-of-scope leads are refused.
- **How:** one request per confirmation, no cookies, redirects not followed, no cache, no referrer, 5 second timeout, response read capped at 8 KiB.
- **What is kept:** the raw credential lives only in memory for at most 5 minutes and is used once. It is never written to storage, logs, reports or exports. Only the result ("accepted", "rejected", "not checked") and a masked identity are kept.
- **Your responsibility:** use a found credential only where the program's rules allow it. Many programs forbid it.

### 5.2 Standalone Developer CLI Outbound Audits (`--url`)
When developers or CI pipelines invoke the standalone ACULYX CLI (`npm run aculyx` / `src/cli.ts`) with the explicit `--url <destination>` parameter, the CLI executes an outbound HTTP/HTTPS request directly to that user-specified destination:
- **Purpose**: Fetches HTTP response headers (such as HSTS, Content-Security-Policy, X-Frame-Options, Cache-Control, and Set-Cookie attributes) to evaluate security posture from the terminal or generate SARIF reports.
- **SSRF & Address Filtering**: The CLI enforces fail-closed server-side request forgery (SSRF) protections. By default, it denies requests targeting private IP ranges (RFC 1918), link-local addresses, loopback hosts (`127.0.0.1`, `localhost`), and cloud instance metadata services (`169.254.169.254`), and pins DNS resolution to mitigate rebinding attacks.
- **Data Boundaries**: Responses and evaluation scores are processed strictly within the local CLI process. No audit data, scanned URLs, or findings are transmitted to external servers, cloud services, or telemetry endpoints.
- **Offline Inspection Alternative**: For air-gapped or zero-network environments, the CLI supports offline inspection (`--input <file.json|file.har>`) which performs no outbound network requests whatsoever.

---

## 6. Open Source Verification
ACULYX is open source under the Apache 2.0 license. You can audit the codebase directly on GitHub to verify all privacy assertions. There is no telemetry, tracking, or analytics code; the only outbound network communications from ACULYX are the optional, user-confirmed credential checks described in Section 5.1 and explicit developer CLI scans described in Section 5.2.

---

## 7. Contact
For questions regarding this privacy policy or ACULYX security practices:
- **Author & Maintainer:** Dhyan Patel
- **Email:** Dhyanpatel884@gmail.com
- **Repository:** https://github.com/Gone27/ACULYX
