# Privacy Policy for ACULYX: Header & Cookie Security Checker

**Effective Date:** September 25, 2026  
**Last Updated:** October 8, 2026  
**Author & Maintainer:** Dhyan Patel

## 1. Overview & Core Philosophy
ACULYX was engineered from the ground up on a strict **zero-telemetry, zero-exfiltration** privacy architecture. We believe security auditing tools should never compromise the privacy of the person using them.

All security analysis and evaluation is executed **100% locally inside your web browser**.

---

## 2. Information We Do NOT Collect
- **Zero Remote Telemetry:** ACULYX does not have external tracking servers, analytics endpoints, or cloud backends. Extension pages enforce `connect-src 'none'`. Content scripts make zero network requests and communicate solely through local extension runtime messaging.
- **Never Retains or Exfiltrates Cookie Values:** ACULYX inspects cookie metadata attributes (such as `Secure`, `HttpOnly`, `SameSite`, and prefix naming) for compliance. Cookie objects returned by browser APIs are accessed for metadata only (never `cookie.value`). Raw in-flight headers are automatically sanitized and query strings and fragments are stripped prior to storage.
- **No Personal Identifiers:** We do not collect names, email addresses, IP addresses, search queries, or browsing history.

---

## 3. Data Handled Locally on Your Device
When you choose to monitor an origin, ACULYX temporarily processes network headers and cookie attributes locally:
- **HTTP Response Headers:** Evaluated against security standards (HSTS, CSP, X-Content-Type-Options, CORS, etc.) for top-level navigations and in-page API (`xmlhttprequest`/`fetch`) calls on permitted origins.
- **API Endpoint Capture:** In-page API requests (`xmlhttprequest` and `fetch`) to first-party and permitted third-party endpoints are captured to evaluate CORS, MIME-sniffing, and security transport configurations. API endpoint states are strictly bounded (LRU capped at 50 per tab) in session storage. Query strings, auth tokens, and credential material in API URLs are automatically redacted before local display or storage.
- **Authentication Posture Diffs (Auth-Diff Storage):** When logging in or out of a monitored site, ACULYX detects transitions based on metadata changes (such as sensitive cookie issuance or rotation). It records a high-level posture comparison (`AuthDiffRecord`) in `chrome.storage.local` to track how security headers and grades evolved between unauthenticated and authenticated states.
- **Attack Surface Graph Persistence:** The extension analyzes permitted navigation hops, cookies, and API endpoints to map relationships between the apex domain and affiliated subdomains (`AttackSurfaceGraph`). Persisted graphs in `chrome.storage.local` are strictly bounded (maximum 100 nodes, 150 edges) and pruned during periodic maintenance sweeps.
- **Evaluation Mode:** An optional user setting ("Evaluation Mode") unlocks exploration of the full accumulated multi-session attack surface graph. Evaluation mode operates entirely locally with no external licensing servers, payment gateways, or network telemetry.
- **Sensitive URL Redaction:** All URL query parameters (`?`) and fragments (`#`) are stripped before storage or export, eliminating inadvertent leaks of OAuth `state`, session tokens, or emails.
- **Local Storage (`chrome.storage.local` & `session`):** 
  - User configuration settings (e.g. per-site allowlist, severity filters, evaluation mode).
  - Historical domain scores and auth-diff records (pruned according to retention settings).
  - Attack surface graphs (bounded and pruned).
  - Tab state cached in session storage to survive service worker idle cycles.
- **Local Export:** When you click "Export JSON" or "Copy Report", the report is compiled locally in memory and provided directly to you. No external service is contacted.

---

## 4. Permissions Usage
ACULYX operates under a strict principle of least privilege:
- `webRequest` & `webNavigation`: Used passively to inspect HTTP response headers for top-level navigation and in-page API (`xmlhttprequest`/`fetch`) requests within monitored origins.
- `cookies`: Used to inspect security flags (`Secure`, `HttpOnly`, `SameSite`) on cookies. Values are never accessed.
- `storage`: Used to persist user settings and local score history on your device.
- `scripting` / `optional_host_permissions`: ACULYX requests host permissions **per-site on demand** when you explicitly click "Monitor this site".
- `activeTab`: Supports interactions with the currently selected tab.

---

## 5. Third-Party Sharing
We do not sell, rent, trade, or transfer any user data to outside parties. There are no third-party SDKs, tracking pixels, or advertisement networks in ACULYX.

---

## 6. Open Source Verification
ACULYX is open source under the Apache 2.0 license. You can audit the codebase directly on GitHub to verify all privacy assertions and ensure that no network exfiltration code exists.

---

## 7. Contact
For questions regarding this privacy policy or ACULYX security practices:
- **Author & Maintainer:** Dhyan Patel
- **Email:** Dhyanpatel884@gmail.com
- **Repository:** https://github.com/Gone27/ACULYX
