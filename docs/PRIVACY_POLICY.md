# Privacy Policy for Header & Cookie Security Checker (SecCheck)

**Effective Date:** September 25, 2026  
**Last Updated:** September 25, 2026

## 1. Overview & Core Philosophy
SecCheck was built from the ground up on a strict **zero-telemetry, zero-exfiltration** privacy architecture. We believe security auditing tools should never compromise the privacy of the person using them.

All security analysis and evaluation is executed **100% locally inside your web browser**. 

---

## 2. Information We Do NOT Collect
- **Zero Remote Telemetry:** SecCheck does not have any external tracking servers, analytics endpoints, or cloud backends. Extension pages enforce `connect-src 'none'`. The page-signal script also makes no network requests; it uses extension runtime messaging only to report locally.
- **Never Retains or Exfiltrates Cookie Values:** SecCheck inspects cookie attributes (such as `Secure`, `HttpOnly`, `SameSite`, and prefix naming) for compliance. Cookie objects returned by browser APIs are accessed for metadata only (never `cookie.value`). While cookie values may be transiently present in raw, in-flight header strings in memory solely for immediate in-flight redaction, the extension never retains, persists, displays, or transmits cookie values. Any `Set-Cookie` or `Cookie` response/request headers captured in network hops are automatically sanitized so that all secret cookie values are replaced with `[REDACTED]` prior to local session storage, state persistence, or display.
- **No Personal Identifiers:** We do not collect names, email addresses, IP addresses, search queries, or browsing history.

---

## 3. Data Handled Locally on Your Device
When you choose to monitor an origin, SecCheck temporarily processes network headers and cookie attributes locally:
- **HTTP Response Headers:** Evaluated against security standards (HSTS, CSP, X-Content-Type-Options, CORS, etc.) for top-level navigations and in-page API (`xmlhttprequest`/`fetch`) calls on permitted origins. Passive sub-resources (such as images, scripts, stylesheets, and third-party iframes) and request/response bodies are not captured or analyzed.
- **API Endpoint Capture:** In-page API requests (`xmlhttprequest` and `fetch`) to first-party and permitted third-party endpoints are captured to evaluate CORS, MIME-sniffing, and security transport configurations. API endpoint states are strictly bounded (LRU capped at 50 per tab) in session storage. Query strings, auth tokens, and credential material in API URLs are automatically redacted before local display or storage.
- **Authentication Posture Diffs (Auth-Diff Storage):** When logging in or out of a monitored site, SecCheck detects transitions based on metadata changes (such as sensitive cookie issuance or rotation). It records a high-level posture comparison (`AuthDiffRecord`) in `chrome.storage.local` to track how security headers and grades evolved between unauthenticated and authenticated states. Diff records store strictly compact finding metadata (rule IDs, titles, severity), score deltas, and timestamps; zero cookie values, tokens, or credentials are ever stored. Stored diffs are bounded and pruned according to the user's history retention settings.
- **Attack Surface Graph Persistence:** The extension analyzes permitted navigation hops, cookies, and API endpoints to map relationships between the apex domain and affiliated subdomains (`AttackSurfaceGraph`). Graph nodes and edges record only hostnames, timestamps, and discovery mechanisms (e.g. CSP allowlists, cookies, CORS targets). Persisted graphs in `chrome.storage.local` are strictly bounded (maximum 100 nodes, 150 edges) and pruned during periodic maintenance sweeps.
- **Evaluation Mode:** An optional user setting ("Evaluation Mode") unlocks exploration of the full accumulated multi-session attack surface graph. Evaluation mode operates entirely locally with no external licensing servers, payment gateways, or network telemetry.
- **Sensitive URL Redaction:** Query parameters in captured API URLs (such as tokens, auth keys, and passwords) are automatically redacted before local display or session storage.
- **Page signals:** After you grant an origin, a content script inspects the document head for the presence of `<meta http-equiv="Content-Security-Policy">` tags and reads the service-worker controller status and script URL. This detection notes the presence of fallback meta tags strictly as an informational indicator; policy directives inside meta tags are not evaluated for syntax or directive strength, as meta CSP cannot replace HTTP response headers. The check runs in local memory and notes presence in temporary tab session storage. The content script never collects page body HTML, DOM tree contents, forms, or user input.
- **Local Storage (`chrome.storage.local` & `session`):** 
  - User configuration settings (e.g. per-site allowlist, severity filters, evaluation mode).
  - Historical domain scores and auth-diff records (pruned according to retention settings).
  - Attack surface graphs (bounded and pruned).
  - Tab state cached in session storage to survive service worker idle cycles.
- **Local Export:** When you click "Export JSON" or "Copy Report", the report is compiled locally in memory and provided directly to you. No external service is contacted.

---

## 4. Permissions Usage
SecCheck operates under a strict principle of least privilege:
- `webRequest` & `webNavigation`: Used passively to inspect HTTP response headers for top-level navigation and in-page API (`xmlhttprequest`/`fetch`) requests within monitored origins. Request and response bodies are never inspected, and non-API sub-resources (images, fonts, stylesheets, iframes) are ignored.
- `cookies`: Used to inspect security flags (`Secure`, `HttpOnly`, `SameSite`) on set cookies. Values are ignored.
- `storage`: Used to persist user settings and local score history on your device.
- `scripting` / `optional_host_permissions`: SecCheck requests host permissions **per-site on demand** when you explicitly click "Monitor this site". Only after permission is granted does SecCheck observe top-level and API response headers or inject the page-signal check on that permitted origin. It does not declare static all-sites host permissions.
- `activeTab`: Supports interactions with the currently selected tab; it does not cause page-signal collection before the origin is granted.

---

## 5. Third-Party Sharing
We do not sell, rent, trade, or transfer any user data to outside parties. There are no third-party SDKs, tracking pixels, or advertisement networks in SecCheck.

---

## 6. Open Source Verification
SecCheck is open source. You can audit the codebase directly on GitHub to verify all privacy assertions and ensure that no network exfiltration code exists.

---

## 7. Contact
For questions regarding this privacy policy or SecCheck security practices:
- **Project Maintainer:** Dhyan Patel
- **Email:** Dhyanpatel884@gmail.com
- **Issue Tracker:** https://github.com/Gone27/Cookie-and-header-reader-extention/issues
