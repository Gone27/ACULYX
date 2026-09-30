# Chrome Web Store & Firefox Add-ons Store Listing Assets

---

## 1. Title & Short Name
- **Extension Name:** Header & Cookie Security Checker (SecCheck)
- **Short Name:** SecCheck
- **Version:** 0.1.0

---

## 2. One-Line Punchy Pitch (Summary / Tagline)
> Passively inspect HTTP response headers, cookies, and subdomain trust escalation paths — 100% locally, with zero telemetry.

---

## 3. Short Description (Max 132 chars for Chrome Web Store)
> Real-time security posture audit for HTTP headers & cookies. Explains vulnerabilities, tests subdomain trust, and exports audit reports.

---

## 4. Detailed Description

### 🛡️ Why SecCheck?
Most security header checkers are remote online scanners that run outside your authenticated session or simple checklist extensions that overwhelm you with confusing warnings. 

**SecCheck** is a developer- and security-focused browser extension designed for web developers, penetration testers, and bug bounty hunters. It passively evaluates HTTP response headers and live cookie configurations directly from within your browser as pages load — giving you an accurate, real-world security grade without sending a single byte of your browsing data over the network.

Because SecCheck observes responses in the browser you are already using, it can audit pages reached after you sign in, subject to the per-origin permission you grant. It does not bypass authentication, defeat access controls, or discover pages you have not visited.

---

### 🚀 Key Features

- **🎯 Trustworthy Scoring Engine:**
  - Evaluates HSTS, Content-Security-Policy (CSP Level 3 aware, recognizing modern nonces and strict-dynamic), COEP/CORP, Permissions-Policy, Document-/Integrity-Policy, browser reporting, legacy headers, server fingerprints, and cache directives.
  - Provides basic HSTS preload-header readiness guidance; it does not query or assert public preload-list membership.
  - Reports headers that disappear between redirect responses and highlights a small curated set of CSP script hosts for manual review (informational heuristics, not proof of exploitability).
  - Sensitivity-aware cookie rules: distinguishes between high-value session tokens and harmless client-side UI cookies (preventing false alarms on theme or analytics cookies).
  - Categorized penalty caps prevent minor cookie issues from artificially tanking an otherwise rock-solid site.

- **💡 Explains "Why", Not Just "What":**
  - Every finding includes a concise, plain-English **Real-World Impact** sentence (e.g. *"An attacker on public Wi-Fi can downgrade connection to HTTP and steal session cookies"*), helping you understand the actual exploitability rather than just theoretical compliance.

- **⚡ Subdomain→Main-Domain Trust Escalation Analysis:**
  - Unique attack-surface analysis inspecting whether a compromise on a low-security subdomain (e.g. blog, staging, dev) can jump over to compromise the apex domain via:
    1. Broad cookie scoping (`Domain=.example.com`)
    2. Missing `__Host-` prefixes (Cookie Tossing risk)
    3. Wildcard CSP script sources (`*.example.com`)
    4. Permissive CORS reflection and iframe framing
    5. Missing Cross-Origin-Opener-Policy (Reverse Tabnabbing)

- **📈 Trend Tracking Over Time:**
  - Automatically remembers past audit scores per domain so you can track whether your fixes improved the site's security posture over time.

- **📋 One-Click Audit Reports:**
  - Export structured technical JSON for automation or test suites.
  - **SARIF 2.1.0 CLI output:** Upload findings to GitHub Code Scanning or other SARIF-compatible CI systems.
  - **Offline HAR import:** Audit a selected captured response, including pages reached in an authenticated browser session; cookie values are redacted and response bodies are not analyzed.
  - **Copy Markdown Report:** Generates an executive summary and findings table formatted ready to paste into Jira, HackerOne bug bounty reports, or client penetration test deliverables.

- **🧭 Browser Side Panel:** Keep findings, score breakdowns, trend, and trust graph open beside the page while you work.

- **🔒 Built for Privacy First:**
  - **Zero Remote Telemetry:** Extension pages block outbound connections with `connect-src 'none'`; the page-signal script makes no network requests and sends only local extension messages.
  - **Zero Cookie Value Storage:** Only cookie metadata (flags and domain scope) is analyzed. Cookie contents and secrets are never read or stored.
  - **Opt-in Permissions:** Works on an on-demand, per-site model — you decide when and where to inspect.
  - **Meta-CSP Signal:** Detects whether a page contains a CSP meta tag, but does not evaluate the meta policy contents.

### Coverage Boundaries

- SecCheck analyzes top-level (`main_frame`) navigation responses and in-page API (`xmlhttprequest` / `fetch`) responses on user-permitted origins. Static sub-resources (such as images, fonts, and stylesheets) and embedded iframes are not inspected; this is not a full whole-page resource crawl.
- Sensitive query parameters (such as tokens, session keys, and auth parameters) in captured API URLs are automatically redacted before local display or storage.
- A detected meta CSP is reported as a presence signal only. Full CSP policy evaluation applies to HTTP response headers.

---

## 5. Screenshot Walkthrough & Captions

> **Submission media status:** No actual store screenshots, promotional tile, or demo video are present in this repository. The captions below are capture briefs, not upload-ready assets. The existing `icons/` files are extension icons, not listing screenshots. Capture real UI screenshots before submitting the CWS listing.

### Screenshot 1: Overview & Instant Security Grade
- **Caption:** *"Instant passive security evaluation with clear letter grades and domain score tracking."*
- **Visual Focus:** Main popup view showing Grade A/B badge, origin URL, score trend indicator, and top findings list.

### Screenshot 2: Plain-English Real-World Impact
- **Caption:** *"Understand the actual risk: every finding clearly explains the exploit vector and recommended fix."*
- **Visual Focus:** Finding card expanded displaying "⚡ Impact:" sentence with remediation advice and OWASP/MDN references.

### Screenshot 3: Subdomain Trust Escalation Panel
- **Caption:** *"Detect whether a vulnerable subdomain can compromise your main domain via cookies, CSP, or CORS."*
- **Visual Focus:** Subdomain Trust Analysis dropdown open showing green/amber/red indicators for Cookie Scoping, Cookie Tossing, CSP, and COOP.

### Screenshot 4: One-Click Audit Report Export
- **Caption:** *"Generate professional Markdown audit reports ready for bug bounty programs, Jira tickets, or client deliverables."*
- **Visual Focus:** Export actions highlighted showing "Export JSON" and "📋 Copy Report".

---

## 6. Categories & Search Keywords
- **Primary Category:** Developer Tools
- **Secondary Category:** Privacy & Security
- **Keywords / Tags:**
  `security headers`, `csp evaluator`, `hsts`, `cookie security`, `httponly`, `samesite`, `clickjacking`, `web security`, `vapt`, `bug bounty`, `penetration testing`, `subdomain takeover`

---

## 7. Reviewer Justification for Permissions
- `webRequest` / `webNavigation`: Passively observes HTTP response headers on main-frame navigations and in-page API calls (XHR/fetch) on user-permitted origins to calculate security header grades.
- `cookies`: Inspects cookie security attributes (Secure, HttpOnly, SameSite, prefixes) to detect insecure session storage.
- `storage`: Persists local user preferences and historical domain scores locally on the device.
- `scripting`: Injects the small page-signal check only after the user grants that origin; it checks meta-CSP presence and service-worker control, and sends results only to the local extension service worker.
- `sidePanel`: Opens the existing analysis UI in Chrome's side panel when the toolbar action is clicked.
- `optional_host_permissions`: Requested strictly on-demand per origin when the user clicks "Monitor this site" to respect least-privilege principles.
