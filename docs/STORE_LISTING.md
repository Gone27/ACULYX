# Chrome Web Store & Firefox Add-ons Store Listing Assets

---

## 1. Title & Short Name
- **Extension Name:** ACULYX: Header & Cookie Security Checker
- **Short Name:** ACULYX
- **Version:** 2.0.0
- **Author:** Dhyan Patel

---

## 2. One-Line Punchy Pitch (Summary / Tagline)
> Passively inspect HTTP response headers, cookies, and subdomain trust escalation paths — 100% locally, with zero telemetry.

---

## 3. Short Description (Max 132 chars for Chrome Web Store)
> Passive HTTP security header & cookie analysis with live grading, CSP evaluation, and privacy-preserving audit capabilities.

---

## 4. Detailed Description

### 🛡️ Why ACULYX?
Most security header checkers are remote online scanners that run outside your authenticated session or simple checklist extensions that overwhelm you with confusing warnings. 

**ACULYX** is a developer- and security-focused browser extension designed for web developers, penetration testers, and security researchers. It passively evaluates HTTP response headers and live cookie configurations directly from within your browser as pages load — giving you an accurate, real-world security grade without sending a single byte of your browsing data over the network.

Because ACULYX observes responses in the browser you are already using, it can audit pages reached after you sign in, subject to the per-origin permission you grant. It does not bypass authentication, defeat access controls, or discover pages you have not visited.

---

### 🚀 Key Features

- **🎯 Defensive Scoring Engine:**
  - Evaluates HSTS, Content-Security-Policy (CSP Level 3 aware, recognizing modern nonces and strict-dynamic via Google `csp_evaluator`), COEP/CORP, Permissions-Policy, Document-/Integrity-Policy, browser reporting, legacy headers, server fingerprints, and cache directives.
  - Sensitivity-aware cookie rules: distinguishes between high-value session tokens and harmless client-side UI cookies (preventing false alarms on theme or analytics cookies).
  - Categorized penalty caps prevent minor cookie issues from artificially tanking an otherwise rock-solid site.

- **💡 Explains "Why", Not Just "What":**
  - Every finding includes a concise, plain-English **Real-World Impact** explanation, helping you understand actual exploitability rather than theoretical compliance.

- **⚡ Subdomain→Main-Domain Trust Escalation Analysis:**
  - Unique attack-surface analysis inspecting whether a compromise on a low-security subdomain (e.g. blog, staging, dev) can jump over to compromise the apex domain via broad cookie scoping, missing `__Host-` prefixes, or wildcard CSP sources.

- **🔒 Zero-Telemetry Guarantee:**
  - ACULYX operates under `connect-src 'none'`. No outbound network requests are made from the extension pages.
  - Cookie values, auth tokens, passwords, and URL query strings are never stored, displayed, or exported.

- **📊 Modern Cyber-Inspired UI:**
  - Dark, Cyberpunk, and Solar theme modes with comfortable and compact density settings.
  - Interactive Attack Surface Graph powered by D3-force in the Side Panel.

---

## 5. Category & Search Keywords
- **Category:** Developer Tools / Security
- **Keywords:** security headers, cookie security, csp evaluator, hsts, subresource integrity, privacy, oauth, web security, owasp, penetration testing
