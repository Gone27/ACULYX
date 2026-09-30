# Privacy Policy for Header & Cookie Security Checker (SecCheck)

**Effective Date:** September 25, 2026  
**Last Updated:** September 25, 2026

## 1. Overview & Core Philosophy
SecCheck was built from the ground up on a strict **zero-telemetry, zero-exfiltration** privacy architecture. We believe security auditing tools should never compromise the privacy of the person using them.

All security analysis and evaluation is executed **100% locally inside your web browser**. 

---

## 2. Information We Do NOT Collect
- **Zero Remote Telemetry:** SecCheck does not have any external tracking servers, analytics endpoints, or cloud backends. Extension pages enforce `connect-src 'none'`. The page-signal script also makes no network requests; it uses extension runtime messaging only to report locally.
- **Never Stores Cookie Values:** SecCheck inspects cookie attributes (such as `Secure`, `HttpOnly`, `SameSite`, and prefix naming) for compliance. **Cookie values and contents are never read, copied, or stored in browser storage.** Only cookie names, domain scopes, and flag metadata are evaluated.
- **No Personal Identifiers:** We do not collect names, email addresses, IP addresses, search queries, or browsing history.

---

## 3. Data Handled Locally on Your Device
When you choose to monitor an origin, SecCheck temporarily processes network headers and cookie attributes locally:
- **HTTP Response Headers:** Evaluated against security standards (HSTS, CSP, X-Content-Type-Options, CORS, etc.) for top-level navigations and in-page API (`xmlhttprequest`/`fetch`) calls on permitted origins. Passive sub-resources (such as images, scripts, stylesheets, and third-party iframes) and request/response bodies are not captured or analyzed.
- **Sensitive URL Redaction:** Query parameters in captured API URLs (such as tokens, auth keys, and passwords) are automatically redacted before local display or session storage.
- **Page signals:** After you grant an origin, a content script checks the top-level document for a non-empty CSP meta tag and reads the service-worker controller status and script URL. It sends only those signals to the extension service worker. It does not collect page HTML or the meta policy text.
- **Local Storage (`chrome.storage.local` & `session`):** 
  - User configuration settings (e.g. per-site allowlist, severity filters).
  - Historical domain scores (capped at the last 10 visits per monitored domain to calculate trends).
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
