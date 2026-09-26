# Privacy Policy for Header & Cookie Security Checker (SecCheck)

**Effective Date:** September 25, 2026  
**Last Updated:** September 25, 2026

## 1. Overview & Core Philosophy
SecCheck was built from the ground up on a strict **zero-telemetry, zero-exfiltration** privacy architecture. We believe security auditing tools should never compromise the privacy of the person using them.

All security analysis and evaluation is executed **100% locally inside your web browser**. 

---

## 2. Information We Do NOT Collect
- **Zero Remote Telemetry:** SecCheck does not have any external tracking servers, analytics endpoints, or cloud backends. The extension's Content Security Policy strictly enforces `connect-src 'none'`, mathematically preventing network requests from extension pages.
- **Never Stores Cookie Values:** SecCheck inspects cookie attributes (such as `Secure`, `HttpOnly`, `SameSite`, and prefix naming) for compliance. **Cookie values and contents are never read, copied, or stored in browser storage.** Only cookie names, domain scopes, and flag metadata are evaluated.
- **No Personal Identifiers:** We do not collect names, email addresses, IP addresses, search queries, or browsing history.

---

## 3. Data Handled Locally on Your Device
When you choose to monitor an origin, SecCheck temporarily processes network headers and cookie attributes locally:
- **HTTP Response Headers:** Evaluated against security standards (HSTS, CSP, X-Content-Type-Options, etc.).
- **Local Storage (`chrome.storage.local` & `session`):** 
  - User configuration settings (e.g. per-site allowlist, severity filters).
  - Historical domain scores (capped at the last 10 visits per monitored domain to calculate trends).
  - Tab state cached in session storage to survive service worker idle cycles.
- **Local Export:** When you click "Export JSON" or "Copy Report", the report is compiled locally in memory and provided directly to you. No external service is contacted.

---

## 4. Permissions Usage
SecCheck operates under a strict principle of least privilege:
- `webRequest` & `webNavigation`: Used passively to inspect response headers as pages load.
- `cookies`: Used to inspect security flags (`Secure`, `HttpOnly`, `SameSite`) on set cookies. Values are ignored.
- `storage`: Used to persist user settings and local score history on your device.
- `activeTab` / `optional_host_permissions`: SecCheck requests host permissions **per-site on demand** when you explicitly click "Monitor this site", rather than demanding blanket access to all websites upon installation.

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
- **Issue Tracker:** https://github.com/dhyanpatel/header-cookie-security-checker/issues
