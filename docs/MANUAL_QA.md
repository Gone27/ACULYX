# Manual QA Verification Checklist

This document provides a comprehensive manual QA checklist for the SecCheck extension to ensure features behave as expected across Edge Cases, MV3 Lifecycle limits, and Privacy requirements.

## 1. Permission and UI Flow
- [ ] **Native consent UI**: Click "Monitor this site" on the extension popup. Verify Chrome prompts for host permission, and upon granting, the extension begins active monitoring.
- [ ] **Per-site permission grant flow**: Verify granting access on one origin does not implicitly grant it on others.
- [ ] **External permission revocation**: Go to `chrome://extensions/?id=[extension_id]` and manually revoke the site permission. Return to the site; the extension should pause gracefully without silent failures or unexpected errors. Verify that there is no silent All-sites fallback.

## 2. Privacy and Isolation
- [ ] **Incognito / Private browsing isolation**:
  - Open an Incognito window and navigate to a monitored site.
  - Verify that findings are captured.
  - Close the Incognito window and verify that the Incognito session's state is completely wiped and cannot be accessed from a regular window.
- [ ] **Storage quota and degraded health handling**: Trigger a large number of history events (e.g., repeatedly navigating) to reach storage limits. Verify that the application does not crash when storage quotas are near and degraded health states are handled gracefully.

## 3. Architecture & Lifecycle (MV3 Service Worker)
- [ ] **MV3 service worker idle shutdown**: 
  - Keep the browser open without interacting with the extension for 5+ minutes until the Service Worker stops.
  - Navigate to a monitored site and verify the Service Worker restarts correctly.
- [ ] **Session hydration revival**: Verify that after a Service Worker restart, previous session state is successfully hydrated from `chrome.storage.session`.

## 4. Visuals & Accessibility
- [ ] **Keyboard accessibility**: Use `Tab` to navigate through the popup and side panel. Ensure all interactive elements have a visible focus outline (`:focus-visible`).
- [ ] **`prefers-reduced-motion`**: Enable OS-level reduced motion settings. Verify animations (e.g., score transitions) are disabled or simplified.
