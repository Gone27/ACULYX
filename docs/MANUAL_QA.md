# Manual QA Verification Checklist

This document provides a comprehensive manual QA checklist for the ACULYX extension to ensure features behave as expected across Edge Cases, MV3 Lifecycle limits, and Privacy requirements.

## 1. Permission and UI Flow
- [ ] **Native consent UI**
  - **Reproduction Steps**: Click "Monitor this site" on the extension popup for a new site.
  - **Pass Criteria**: Chrome prompts for host permission, and upon granting, the extension begins active monitoring.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox
- [ ] **Per-site permission grant flow**
  - **Reproduction Steps**: Grant access on `example.com`, then navigate to `example.org`.
  - **Pass Criteria**: Verify granting access on one origin does not implicitly grant it on others.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox
- [ ] **External permission revocation**
  - **Reproduction Steps**: Go to `chrome://extensions/?id=[extension_id]` and manually revoke the site permission. Return to the site.
  - **Pass Criteria**: The extension should pause gracefully without silent failures or unexpected errors. Verify that there is no silent All-sites fallback.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox

## 2. Privacy and Isolation
- [ ] **Incognito / Private browsing isolation**
  - **Reproduction Steps**: Open an Incognito window and navigate to a monitored site. Generate findings. Close the Incognito window. Try to view the findings in a regular window.
  - **Pass Criteria**: Findings are captured in Incognito. Closing the window completely wipes the Incognito session's state from memory and session storage, and it cannot be accessed from a regular window.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox
- [ ] **Storage quota and degraded health handling**
  - **Reproduction Steps**: Trigger a large number of history events (e.g., repeatedly navigating) to reach storage limits (simulate via script if needed).
  - **Pass Criteria**: The application does not crash when storage quotas are near, and degraded health states are handled gracefully (e.g., pruning old records).
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox

## 3. Architecture & Lifecycle (MV3 Service Worker)
- [ ] **MV3 service worker idle shutdown**
  - **Reproduction Steps**: Keep the browser open without interacting with the extension for 5+ minutes until the Service Worker stops (or stop it manually in `chrome://serviceworker-internals`). Navigate to a monitored site.
  - **Pass Criteria**: Verify the Service Worker restarts correctly and begins capturing data immediately.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox
- [ ] **Session hydration revival**
  - **Reproduction Steps**: Stop the Service Worker. Trigger an event that restarts it (e.g., open popup). Check if previous session state is intact.
  - **Pass Criteria**: Previous session state (like active tabs and incognito tab lists) is successfully hydrated from `chrome.storage.session` and `chrome.tabs.query`.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox

## 4. Visuals & Accessibility
- [ ] **Keyboard accessibility**
  - **Reproduction Steps**: Use `Tab` to navigate through the popup and side panel.
  - **Pass Criteria**: Ensure all interactive elements have a visible focus outline (`:focus-visible`) and can be activated via `Enter`/`Space`.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox
- [ ] **`prefers-reduced-motion`**
  - **Reproduction Steps**: Enable OS-level reduced motion settings. Open the popup.
  - **Pass Criteria**: Verify animations (e.g., score transitions, pulsing dots) are disabled or simplified.
  - **Browser Test Results**: [ ] Chrome | [ ] Edge | [ ] Firefox
