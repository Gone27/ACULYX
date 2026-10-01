# SecCheck Behavior Contract: Modes, Permissions, Capture Gating, and Retention

This document specifies the exact runtime semantics and invariant contracts for SecCheck (Header & Cookie Security Checker) regarding monitoring modes, browser permissions, traffic capture gating, data retention, and lifecycle cleanup. All extension code, user interfaces, background services, and automated test suites must conform to this contract.

---

## 1. Non-Negotiable Invariants

1. **Zero Secret Exfiltration / Storage:** Cookie values and request/response bodies are never persisted, logged, transmitted, messaged, or exported. Set-Cookie/Cookie header values in memory are immediately redacted to `[REDACTED]`.
2. **Strict Consent on Broad Grants:** The extension never requests broad host access (`<all_urls>` or `*://*/*`) unless the user explicitly chooses "All sites" with a direct user click/gesture. Access is never broadened silently to circumvent missing coverage.
3. **Passive Observation Only:** The browser extension is purely passive. It never generates artificial probe requests or out-of-band network traffic to inspect sites. (CLI `--url` mode is separate and intentional).
4. **Local-First & Safe UI:** No remote telemetry, no external scripts or remote assets, and no dynamic HTML injection (`innerHTML`, `outerHTML`, or `insertAdjacentHTML` with unescaped data).
5. **Presentation Separation:** Presentation settings (such as `severityFilter`) alter only visible UI views; they **never** alter the underlying computed security score or grade. Developer flags (such as `evaluationMode`) never weaken security checks.
6. **MV3 Lifecycle Independence:** The background service worker can terminate at any moment due to inactivity. Persistent state lives in `chrome.storage.session` and `chrome.storage.local`. No feature may rely on continuous keepalive alarms.

---

## 2. Monitoring Mode Contract

SecCheck operates in one of three mutually exclusive monitoring modes:

| Mode | Runtime Capture Behavior | Permission & UI Contract |
| :--- | :--- | :--- |
| `per-site` | Inspects HTTP headers, cookies, and page signals **only** for web origins explicitly granted by the user. Enforced at the browser layer via optional host permissions. | Popup displays current site status. If the origin lacks permission, an explicit "Monitor this site" action is shown. Granting permission requests host access for `origin/*` via `chrome.permissions.request()`. |
| `all-sites` | Inspects HTTP headers, cookies, and page signals across all supported web origins (`http://*`, `https://*`). Browser-internal pages (`chrome://`, `about:`, Web Store) are excluded. `file:` URLs require separate explicit browser-level file-access approval. | Switching to `all-sites` in Options or Popup initiates a user-gesture request for `<all_urls>`. **If denied or cancelled by the user**, the extension immediately restores the exact previous mode (e.g. `per-site` or `off`), restores the UI selection, and explains what remains observable. |
| `off` | **Completely inactive:** Zero navigation capture, zero API capture, zero cookie correlation, zero page-signal script injection, and badge cleared (`''`). | Options and Popup provide two distinct actions: <br>1. **Pause Monitoring:** Halts all capture while preserving existing host permission grants.<br>2. **Pause and Revoke Access:** Halts all capture and explicitly revokes all optional host grants via `chrome.permissions.remove()`. <br>The UI must never claim permissions are revoked when capture is merely paused. |

### 2.1 Broad Grant Conflict Handling

If `monitoringMode` is configured to `per-site` but a broad grant (e.g. `<all_urls>` or `*://*/*`) is currently active in the browser's permission store:
- **Display Warning:** Options and Popup display an explicit notice: *"Broad access is active"*.
- **Conflict Actions:** The user is provided two one-click remediation actions:
  1. *Remove broad access* (invokes `chrome.permissions.remove` for the broad pattern).
  2. *Switch to All sites* (updates `monitoringMode` to `all-sites`).
- **Gating Resolution:** While unresolved, capture is treated as paused with reason `broad-access-conflict`. This guarantees predictable consent without guessing the user's intent.
- **Mode Switching:** Switching from `all-sites` to `per-site` explicitly offers to revoke the active broad grant.

---

## 3. Capture Gating Specification

### 3.1 Pure Decision Function: `isModeCaptureAllowed`

A pure synchronous function evaluates whether a URL qualifies for capture under the active configuration:

```typescript
export interface CaptureGateResult {
  allowed: boolean;
  reason: 'ok' | 'off' | 'broad-access-conflict' | 'restricted-url';
}

export function isModeCaptureAllowed(
  url: string,
  settings: SettingsV2,
  broadGrantPresent: boolean
): CaptureGateResult;
```

**Evaluation Rules:**
1. If `url` is blank or belongs to a restricted scheme (`chrome://`, `chrome-extension://`, `edge://`, `about:`, Chrome Web Store, Firefox Add-ons site), return `{ allowed: false, reason: 'restricted-url' }`.
2. For `file:` URLs: if browser file-scheme access is not granted, return `{ allowed: false, reason: 'restricted-url' }`.
3. If `settings.monitoringMode === 'off'`, return `{ allowed: false, reason: 'off' }`.
4. If `settings.monitoringMode === 'per-site'` and `broadGrantPresent === true`, return `{ allowed: false, reason: 'broad-access-conflict' }`.
5. Otherwise, return `{ allowed: true, reason: 'ok' }`.

> **Note on Host Permissions:** `isModeCaptureAllowed` evaluates policy and restricted URLs. It does **not** assume `broadGrantPresent` implies access to a specific URL. Actual origin host permissions are checked asynchronously via `chrome.permissions.contains({ origins: [origin + '/*'] })`.

### 3.2 Gating Scope: Analysis vs. Cleanup

- **Gated Operations (Halted when not allowed):**
  - Processing `onHeadersReceived` / `onResponseStarted` hops into `TabState`.
  - Computing security rules, scores, and grades.
  - Correlating cookies.
  - Recording API subresource endpoints (`xmlhttprequest` / `fetch`).
  - Injecting page-signal content scripts.
  - Setting action badge grade.
- **Ungated Operations (Always executed):**
  - Request lifecycle cleanup (`onCompleted`, `onErrorOccurred`, `onBeforeRedirect` map housekeeping).
  - Tab closure cleanup (`tabs.onRemoved`).
  - Permission revocation synchronization (`permissions.onRemoved`).
  - History retention maintenance sweep (`pruneHistory`).

---

## 4. Permissions Synchronization & Revocation

### 4.1 Single Source of Truth
`chrome.permissions.getAll()` is the authoritative source of truth for granted origins. The extension never stores or relies on a separate `allowedOrigins` array in local storage as a source of truth.

### 4.2 Request Sequencing
All `chrome.permissions.request()` calls must be the synchronous first action within a user gesture callback (click event). Never `await` async storage or messaging prior to invoking `chrome.permissions.request()`, as doing so forfeits the user gesture token in Chromium and Firefox.

### 4.3 Revocation & Cleanup (`clearTabCapture`)
When a host permission is removed (via popup "Stop Monitoring", Options "Remove", or externally in browser extension settings):
1. Service worker receives `chrome.permissions.onRemoved` (or detects missing permission on startup reconciliation).
2. For each tracked tab belonging to the revoked origin, `clearTabCapture(tabId)` is invoked:
   - Evicts tab from in-memory `tabStates`.
   - Deletes `tab:${tabId}` from `chrome.storage.session`.
   - Clears pending capture maps, partials, and page-signal receipts.
   - Clears action badge: `chrome.action.setBadgeText({ tabId, text: '' })`.
   - Notifies connected ports and broadcasts empty state update to open popup and side panel.

---

## 5. Data Retention & Deletion Contract

### 5.1 Historical Domain Scores
Historical domain scores are stored in `chrome.storage.local` under `history:${origin}`:
- `retainHistoryDays`:
  - `0`: Keep forever (age pruning disabled).
  - `1..365`: Entries older than $N \times 86400 \times 1000$ milliseconds are pruned.
- `maxHistoryPerOrigin`:
  - Default: `10` entries.
  - Permitted range: `1..50` entries.
- **Pruning Precedence:** Age pruning (`retainHistoryDays`) is applied first. The per-origin count cap (`maxHistoryPerOrigin`) is applied second to the remaining entries.
- **Maintenance Execution:** Pruning runs upon service-worker startup and periodically via a 1-minute browser alarm (`chrome.alarms`).

### 5.2 Revocation Deletion Policy
- **Default Policy:** Revoking an origin clears active session state and badges immediately, but **preserves** historical score trends and attack surface graphs so users do not lose historical audit data on temporary permission pauses.
- **Explicit Site Purge:** An explicit action, *"Delete stored data for this site"*, is available in Options to purge all historical data and graph nodes for a specified origin.

---

## 6. Presentation and Evaluation Invariants

1. **Severity Filter (`severityFilter`):**
   - Applies strictly as a display filter in UI views (`selectVisibleFindings`).
   - Does **not** modify `TabState.score`, `TabState.grade`, or `TabState.scoreBreakdown`.
   - UI displays count of hidden findings (e.g. *"2 findings hidden by filter"*) with a *"Show all"* override.
2. **Evaluation Mode (`evaluationMode`):**
   - Replaces the user-facing "Pro" branding. Located under a collapsed Developer section in Options.
   - Strictly controls diagnostic export capabilities and attack-surface visualization options.
   - **Never** alters, suppresses, or weakens any rule finding or penalty weight. Security scores are identical regardless of whether `evaluationMode` is `true` or `false`.
