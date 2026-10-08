# ACULYX Authoritative Behavior Contract: Modes, Permissions, Capture Gating, Runtime Architecture, and Data Lifecycle

This document is the binding architectural and behavioral specification for ACULYX (Header & Cookie Security Checker) across all workstreams (WS0 through WS7). All extension components—including the background service worker, content scripts, popup, Options page, side panel, sandbox proof-of-concept generators, and standalone CLI—must strictly adhere to the contracts, state transitions, and invariants defined herein.

---

## 1. Non-Negotiable Core Invariants

1. **Zero Secret Exfiltration / Storage:** Cookie values and request/response bodies are never persisted, logged, transmitted, messaged, or exported. Set-Cookie and Cookie header values in memory are immediately redacted to `[REDACTED]`. Sensitive URL path segments and query parameters are redacted before entering state. Synthetic canary tests must be maintained across local storage, session storage, port messages, diagnostics, and export sinks to guarantee secret containment.
2. **Strict Consent on Broad Grants:** The extension never requests broad host access (`<all_urls>` or `*://*/*`) unless the user explicitly chooses "All sites" via a direct user gesture (click event). Host access is never silently widened to circumvent missing coverage. Permission API requests (`chrome.permissions.request()`) must execute as the synchronous first action within a user gesture callback before any asynchronous operations or awaits.
3. **Authoritative Browser Permission Store:** `chrome.permissions.getAll()` and permission lifecycle events (`permissions.onAdded`, `permissions.onRemoved`) are the sole authoritative source of truth for granted origins. The extension never stores or relies on a separate `allowedOrigins` array in storage as a source of truth.
4. **Passive Observation Only:** The browser extension operates purely passively. It never generates artificial probe requests or out-of-band network traffic to inspect sites. (The standalone CLI `--url` mode is a separate, intentional, explicit developer action).
5. **Local-First & Safe UI:** No remote telemetry, no external scripts or remote stylesheets, and no dynamic HTML injection (`innerHTML`, `outerHTML`, or `insertAdjacentHTML` with unescaped or untrusted data).
6. **Presentation Separation:** Presentation settings (such as `severityFilter`) alter only visible UI views; they **never** alter the underlying computed security score, grade, or breakdown. Developer flags (such as `evaluationMode`) never weaken security checks or alter score algorithms.
7. **MV3 Lifecycle Independence:** The background service worker can terminate at any moment due to browser inactivity. Correctness relies entirely on persistent storage (`chrome.storage.session` and `chrome.storage.local`), versioned state snapshots, and idempotent event listeners—not on continuous keepalive alarms or in-memory timers.
8. **Private Browsing / Incognito Segregation:** Private browsing records must never mix into ordinary persistent history, attack surface graphs, authentication baselines, diagnostics, or exports. Incognito observations reside strictly in an ephemeral session-only namespace and are destroyed when the last private window closes.
9. **Elimination of Commercial Branding:** The extension is strictly open-source and developer-focused. No commercial entitlement language ("Pro", "Free Tier", "Upgrade to Pro") may appear in UI copy, code symbols, messages, or metadata.

---

## 2. Monitoring Mode & Permission Contract

ACULYX operates in one of three mutually exclusive monitoring modes: `per-site`, `all-sites`, and `off`.

| Mode | Runtime Capture Behavior | Permission & UI Contract |
| :--- | :--- | :--- |
| `per-site` | Inspects HTTP headers, cookies, and page signals **only** for web origins explicitly granted by the user. Enforced at the listener boundary via normalized browser host permissions. | Popup displays current site status. If the origin lacks permission, an explicit "Monitor this site" action is shown. Granting permission requests host access for `origin/*` via `chrome.permissions.request()`. |
| `all-sites` | Inspects HTTP headers, cookies, and page signals across all supported web origins (`http://*`, `https://*`). Browser-internal pages (`chrome://`, `about:`, Web Store) are excluded. `file:` URLs require separate explicit browser-level file-access approval. | Switching to `all-sites` initiates a user-gesture request for broad host permissions. **If denied or cancelled by the user**, the extension immediately restores the exact previous mode (e.g. `per-site` or `off`), restores the UI selection, and explains what remains observable. |
| `off` | **Completely inactive:** Zero navigation capture, zero API capture, zero cookie correlation, zero page-signal script injection, and universal badge clearing (`''`) across all tabs. | Options and Popup provide two distinct actions:<br>1. **Pause Monitoring:** Halts all capture while preserving existing host permission grants.<br>2. **Pause and Revoke Access:** Halts all capture and explicitly revokes all optional host grants via `chrome.permissions.remove()`.<br>The UI must never claim permissions are revoked when capture is merely paused. |

### 2.1 Complete Definition of All-Sites & Incomplete Broad Grants

1. **Complete Coverage Definition:** "All-sites" mode is defined as coverage across **all supported web schemes and hosts** (`http://*` and `https://*`, or `<all_urls>`).
2. **Incomplete Broad Grants:** If the browser host permissions contain only a partial broad pattern (e.g. `https://*/*` is granted but `http://*/*` is absent), the permission state is classified as **incomplete**. The extension must not treat an incomplete broad pattern as satisfying the "All-sites" requirement.
3. **No Silent Fallback:** Incomplete broad coverage is handled identically to missing broad coverage: capture pauses, the UI displays an incomplete coverage warning, and the user is prompted to complete the grant or switch modes.

### 2.2 External Revocation & "Paused — All-Sites Permission Missing"

If broad host permission (`<all_urls>` or `*://*/*`) is removed or reduced externally (for example, via the browser's extension management settings or enterprise policy):
1. **Transition to Paused State:** The runtime monitoring state immediately transitions to **"Paused — All-sites permission missing"**.
2. **Strict Prohibition of Silent Degradation:** The capture engine **must never** silently degrade to monitoring individual origins that happen to have residual narrow grants. If `monitoringMode === 'all-sites'` and broad coverage is missing, all capture is paused regardless of any narrow origin grants present in the permission store.
3. **No Automatic Prompts:** The extension must **not** automatically trigger permission prompts upon detecting external revocation. Restoring access requires an explicit user gesture.
4. **User-Gesture Recovery Actions:** The UI must display two explicit actions:
   - **"Restore All-sites access":** Initiates a user-gesture `chrome.permissions.request({ origins: ['<all_urls>'] })`.
   - **"Switch to per-site":** Explicitly changes `monitoringMode` to `per-site`, activating monitoring only for origins with verified narrow grants.
5. **UI Separation of Intent vs. Coverage:** The user interface must distinctly represent **selected intent** (e.g., `all-sites` selected in settings) from **actual host access state** (e.g., `missing` / `paused`).

### 2.3 Broad Grant Conflict Handling in Per-Site Mode

If `monitoringMode` is configured to `per-site` but a broad grant (`<all_urls>` or `*://*/*`) is currently active in the browser's permission store:
1. **Gating Resolution:** Capture is immediately paused with reason `broad-access-conflict`. This guarantees that unconsented origins are never captured when the user intended per-site restriction.
2. **Display Warning:** Options and Popup display an explicit notice: *"Broad access is active"*.
3. **Remediation Actions:** The user is provided two one-click remediation actions:
   - **"Remove broad access":** Invokes `PermissionsService.removeAllBroadGrants()` and verifies removal before updating the UI.
   - **"Switch to All sites":** Updates `monitoringMode` to `all-sites`.
4. **Mode Switching Safety:** Switching from `all-sites` to `per-site` must explicitly prompt the user to revoke the active broad grant.

### 2.4 Off Mode & Universal Action Badge Clearing

1. **Synchronous Gate Flip:** Upon transitioning to `off`, the background service worker synchronously flips the shared capture gate to closed before any asynchronous cleanup begins.
2. **In-Flight and Session Purge:** In-flight request metadata (`inFlightRequests`), partial capture maps (`captureMap`), active tab states (`tabStates`), session storage records (`chrome.storage.session`), and pending page-signal receipts are immediately cleared.
3. **Universal Action Badge Clearing:** The action badge must be cleared (`chrome.action.setBadgeText({ tabId, text: '' })`) across **all open browser tabs**. This includes tabs that do not have an active `TabState` record in memory (such as unmonitored tabs, restricted browser tabs, or tabs displaying a `'?'` badge due to prior conflicts). The extension enumerates active tabs or tracks badge assignments to guarantee zero lingering badges.
4. **UI Notification:** Open popup and side panel ports receive an immediate empty-state broadcast.

### 2.5 Reload-Required Grants & Post-Grant Lifecycle

When a user grants host permissions for a tab that is already open and currently unmonitored:

1. **Non-Retroactive WebRequest Observation:**
   - The browser's WebRequest API (`chrome.webRequest`) operates strictly as an in-flight network tap. It **cannot retroactively observe HTTP response headers, status codes, redirect hops, or transport security attributes** for document navigations that completed prior to host permission acquisition.
   - Granting host access while viewing an unmonitored page leaves the extension with zero historical response data for that tab.

2. **Mandatory Navigation / Reload Requirement:**
   - To inspect a newly granted site, the tab must perform a fresh network navigation (HTTP GET) so that `onBeforeSendHeaders`, `onHeadersReceived`, and `onResponseStarted` events can be intercepted by active WebRequest listeners.
   - A full tab reload is required to capture:
     * Main frame HTTP response headers (HSTS, CSP, X-Frame-Options, Cache-Control, Server, etc.).
     * Pre-navigation redirect hops (e.g. HTTP-to-HTTPS upgrades, canonical domain redirects).
     * Set-Cookie response directives and initial cookie state.

3. **Automated Popup Reload Workflow:**
   - When the user clicks "Monitor this site" in the Popup and `chrome.permissions.request({ origins: [...] })` succeeds (`granted === true`):
     * The popup updates its interface to an immediate waiting state: *"Permission granted. Refreshing this page to begin monitoring…"*.
     * The popup triggers an automated reload of the active tab: `chrome.tabs.reload(currentTabId, {}, callback)`.
     * Upon reload, standard navigation listeners capture the incoming response hops, the per-tab reducer populates `TabState`, the rules engine computes security findings, and the action badge updates to a letter grade (`A`–`F`).

4. **Fallback & Error Handling for Blocked / Deferred Reloads:**
   - If `chrome.tabs.reload` produces an error (e.g. `chrome.runtime.lastError != null`, tab discarded, or browser navigation policy block):
     * The popup surfaces a clear fallback notice: *"Permission was granted, but this page could not be refreshed. Reload it to begin monitoring."*.
     * The action badge remains `'?'` (pending reload / scanning state) until navigation occurs.

5. **External Grant Handling (Options Page / Management UI):**
   - If an origin grant is added externally (e.g. from the Options page or browser settings) while an existing tab for that origin is open:
     * `permissions.onAdded` updates the central capture policy snapshot immediately.
     * The open tab's `TabState` remains unmonitored or pending reload.
     * The action badge for that tab remains `'?'` until the tab navigates or is reloaded by the user.

6. **Strict Prohibition of Synthetic Out-of-Band Probes:**
   - Under Invariant 4 (Passive Observation Only), the extension is **strictly forbidden** from dispatching synthetic `fetch()` or `XMLHttpRequest` probe requests in the background or content script to retrieve past headers. All header evidence must originate exclusively from genuine user- or browser-initiated navigations.

7. **Rule Engine & Page Signal Decoupling on Un-Reloaded Tabs:**
   - Page signals (Meta-CSP, SRI) injected by content scripts on an un-reloaded tab cannot produce a valid security grade in the absence of main frame response headers.
   - The rule engine requires at least one valid top-level response hop before evaluating composite grades. If page signals arrive for a tab with zero recorded main frame hops, they are buffered without triggering a premature, false-failing evaluation (preventing false 'F' grades caused by unobserved headers).

### 2.6 Third-Party Visibility & Subresource Boundary Contract

Monitored web pages frequently trigger cross-origin subresources (e.g. API requests, third-party authentication, telemetry endpoints). Capture and visibility for these subresources are strictly gated:

1. **Boundary Gating in `per-site` Mode:**
   - In `per-site` mode, permission is granted only for explicit origin patterns (e.g. `https://example.com/*`).
   - The synchronous boundary pre-filter (`isCaptureAllowedAtBoundary`) evaluates the **destination URL origin** (`extractOrigin(request.url)`), not merely the initiating tab's top-level URL.
   - If a subresource (XHR or `fetch`) is initiated to a third-party origin not present in `snapshot.grantedOrigins` (e.g. `https://api.thirdparty.com` called from `https://example.com`):
     * The request is dropped at the listener boundary before creating entries in `captureMap` or storing metadata in `inFlightRequests`.
     * Zero request headers, response headers, or cookies from the unconsented origin are processed or stored.
     * The request is recorded in the tab's `CoverageLedger` as an unobservable blind spot with reason `'third-party-blocked'`.
     * This guarantees that narrow per-site consent is never used to passively inspect unconsented third-party services.

2. **Boundary Gating in `all-sites` Mode:**
   - In `all-sites` mode with a verified broad grant (`<all_urls>` active), third-party subresources directed to supported web schemes (`http://*`, `https://*`) are captured under the broad grant authority.
   - Subresources identified as API requests (XHR/fetch) are analyzed for endpoint security controls (CORS configuration, transport security, authentication header presence without secret values) and stored in `state.apiEndpoints` (bounded to 50 entries).
   - Static non-API subresources (images, stylesheets, fonts, media, and third-party iframe document navigations) remain ignored and excluded from API capture to preserve memory bounds.

3. **Third-Party Cookie Correlation Rules:**
   - Cookies observed in the context of a tab:
     * Third-party status is derived directly from hop `Set-Cookie` headers: the setting host (from the response URL) or the `Domain` attribute is compared against the page's registrable domain (eTLD+1). When a third-party cookie is set by a subresource/hop, it is recorded as a third-party `CookieRecord` from the header metadata even though Chrome's URL-scoped cookie query (`chrome.cookies.getAll({ url: tabUrl })`) restricts live results to the page origin.
     * For cookies present in the live store, a cookie is flagged as third-party (`isThirdParty: true`) if its domain does not match the apex/registrable domain (eTLD+1) of the top-level document URL.
     * Partitioned cookies (CHIPS / Cookies Having Independent Partitioned State) are evaluated based on partition keys and attributes (`Partitioned`, `SameSite=None`, `Secure`).
     * Third-party cookies are represented in findings and attack-surface trust graphs to identify cross-site tracking and authentication exposure.
     * **Zero Secret Value Retention:** Consistent with Invariant 1, third-party cookie values are never inspected, stored, or transmitted; only cookie name, domain, path, expiry, security attributes (`Secure`, `HttpOnly`, `SameSite`, `Partitioned`), and third-party flags are correlated.

4. **Blind Spot Reporting in UI & Exports:**
   - Third-party endpoints blocked in `per-site` mode are surfaced distinctly in the Popup, Side Panel, and export artifacts (JSON, SARIF) under the Coverage Ledger.
   - The UI makes it transparent that these endpoints were omitted due to permission boundary gating, preventing users from mistaking unobserved third-party endpoints for passing or failing security controls.

---

## 3. Synchronous Capture-Policy Snapshot & Gating Architecture

### 3.1 Synchronous Immutable Policy Snapshot

Because WebRequest listener callbacks cannot synchronously await asynchronous browser permission APIs (`chrome.permissions.getAll()` / `chrome.permissions.contains()`), and cannot block or modify network traffic, capture decisions must rely on a **central synchronous immutable policy snapshot**.

```typescript
export interface CapturePolicySnapshot {
  readonly ready: boolean;
  readonly revision: number;
  readonly mode: MonitoringMode;
  readonly broadGrantActive: boolean;
  readonly grantedOrigins: ReadonlySet<string>;
}
```

#### Snapshot Lifecycle & Invariants:
1. **Fail-Closed Prior to Hydration:** At service worker startup, prior to completing initial storage and permission reads, the snapshot exists in an unhydrated state (`ready === false`). All WebRequest listeners fail closed immediately when `ready === false`, dropping capture before allocating any metadata.
2. **Hydration & Monotonic Revision:** The snapshot is hydrated from `SettingsService` and `chrome.permissions.getAll()` during worker initialization. Each update increments a monotonic `revision: number`. Asynchronous refreshes with an older revision cannot overwrite a newer snapshot.
3. **Idempotent Refresh Triggers:** The snapshot is refreshed on:
   - `SettingsService` settings update events.
   - `chrome.permissions.onAdded` and `chrome.permissions.onRemoved` browser events.
   - Extension startup reconciliation.
4. **Scheme Conservatism:** Broad patterns are evaluated conservatively by scheme. A grant for `https://*/*` does not grant `http://*/*`. Exact `per-site` checks verify that the normalized request origin exists within `snapshot.grantedOrigins`.

### 3.2 Listener Boundary Gating (Pre-filtering)

The capture-policy snapshot is evaluated at the **earliest listener boundary** (`chrome.webRequest.onBeforeSendHeaders`, `onHeadersReceived`, `onResponseStarted`, `onBeforeRedirect`):

```typescript
export function isCaptureAllowedAtBoundary(
  url: string,
  snapshot: CapturePolicySnapshot
): boolean {
  if (!snapshot.ready) return false;
  if (!url || isRestrictedUrl(url)) return false;
  if (snapshot.mode === 'off') return false;
  if (snapshot.mode === 'per-site') {
    if (snapshot.broadGrantActive) return false; // Broad conflict
    const origin = extractOrigin(url);
    return origin !== null && snapshot.grantedOrigins.has(origin);
  }
  if (snapshot.mode === 'all-sites') {
    return snapshot.broadGrantActive; // Fail-closed if broad grant missing
  }
  return false;
}
```

#### Strict Pre-filtering Invariant:
No `captureMap` entries may be created, no `inFlightRequests` metadata stored, no response headers normalized, and no cookie correlation initiated unless `isCaptureAllowedAtBoundary` returns `true`. The subsequent asynchronous `CapturePolicy.evaluate(url)` check remains in place as defense in depth.

### 3.3 Gating Scope: Analysis vs. Cleanup Operations

| Operation Category | Scope | Behavior When Capture Is Denied / Paused / Off |
| :--- | :--- | :--- |
| **Gated (Analysis)** | `onHeadersReceived` / `onResponseStarted` hop building, rule engine execution, score calculation, cookie jar correlation, API endpoint recording, page-signal script injection, action badge updates. | **Halted:** Dropped immediately at listener boundary; zero processing, zero storage allocation. |
| **Ungated (Cleanup)** | `onCompleted`, `onErrorOccurred`, `onBeforeRedirect` map housekeeping, tab closure (`tabs.onRemoved`), permission revocation (`permissions.onRemoved`), scheduled retention sweeps. | **Always Executed:** Runs unconditionally to ensure maps, timers, and storage structures do not leak or grow unbounded. |

### 3.4 Page-Signal Startup Hydration Barrier

1. **Hydration Barrier:** Content script injection (`injectPageSignals(tabId, url)`) must await the readiness of `SettingsService` and `PermissionsService` before evaluating injection eligibility. It must **not** abort immediately on an unhydrated synchronous cache.
2. **Re-Verification on Readiness:** Once the startup promise resolves, the handler re-verifies the tab's current URL, monitoring mode, broad conflict status, and origin permissions. If the tab has navigated or permissions are absent, injection is cleanly aborted.
3. **No Lost First Navigation:** This barrier guarantees that the initial page navigation immediately following service worker revival is inspected once settings are ready, eliminating startup signal drops.

### 3.5 Throttled SRI & Meta-CSP DOM Observer Contract

Content scripts injected into monitored web pages must adhere to strict performance and deduplication boundaries:

1. **Meta-CSP Observation:** The mutation observer for Meta-CSP is strictly scoped to the document `<head>` and monitors only `<meta http-equiv>` attributes. The observer is disconnected upon page unload.
2. **Throttled SRI Observation:**
   - **Targeting:** Observes only `SCRIPT` and `LINK` elements, with attribute filters restricted to `src`, `integrity`, `href`, and `rel`.
   - **Rate Limiting:** DOM mutations are coalesced to at most **one scan per 250 milliseconds** (debounced/throttled).
   - **Payload Deduplication:** The content script calculates a cryptographic or structural signature of the extracted scripts and links. It transmits `SRI_SCAN` messages to the service worker **only when the observed evidence has changed**.
3. **Background Invariance:** The service worker verifies incoming page-signal payloads against the existing `TabState`. Identical payloads result in zero rule re-runs, zero storage writes, and zero UI broadcasts.

---

## 4. Atomic Settings Transitions & Re-Scoring Lifecycle

### 4.1 Single Atomic Transition Pipeline via `lastAppliedSettings`

To eliminate race conditions between `chrome.storage.onChanged` events and runtime `SETTINGS_CHANGED` messages, all configuration changes pass through a single serialized transition pipeline:

```typescript
export class SettingsTransitionPipeline {
  private lastAppliedSettings: SettingsV2;

  public async transition(
    incoming: SettingsV2,
    source: 'storage' | 'message'
  ): Promise<void>;
}
```

#### Transition Algorithm:
1. **Validation & Version Check:** The incoming payload is validated against `SettingsV2` schema rules. Unknown schema versions (`schemaVersion > 2`) are preserved intact and read-only without modification.
2. **Deduplication:** The incoming settings are compared against `lastAppliedSettings`. If identical in revision and content, the transition terminates immediately without side effects.
3. **Delta Detection:** Differences are identified across:
   - `monitoringMode`: Triggers capture-policy snapshot refresh and mode side effects (such as Off cleanup).
   - `sensitiveCookieNames` / `ignoredCookieNames`: Flags the need for immediate tab re-scoring.
   - `severityFilter`: Affects UI presentation only; zero rule or scoring side effects.
   - `retainHistoryDays` / `maxHistoryPerOrigin`: Schedules storage pruning maintenance.
   - `evaluationMode`: Updates graph discovery and export flags.
4. **Execution of Side Effects:** Required side effects execute in a deterministic order.
5. **Atomic Publication:** The new configuration is committed to `lastAppliedSettings`, the capture snapshot is refreshed, and the updated state is broadcast once.

### 4.2 Storage vs. Message Race Resolution

- Runtime `SETTINGS_CHANGED` messages are treated as lightweight notifications, **not** as an independent source of truth.
- If `storage.onChanged` arrives before the message: the pipeline applies the change from storage; the subsequent message is recognized as identical to `lastAppliedSettings` and safely dropped.
- If `SETTINGS_CHANGED` arrives before the storage event: the pipeline executes the transition; the subsequent storage event matches `lastAppliedSettings` and is deduplicated.
- `currentSettings` is **never mutated directly in an event listener** prior to comparative delta evaluation.

### 4.3 Immediate Tab Re-Scoring on Cookie List Mutation

When the user updates custom cookie classifications (`sensitiveCookieNames` or `ignoredCookieNames`):
1. **Immediate Evaluation:** The background service worker immediately re-evaluates rules (`recomputeTabState`) for **all active tabs** currently tracked in `tabStates`.
2. **Sanitized Persistence:** Updated `TabState` records with recomputed findings, scores, and grades are written to `chrome.storage.session`.
3. **State Broadcast:** Connected popup and side panel ports receive updated `TAB_STATE_UPDATE` messages, reflecting the updated security posture instantly without requiring tab reloads.

### 4.4 Schema Version Preservation & Backward/Forward Compatibility

1. **Current Schema:** All settings adhere to `SettingsV2` (`schemaVersion: 2`).
2. **Future Schema Protection:** If the extension encounters `schemaVersion > 2` in storage:
   - The settings envelope must be preserved read-only.
   - The extension must **never** downgrade, overwrite, or sanitize unrecognized future schema fields.
   - The UI surfaces an explicit *"Unsupported configuration version"* state.
3. **Deprecation of Legacy Fields:** Legacy fields (such as `allowedOrigins`) are permanently decoupled from runtime permissions and ignored.

---

## 5. End-to-End Runtime Data & Control Flow

### 5.1 Architecture & Pipeline Diagram

```
+----------------------------------------+       +------------------------------------+
|         Browser WebRequest APIs        |       |    Content Script / Page Signals   |
| (onBeforeSendHeaders, onHeadersRecv,   |       |  (Meta-CSP Observer, SRI Scanner   |
|  onResponseStarted, onBeforeRedirect)  |       |   DOM Mutation Throttled <= 250ms) |
+----------------------------------------+       +------------------------------------+
                    |                                              |
                    v                                              |
+----------------------------------------+                         |
|        [ 1. Boundary Pre-Filter ]      |                         |
| Synchronous Immutable Capture Policy   |                         |
| Snapshot (Fail-Closed, Scheme-Checked) |                         |
+----------------------------------------+                         |
                    | (Allowed)                                    |
                    v                                              |
+------------------------------------------------------------------+
|                      [ 2. Per-Tab Reducer ]                      |
| - Accumulate Hops (Main Frame & Redirect Chains)                 |
| - Correlate Cookies (Redacted Values, Third-Party Flagging)      |
| - Process First-Party API Endpoints (Bounded <= 50)              |
| - Ingest Page Signals & Update Coverage Ledger                   |
+------------------------------------------------------------------+
                    |
                    v
+------------------------------------------------------------------+
|                    [ 3. Deterministic Rules ]                    |
| - Engine: HSTS, CSP, XFO, Cookies, Isolation, CORS, SRI, Redir   |
| - Scoring: weights.json, Caps, Dedupe, Grades (A-F)              |
+------------------------------------------------------------------+
                    |
                    v
+------------------------------------------------------------------+
|                  [ 4. Storage & Persistence ]                    |
| - Session Storage: tab:${tabId}, auth_baseline, incognito session|
| - Local Storage: history:${origin}, graph:${apex}, auth_diff     |
|   (Strictly Sanitized, Zero Secrets, Age/Count Pruning)          |
+------------------------------------------------------------------+
                    |
        +-----------+-----------+
        |                       |
        v                       v
+----------------+  +-----------------------------------------------------+
| [ 5. Action    |  |     [ 6. PortRegistry Broadcast & UI Layer ]        |
|      Badge ]   |  | - Popup (Shield, Findings, Details, Remediation)    |
| - Grade (A-F)  |  | - Side Panel (D3 Graph, Topology, Endpoints)        |
| - '?' (Pending/|  | - Options (Permissions, Settings, History, Purge)   |
|   Conflict)    |  +-----------------------------------------------------+
| - '' (Off/Clr) |                             |
+----------------+                             v
                    +-----------------------------------------------------+
                    |                   UI Export Sinks                   |
                    | - JSON Download                                     |
                    | - Markdown Clipboard Copy                           |
                    | - SARIF Export (Sanitized Security Audit)           |
                    +-----------------------------------------------------+


+-------------------------------------------------------------------------+
|                  [ 7. Standalone CLI (Independent Tool) ]               |
|                                                                         |
|  Independent Inputs:                                                    |
|  - Target URL:        `aculyx --url <url>` (Explicit Network Fetch)     |
|  - Offline HAR:       `aculyx --har <path.har>`                         |
|  - Raw JSON Input:    `aculyx --input <path.json>`                      |
|                                                                         |
|                                   |                                     |
|                                   v                                     |
|  [ Shared Deterministic Rules Engine (src/rules/) & Scoring Weights ]   |
|                                                                         |
|                                   |                                     |
|                                   v                                     |
|  CLI Outputs & Export Sinks:                                            |
|  - Terminal Formatted Console Summary & Tables                          |
|  - SARIF Report (`--sarif`)                                             |
|  - JSON Data Export (`--json`)                                          |
|  - Markdown Audit Report (`--markdown`)                                 |
|  - User Baselines Regression Diff (`--diff <baseline.json>`)            |
+-------------------------------------------------------------------------+
```

### 5.2 Component Responsibilities & State Boundaries

1. **`src/background/capture.ts`:** Listens to WebRequest events. Executes synchronous boundary pre-filtering via the capture snapshot. Manages bounded `inFlightRequests` and `captureMap` structures. Dispatches hops to index reducer.
2. **`src/background/capture-policy.ts`:** Manages the central `CapturePolicySnapshot`. Interfaces with `PermissionsService` and `SettingsService` to maintain immutable snapshot revisions.
3. **`src/background/index.ts`:** Central tab reducer and event coordinator. Maintains `tabStates`, orchestrates cookie correlation, processes API hops, ingests page signals, executes re-scoring, writes to storage, and broadcasts updates.
4. **`src/rules/engine.ts` & `src/rules/scoring.ts`:** Pure, deterministic security evaluation. Calculates penalties, applies category deduplication, computes grades, and generates advisory quality scores.
5. **`src/shared/storage.ts`:** Encapsulates `SessionStorage` and `LocalStorage`. Enforces zero-secret assertions, history retention limits, and origin data purging.
6. **`src/shared/messaging.ts`:** Manages typed port connections and broadcast distribution for popup and side panel interfaces.
7. **`src/popup/` & `src/sidepanel/`:** User interface presentation layers. Consume `TabState` and graph structures; enforce presentation filters without mutating underlying data.
8. **`src/cli.ts`:** Independent command-line security auditor. Reuses core rule logic and fix catalogs; operates on explicit user target URLs or HAR archives.

### 5.3 Bounded Data Structures & Eviction Invariants

All in-memory and persistent data structures must remain strictly bounded:
- `inFlightRequests` Map: Bounded to a maximum of **100 entries**. Evicted on response, error, or 60-second TTL timeout.
- `captureMap` Map: Bounded to active request IDs. Cleaned on request completion, navigation, or tab closure.
- `tabStates` Map: Bounded to active browser tab IDs. Evicted immediately upon `tabs.onRemoved` or `clearTabCapture`.
- `apiEndpoints` Array: Bounded to a maximum of **50 entries** per tab.
- `coverageLedger` Array: Bounded to a maximum of **50 entries** per tab.
- `history:${origin}` Storage: Bounded by `retainHistoryDays` (0..365) and clamped to `maxHistoryPerOrigin` (1..50, default 10).
- `graph:${apex}` Storage: Bounded to unique discovered hostnames per apex domain.

---

## 6. Full Mode × Browser Permission × Event Path Matrix

| Mode | Browser Host Permission State | Event Path | Expected Capture Behavior | Badge State | UI State & Notice |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `per-site` | Exact origin granted (e.g. `https://example.com/*`), no broad grant | Top-level navigation (`main_frame`) | Capture full hops, correlate cookies, run rules, update history & graph | Security Grade (`A`–`F`) | Monitored: score shield, findings list, "Stop monitoring" action |
| `per-site` | Exact origin granted, no broad grant | First-party XHR/Fetch API call | Capture `ApiHop`, run API rules, record in `state.apiEndpoints`, ledger entry | Unchanged | API section populated; does not modify base security grade |
| `per-site` | Exact origin granted, no broad grant | Cross-origin third-party API call (destination origin unpermitted) | Destination origin checked at boundary pre-filter; dropped before `inFlightRequests` allocation; recorded in `CoverageLedger` with reason `'third-party-blocked'` | Unchanged | Third-party endpoint listed as unobservable blind spot (permission boundary) |
| `per-site` | Exact origin granted, no broad grant | Redirect chain (e.g. 302 -> 200) | Capture intermediate hops, detect header drops (`REDIR-001`), evaluate final hop | Final Grade | Coverage bar reflects captured vs expected hops (e.g. 2/2) |
| `per-site` | Exact origin granted, no broad grant | DOM mutation (SPA / script tag) | Content script evaluates readiness, executes SRI scan; throttled <= 1/250ms | Unchanged | Updated SRI / Meta-CSP findings if evidence changed |
| `per-site` | Origin granted for currently loaded unmonitored tab | User grants permission in prompt ("Monitor this site") | Non-retroactive: headers cannot be observed retroactively. Popup attempts programmatic reload (`chrome.tabs.reload(currentTabId)`). Upon reload, navigation capture begins; page signals buffered until navigation | `'?'` (pending reload) &rarr; Grade (`A`–`F`) on reload | "Permission granted. Refreshing this page to begin monitoring…" (or prompt to reload manually if reload blocked) |
| `per-site` | Origin NOT granted, no broad grant | Navigation / API / Signals | Listener snapshot drops request; zero headers in `captureMap`; no script injection | `'?'` | "Permission required", "Monitor this site" action |
| `per-site` | Broad grant active (`<all_urls>` or `*://*/*`) | Any event | **Paused (Conflict):** Zero capture, zero API storage, zero script injection | `'?'` | "Broad access is active", conflict remediation actions |
| `per-site` | Origin revoked via browser settings | `permissions.onRemoved` | `clearTabCapture()`: evict memory, delete session storage, broadcast empty state | `''` (cleared) | State cleared, returns to unmonitored view |
| `all-sites` | Full broad grant active (`<all_urls>`) | Navigation / API / Signals | Full capture across all valid `http:` and `https:` origins, including third-party APIs | Security Grade (`A`–`F`) | Monitored across all sites |
| `all-sites` | Broad grant missing or revoked externally | Any event | **Paused (Missing Access):** Zero capture; **never** degrades to per-site narrow grants | `'?'` | "Paused — All-sites permission missing", "Restore access" action |
| `all-sites` | Incomplete broad grant (e.g. `https://*/*` only) | Any event | Treated as missing broad permission: zero capture | `'?'` | Notice: incomplete broad coverage |
| `all-sites -> per-site` | Broad grant active (`<all_urls>` or `*://*/*`) | Mode transition in Settings | Capture immediately paused with `broad-access-conflict`; in-flight requests cleared; existing history/graph preserved | `'?'` | "Broad access is active — conflict detected"; prompt: "Remove broad access" or "Switch to All sites" |
| `per-site -> all-sites` | User cancels / denies browser permission prompt | Mode selection click in Settings / Popup | Request denied; atomically rolls back mode to `per-site`; zero broad state applied; prior monitoring continues | Unchanged (Grade or `'?'`) | Reverts selection to `per-site`; displays notice: permission denied/cancelled |
| `off` | Any browser permission state | Top-level navigation | Zero capture: dropped at listener boundary before `captureMap` allocation | `''` (cleared) | "Monitoring is turned off in Settings" |
| `off` | Any browser permission state | API / XHR request | Zero capture: dropped before `inFlightRequests` allocation | `''` (cleared) | Inactive |
| `off` | Any browser permission state | Page-signal injection event | Script injection blocked immediately | `''` (cleared) | Inactive |
| `off` | Any browser permission state | Mode transition to Off | Synchronous gate flip; in-flight maps cleared; session storage cleared; universal badge clear | `''` (all tabs) | Popup and side panel notified of empty state |
| Any | Any | WebRequest arrives during worker startup before hydration (`ready === false`) | Synchronous boundary pre-filter drops request fail-closed; zero metadata allocated in `captureMap` or `inFlightRequests` | Unchanged | Temporary worker startup state; no unverified capture |
| Any | Any | Restricted URL (`chrome://`, Add-ons Store) | Blocked immediately by `isRestrictedUrl`; zero capture | `'?'` | "Restricted page — browser pages cannot be inspected" |
| Any | Any | Tab closure (`tabs.onRemoved`) | `tabStates.delete(tabId)`, `SessionStorage.removeTabState(tabId)`, pending receipts purged | N/A | Ports disconnected |
| Any | Any | Service worker startup / revival | Hydrate snapshot & state from storage; run permission reconciliation; evict dead tabs | Restored | UI connects and receives restored state immediately |

---

## 7. Private Browsing & Incognito Isolation Contract

### 7.1 Ephemeral Session Namespace & Zero Persistence Invariant

1. **Strict Storage Isolation:** Incognito and private browsing tabs operate exclusively within an ephemeral, session-scoped namespace (`chrome.storage.session` and in-memory maps tagged with `isIncognito: true`).
2. **Zero Persistent Writes:** Private browsing observations **must never** enter `chrome.storage.local`.
   - **No Origin History:** `LocalStorage.recordOriginHistory` is completely bypassed for incognito tabs.
   - **No Graph Accumulation:** `LocalStorage.saveGraph` is completely bypassed. Discovered nodes are discarded or held only in ephemeral memory.
   - **No Auth Baselines or Diffs:** `LocalStorage.recordAuthDiff` is completely bypassed.
   - **No Diagnostic Logs:** Incognito URLs, hosts, and timestamps must never appear in persistent diagnostic stores.
3. **Export Tagging:** Any manual export initiated from an incognito tab is clearly stamped in its metadata as an ephemeral session export and contains zero historical trend data.

### 7.2 Lifecycle Teardown

When the last incognito tab or window is closed:
1. All in-memory `TabState` records, partial captures, and page-signal receipts associated with incognito tabs are permanently destroyed.
2. All session storage entries for incognito tabs are removed.
3. No persistent artifacts remain on disk.

### 7.3 Secret Canary Verification

The test harness must maintain synthetic canary tests verifying that sensitive tokens and origin identifiers originating in incognito contexts never escape into `chrome.storage.local`, persistent files, error logs, or export bundles.

---

## 8. Finding Model: Provenance, Confidence, Applicability, and Coverage

### 8.1 Evidence Provenance

Every security finding records its **evidence provenance** to distinguish observed network facts from DOM signals and offline imports:

```typescript
export type EvidenceProvenance =
  | 'response-header'  // Observed on main frame or API response headers
  | 'redirect-hop'      // Observed across an intermediate redirect transition
  | 'cookie-metadata'   // Extracted from Set-Cookie and Cookie Jar metadata
  | 'dom-signal'        // Injected DOM signal (Meta-CSP, SRI hash/script presence)
  | 'har-import'        // Parsed from offline HAR archive
  | 'cli-fetch';        // Direct HTTP request initiated by CLI
```

### 8.2 Confidence Classifications

Findings are categorized by confidence:
- **`deterministic`:** Direct, incontrovertible syntactic observation (e.g. missing `Strict-Transport-Security` header, invalid `SameSite` attribute, unpinned SRI hash).
- **`heuristic`:** Inferred or advisory observation (e.g. server banner heuristics, potential framework version classification, advisory quality metrics).

### 8.3 Applicability & Outcome Semantics

Every evaluated security rule produces an explicit outcome:
- **`violation`:** The check failed; a security deficiency was identified and a score penalty is applied.
- **`pass`:** The recommended security control is present and correctly configured; zero penalty applied.
- **`not-observed`:** The security control could not be inspected due to environmental or permission constraints (e.g., third-party subresource headers omitted by browser CORS policies, or missing intermediate redirect hops). **`not-observed` is never scored as a pass or a failure.**
- **`not-applicable`:** The check is irrelevant to the evaluated context (e.g., HSTS checks on plain `http://` navigation, or cookie attribute checks on responses without `Set-Cookie` headers).

### 8.4 Coverage & Blind Spot Semantics

- **Coverage Ledger:** Every `TabState` maintains a bounded `CoverageLedger` recording expected vs. captured hops, API subresources, and unobservable endpoints.
- **Explicit Blind Spots:** Any limitation in observation must be classified with an explicit reason (`third-party-blocked`, `incomplete-redirect-chain`, `opaque-response`, `permission-restricted`) and displayed distinctly in the UI.

### 8.5 Score Weight Stability Invariant

- Confidence, applicability, and coverage flags **must not** be multiplied or factored into base rule penalty weights.
- Security scores are computed deterministically from `src/rules/weights.json` penalty definitions, ensuring stable, explainable, and reproducible audit scores across all runs.

---

## 9. Developer Evaluation Mode & UI Terminology Contract

### 9.1 Elimination of Commercial Branding

1. **Prohibited Terminology:** The terms "Pro", "Free Tier", "Upgrade to Pro", "Pro License", and "isPro" are strictly forbidden across all extension surfaces, code symbols, messages, and HTML templates.
2. **Standard Terminology:** All surfaces must use "Developer Evaluation Mode", "Standard Mode", or "Evaluation Features".

### 9.2 Developer Evaluation Mode Contract

Developer Evaluation Mode (`SettingsV2.evaluationMode: boolean`, default `false`) is a local developer convenience flag located under "Developer Settings (Evaluation Mode)" in the Options page.

#### Functional Scope:
- **Enabled (`true`):** Activates multi-origin attack surface graph visualization (visualizing nodes beyond the immediate apex domain) and enables advanced diagnostic export options.
- **Disabled (`false`):** Restricts the attack surface graph to the immediate domain and its directly observed first-party subdomains.

#### Strict Behavioral Invariants:
1. `evaluationMode` **never** weakens, disables, or modifies any security rule or penalty calculation.
2. `evaluationMode` **never** bypasses host permission gating, consent checks, or capture policies.
3. Security scores, grades, findings, and remediation advice are **100% identical** regardless of whether `evaluationMode` is `true` or `false`.

---

## 10. Data Retention, Purge, and Revocation Lifecycle

### 10.1 Historical Domain Scores & Retention Pruning

Historical security audit scores are stored in `chrome.storage.local` under `history:${origin}`:
- **`retainHistoryDays`:**
  - `0`: Keep forever (age pruning disabled).
  - `1..365`: Entries older than $N \times 86,400 \times 1,000$ milliseconds are pruned.
- **`maxHistoryPerOrigin`:**
  - Default: `10` entries.
  - Permitted range: `1..50` entries.
- **Pruning Precedence:** Age pruning (`retainHistoryDays`) is applied first. The count cap (`maxHistoryPerOrigin`) is applied second, slicing the remaining entries to the newest $N$ items.
- **Execution Schedule:** Pruning runs at service worker startup and periodically via a 1-minute browser alarm (`chrome.alarms`).

### 10.2 Origin Purge vs. Permission Revocation Distinction

| Action | User Intent | Effect on Active State | Effect on Historical Data |
| :--- | :--- | :--- | :--- |
| **Stop Monitoring / Revoke Permission** | Cease active inspection of origin | Evicts active tab state, clears session storage, clears action badge (`''`). | **Preserved:** Historical score trends (`history:${origin}`) and attack surface graph nodes (`graph:${apex}`) remain intact to prevent accidental loss of audit history. |
| **Delete Stored Data (Purge)** | Explicitly erase historical audit records | Active tab state is refreshed/re-initialized. | **Purged:** Completely removes `history:${origin}`, `auth_diff:${origin}`, and associated graph nodes from local storage. |

### 10.3 Scheduled Maintenance Sweeps

The background service worker registers a periodic maintenance alarm (`MAINTENANCE_ALARM`):
1. **Frequency:** Runs every 1 minute when the service worker is active.
2. **Operations:**
   - Executes `LocalStorage.pruneAllHistory()`.
   - Cleans orphaned in-flight request entries older than 60 seconds.
   - Cleans stale session auth baselines whose tabs are no longer open.
3. **Failure Resilience:** Storage quota errors or write rejections during maintenance sweeps must be caught, surfaced as a visible degraded-storage status in Options, and never crash the service worker.
