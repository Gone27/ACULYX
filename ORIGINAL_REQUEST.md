# Original User Request

## 2026-10-02T08:09:12Z

Execute the complete SecCheck master roadmap and implementation plan across workstreams WS0 through WS7 on the local-first Manifest V3 browser extension repository.

Working directory: D:\Projects\header-cookie-security-checker
Integrity mode: development

---

# SecCheck Master Roadmap & Implementation Prompt

**Updated for:** `Gone27/Cookie-and-header-reader-extention`, `main` at `e1392c0ab1f4781b451e46a366d5f25d4b9dbf4f` (2026-10-02). Re-fetch `origin/main` before implementation; if it has moved, inspect and summarize the new diff before relying on this snapshot.

> **North star:** make SecCheck feel dependable and integrated: every visible setting and feature behaves consistently across the extension; capture is strictly consent-gated; the popup, Options and side panel stay responsive without avoidable work; and the interface looks like a polished security tool with a restrained cyber-futuristic character—not a flashy neon demo.

This document is both the roadmap and the coding-agent execution prompt. It does **not** promise software can be made bug-free. The release goal is **zero known P0/P1 issues, no inert or misleading controls, tested recovery from expected failures, and performance measured against agreed scenarios**.

---

## 1. Copy/paste master execution prompt

You are the senior engineer and integration owner for SecCheck, a local-first Manifest V3 browser extension with Chrome and Firefox builds, a separate CLI, header/cookie/API analysis, page signals, history/authentication diffs, an attack-surface graph, a popup, Options page and side panel.

### Work rules

1. **Verify the checkout first.** Fetch `origin/main`; record full commit, branch, `git status`, Node/npm versions, package scripts and current gates. Read the implementation and tests before editing. Verify every path/feature referenced in this roadmap exists; adapt to actual code and report anything absent rather than fabricating it.
2. **Work by workstream, not by individual commit.** Keep related implementation commits together in one reviewable workstream/PR. Run its gates and review the complete workstream before beginning a conflicting one. Do not ask for an extra approval after every commit. Do not start a later workstream if the current one has failing required gates or open P0/P1 defects.
3. **Keep one integration owner.** If using multiple agents, delegate non-overlapping investigations, tests, or UI audits. Do not let agents concurrently edit the capture policy, settings transition path, or the same UI component. The integration owner resolves interfaces and runs the full suite on the combined result.
4. **Do not publish or push** unless the user explicitly asks. Keep changes in the authorized checkout. Report exact commit/branch and whether the worktree is clean or dirty.
5. **No silent behavior changes.** Preserve rule weights, score semantics, permission scope, retained-data policy and CLI behavior unless a roadmap item explicitly changes them. Explain assumptions and add tests for changed behavior.
6. **Measure before optimizing.** Record actual browser/version, OS, test page, counts, timing and bundle size. Treat performance numbers below as initial targets to calibrate, not promises.
7. **Do not claim zero bugs.** Report what was checked, what passed, what was manually verified, and what remains untested.

### Non-negotiable invariants

- Cookie values, authorization credentials, secret header values, request/response bodies, and sensitive URL path/query material must not be persisted, logged, messaged, telemetered or exported. Redact before data enters persistent/shared state; maintain synthetic canary tests across storage, UI messages, diagnostics and exports.
- The extension is passive: it does not send its own probes. CLI URL fetching is a separate, explicit user action.
- Never request broad host permissions without a direct user choice. Never silently widen permissions to improve coverage. Permission API requests must occur directly in a user gesture before awaits or storage work.
- `chrome.permissions.getAll()` and permission events are the authority for grants—not a legacy `allowedOrigins` setting.
- `off` means no new navigation/API/page-signal analysis and no grade badge. Cleanup still runs for requests already in flight, tab closure, revocation and storage maintenance.
- In `per-site`, any conflicting broad grant pauses capture until the user resolves the conflict. Enforce this **before listeners retain response headers or API metadata**, not only before analysis.
- In `all-sites`, missing/incomplete broad permission must be visible as paused/incomplete. Do not silently behave as per-site while the UI claims All-sites. Do not auto-request permission after an external revocation; require an explicit click.
- Severity/display filters never change the underlying score. Evaluation/developer controls never weaken checks or imply a real paid entitlement.
- MV3 workers may stop at any time. Correctness must rely on persistence, event listeners, versioned state and recovery—not a keepalive loop.
- Incognito/private records must never mix into ordinary persistent history, graph, baselines, diagnostics or exports.
- No telemetry, remote code, remote assets, or unsafe dynamic HTML with untrusted values.

---

## 2. Verified starting point and remaining work

At the reviewed `e1392c0` commit, the following passed: typecheck, lint, **234 unit tests**, Chrome build, Firefox build, **8 Playwright E2E tests**, and `npm audit` (**0 vulnerabilities**). CI now runs Chromium E2E. Those are a strong baseline, not proof of correctness in all browser permission and service-worker sequences.

The update fixed important earlier issues: Off-mode state cleanup, future-schema protection, broad-grant removal and reconciliation, and added cookie-list re-scoring. The next work must close these **verified remaining edge cases**:

1. `src/background/capture.ts` currently uses a prefilter that checks Off/restricted URL, but not per-site/broad conflict or exact-origin permission. Full policy is checked later in `index.ts`, after temporary capture-map/request-metadata work.
2. `src/background/capture-policy.ts` allows All-sites to fall through to an individual origin grant when broad access is absent. A synthetic probe showed one site allowed and another denied while All-sites remains selected.
3. Settings storage-change handling updates `currentSettings` separately from the `SETTINGS_CHANGED` message handler. If the storage event arrives first, comparing `previousSettings = currentSettings` to the incoming settings can miss the cookie-list delta and skip re-scoring.
4. Page-signal injection reads a fail-closed cache and returns if settings are still hydrating; it does not queue/retry, so the first page after worker startup can miss signals.
5. Off cleanup clears badges only for IDs in `tabStates`; a `?` badge can be set on a tab without a stored `TabState` and remain visible.
6. Options’ per-origin permission-removal error path can remove a row locally even if browser revocation failed.

Re-confirm every finding against the live checkout before changing code.

---

# 3. Roadmap workstreams

## WS0 — Baseline, architecture map, and behavior contract

**Purpose:** know exactly what is connected before refactoring.

1. Record full commit, Node/npm, clean/dirty status, bundle sizes, and the gates below. Run `npm audit` at the start.
2. Trace the actual flow for each feature: browser event → permission/mode gate → per-tab state → rule engine → persistence/history/graph → message → popup/Options/side panel/export. Include CLI inputs separately.
3. Build a setting/permission inventory: each visible control, its source of truth, write path, every runtime consumer, UI feedback, and tests. Mark any control that is currently display-only or only partly wired.
4. Maintain/update `docs/BEHAVIOR_CONTRACT.md` so it covers per-site, All-sites, Off, broad conflicts, denied grants, external revocation, reload-required grants, retention, stored-data deletion, restricted pages, third-party visibility, private browsing, score semantics and cleanup.
5. Create a **mode × browser permission × event path** test matrix. At minimum cover navigation headers, redirects, XHR/fetch/API hops, page signals, startup/hydration, mode transitions and tab close.

**Exit gate:** contract and flow diagram match current code; no code changes mixed into the audit; baseline failures are identified and separated from new failures.

## WS1 — Settings, permission and capture correctness (do this next)

This workstream includes the remaining `e1392c0` fixes. Treat capture/permission fixes as a release blocker; visual redesign must not be used to mask behavior gaps.

### 1A. Use one fail-closed capture-policy snapshot at the listener boundary

- Create or extend a central policy service with a **synchronous immutable snapshot** for WebRequest callbacks. Snapshot fields should explicitly represent readiness/error, settings revision/mode, broad-grant status/coverage and normalized explicitly granted origins. Unknown or stale permission state fails closed.
- Hydrate the snapshot from `SettingsService` plus `chrome.permissions.getAll()` at startup. Refresh idempotently on settings updates and `permissions.onAdded` / `permissions.onRemoved`. Increment a revision and ensure async refreshes cannot overwrite a newer revision.
- WebRequest listener callbacks cannot synchronously await browser permission APIs. Do not issue a `getAll()` call per request and do not block/modify network traffic. Instead, consult the precomputed snapshot **before** creating `captureMap` entries, storing XHR request metadata, normalizing response headers, correlating cookies, or starting page-signal work. Keep the async `CapturePolicy.evaluate()` check later as defense in depth.
- Exact `per-site` checks use normalized browser-granted origins. Broad patterns must be interpreted conservatively and by scheme; do not assume one `https://*/*` pattern grants `http://` or vice versa. Keep actual browser permission semantics authoritative.
- Keep completion/error/redirect/tab cleanup listeners active even when capture is denied, so old records cannot leak or grow.

**Required tests:** before hydration, no capture; storage/API error, no capture; per-site without exact origin, no partial or API metadata entry; per-site plus `<all_urls>` conflict, no entry in either map; allowed narrow per-site capture works; Off transition clears existing in-flight records; cleanup still runs after a denied/new policy transition.

### 1B. Make All-sites permission state truthful

- Define All-sites as coverage over every supported web scheme/host in the behavior contract. Validate whether the actual browser grant covers that definition; do not equate “some broad-looking pattern exists” with complete coverage.
- On explicit user selection, invoke `permissions.request()` synchronously as the first operation in that click handler. If denied/cancelled, restore the **exact prior mode and UI choice**, including Off.
- If a broad grant is later removed or reduced externally, keep the selected intent visible but set monitoring state to **Paused — All-sites permission missing** (or another explicitly agreed behavior). Do not silently monitor just the few exact sites still granted. Do not auto-request on revocation; expose a user-gesture “Restore All-sites access” action and a deliberate “Switch to per-site” action.
- Recheck after `permissions.onRemoved`, browser restart, and popup/options load. The UI must separate selected mode from actual access state.

**Required tests:** full grant, denied initial request from each prior mode, one-scheme-only grant, broad grant externally removed with narrow grants remaining, browser restart with missing grant, explicit recovery action.

### 1C. Make settings transitions atomic and idempotent

- Keep a stable `lastAppliedSettings` snapshot. Route both storage changes and extension messages through one transition function: validate revision → compare old/new → apply necessary side effects → publish the new snapshot once. Do not mutate `currentSettings` in a storage listener before the transition logic can compare it.
- Treat messages as notifications, not a second source of truth. Deduplicate repeated or out-of-order notifications by schema/revision/content; never apply stale settings over newer storage.
- Rule-affecting cookie-list changes must recompute existing tab findings immediately, persist the sanitized result and broadcast a state update. Severity filter changes update visible rows only; do not recompute or alter score. Retention changes trigger pruning at the next safe maintenance point and explain when it takes effect.
- Keep future schema values intact and read-only; surface a clear unsupported-version state without overwriting them. Preserve v1 sensitive/ignored cookie lists, evaluation flag, valid mode/filter/retention values. Do not use `allowedOrigins` as a permission source.

**Required tests:** storage event before message; message before storage event; duplicate/stale revisions; cookie list update refreshes open state exactly once; presentation-only update leaves score identical; future schema is not overwritten; storage failure stays fail-closed.

### 1D. Complete Off, revocation and Options permission behavior

- Off means no new capture, analysis, cookie correlation, page-signal injection or grade badge. On transition, synchronously flip the shared gate first; then clear in-flight maps, live per-tab state, session-tab records and pending signal receipts; notify open UI. Clear all relevant badges, including `?` badges on tabs without stored state (track badge IDs or enumerate current tabs safely). Preserve optional grants unless the user separately chooses **Pause and revoke access**.
- Page-signal injection should await/queue behind settings and permission readiness, then re-check current tab URL, mode, broad conflict and origin grant before injecting. If state changed while awaiting, do nothing. Do not lose the first hard-navigation signal merely because startup hydration was pending.
- Removing one exact origin clears only that origin’s active state; removing broad access preserves tabs with a remaining exact grant. “Remove broad access” must inspect browser-returned patterns, check API result and re-read `getAll()` before reporting success.
- Fix per-origin removal failure behavior: on exception/false, keep the row or re-read browser permissions, show an error and never pretend revocation succeeded.
- Keep the five agreed UI semantics: preserve legacy values; denied All-sites grant restores the exact prior mode; mode and actual host access are distinct; All-sites means supported origins only; tests using a permission shim are described honestly.

**WS1 exit gate:** policy is enforced before capture-map/request metadata collection; Off and conflict paths truly pause; All-sites access status cannot silently degrade; settings transitions update state deterministically; permission UI equals browser state; future schema/data preserved; all the tests above pass.

## WS2 — MV3 recovery, state ordering and feature integration

**Purpose:** prevent stale or out-of-order results and connect existing features into one dependable pipeline.

1. Register MV3 event listeners synchronously, but gate feature work on shared `settingsReady` and session-hydration promises. Preserve fail-closed behavior while pending. Never solve startup timing by keeping the worker alive.
2. Introduce a per-tab navigation generation/version. Serialize state-changing work per tab or use a reducer; discard late cookie/API/rule results for an older navigation. Ensure startup hydration cannot overwrite an event received after the restored state snapshot.
3. Make one state pipeline authoritative: capture → synchronous policy snapshot → per-tab ordered reducer → cookie correlation/API/CSP/SRI analysis → rule results and score → sanitized persistence → typed broadcast → shared UI selectors. Popup and side panel display the same state and do not recompute rules independently.
4. Deduplicate messages by event/request ID and content/version. Update only changed state. Track which outputs each event affects: findings, coverage, history, graph, badge, and visible UI.
5. Bound every transient structure: partial captures, in-flight API requests, pending page signals, queues, history, graph nodes/edges and ledger. Give entries timestamps/TTL, deterministic eviction and tests. A malformed/quota-failed item must not stop all tabs or UI startup.
6. Serialize storage read-modify-write per tab/origin/apex to avoid lost history, auth baseline and graph updates. Handle quota and rejected writes as a visible local degraded-storage state; do not silently claim data saved.
7. Audit cleanup on request completion/error/redirect, Off, permission revocation, tab close, navigation change and worker restart. Old IDs/timers/observers/simulations must be stopped or invalidated.

**Integration checklist:**

| Feature | One authority | Must update consistently |
|---|---|---|
| Monitoring mode + permissions | Settings service + browser permission snapshot | Capture listeners, page signals, popup, Options, side panel |
| Headers/cookies/API findings | Background rule engine + shared TabState | Score, coverage, history, exports and both UIs |
| Custom cookie lists | Versioned SettingsService transition | Existing and future tab findings, session state and UI |
| Severity filter | Shared presentation selector | Visible rows only, never base score |
| Retention/deletion | Local storage service | History, graph, auth baselines and data-inventory counts |
| CSP/SRI/page signals | Content signal + background reducer | Deduped evidence, coverage state, UI and export |
| Graph/auth diff | Serialized per-origin/apex update | Side panel and user-selected reports; never cross private boundary |

**Exit gate:** delayed/out-of-order event tests pass; refresh/restart does not lose newest state; same event is idempotent; every cross-feature update is visible in the same session; all data structures are bounded.

## WS3 — Performance and “smooth use”

### Measure first

Benchmark at least: ordinary page with modest requests; API-heavy app; redirect chain; 5,000-node or similarly heavy DOM; mutation-heavy SPA; graph with maximum supported nodes; multiple active tabs; 30-minute soak. Record machine/browser, workload, median/p95, CPU or task timings available, messages, storage writes, rerenders, map/queue sizes and bundle size. Instrument only static labels and counts/timings; never record URL path/query, headers, cookie names/values, page content or token-derived hashes.

### Optimize the proven hot paths

- **SRI:** one initial scan, then inspect only added/changed relevant `SCRIPT`/`LINK` nodes/attributes. Coalesce mutations to at most one scan per ~250 ms (calibrate); send only changed evidence. Background ignores identical payloads without recompute, write or broadcast.
- **Meta CSP:** narrow observer to relevant `<meta http-equiv>` changes under head; do not rescan the whole document. Keep it only as long as needed and clean up on navigation/teardown.
- **Capture/rules:** avoid duplicate URL parsing/header normalization/rule runs. Memoize only pure calculations with a safe key. Never hash raw path/query as a “safe” cache key; use redacted structural keys.
- **State/UI:** batch session writes and broadcasts, coalesce noisy updates per tab (initial goal: ≤1 user-visible broadcast per 100 ms and ≤2 sustained session writes/sec/tab), skip unchanged DOM updates, render cached UI state immediately then reconcile.
- **Graph:** keep one D3 simulation reference; stop before replacement and on panel teardown; preserve node coordinates keyed by hostname; update topology incrementally; refresh same-apex changes with debounce. Do not rerender/randomize on unchanged grades.
- **Popup/side panel:** avoid repeated full render and layout shift; lazy-render collapsed details; retain focused element and scroll position after updates. Show stale/loading/errors accurately rather than freezing.
- Remove any keepalive-only alarm. Use alarms for real bounded maintenance and tolerate arbitrary delay.

**Initial goals to calibrate, not guarantees:** cached popup interactive near 150–200 ms; background handler p95 near 10 ms excluding browser API waits; no repeated work for identical events; one active graph simulation; no unbounded growth in a 30-minute soak. Tune from measured baseline and explain deviations. Do not claim “no lag” without a named workload/result.

**Exit gate:** benchmark improvements are measurable; no regression in correctness/privacy; observer/graph stress tests remain bounded; no unhandled promise errors; browser remains responsive during heavy pages.

## WS4 — Private-browsing, storage and data lifecycle

1. Decide and document whether incognito/private tabs are disabled by default or explicitly supported. If supported, require browser enablement and isolate every record by privacy context. `incognito: split` alone is not storage isolation; prove actual storage semantics for each supported browser.
2. Private observations must never enter regular persistent history, graphs, auth baselines, diagnostics or exports. Prefer private session-only namespace; clear when the final private tab closes. If the browser cannot enforce isolation, disable that feature there and explain.
3. Validate/version storage envelopes, bound payload size/depth, isolate corrupt records, catch quota failures and provide visible repair/clear options. Preserve unknown future schemas read-only; never downgrade or erase them.
4. Provide explicit data inventory and deletion actions with accurate scopes: current session, one origin, history, graph, auth baselines, private records, all local data. Explain which history survives permission revocation versus explicit purge.
5. Run canary tests through session/local storage, port messages, logs, diagnostics, JSON/SARIF/HAR/bundle exports and incognito paths. Canaries must be absent from every prohibited sink.

**Exit gate:** private data never mixes with regular data; corrupt/quota errors are recoverable and visible; deletion behavior matches copy; all secret canaries are absent from forbidden sinks.

## WS5 — UI/UX refresh: restrained cyber-futuristic, clear and accessible

Do this after WS1 behavior is green and WS2/WS3 have a stable state model. Preserve a recognizable SecCheck identity; avoid a wholesale rewrite if shared tokens and component polish solve it.

### Visual direction

- Deep ink/navy and charcoal surfaces; a restrained electric-cyan/teal accent; optional muted violet for selection; clear severity colors for critical/high/medium/info/pass. Use thin borders, subtle depth, small controlled glow only around selected/focused/active elements, and crisp numerals for scores/counts.
- Use clean readable system typography. Keep body copy and findings highly legible; do not use tiny low-contrast “terminal” text for essential information.
- No flashing, glitch effects, animated backgrounds, excessive neon/bloom, continuous movement, or decorative animation that competes with findings. Motion should communicate state, be brief, and respect `prefers-reduced-motion`.
- Build shared design tokens for color, spacing, radius, border, type, elevation, focus and motion across popup, Options and side panel. Severity must not be communicated by color alone.

### Popup

- Fit narrow popup widths and browser zoom without horizontal scrolling. Show current site/mode/access state first, then grade and top-priority findings, then coverage limitations. Use explicit states: Not monitored; permission needed; grant denied; access granted/reload; capturing; results; paused/conflict; All-sites permission missing; restricted; storage/error.
- Make findings, notes, passes and “not observed” distinct. Show evidence/provenance, confidence/applicability where available, concise explanation and safe remediation. Keep long details/API endpoints/redirects/cookies collapsible and lazy-rendered.
- Show whether capture is paused versus permissions revoked. Never let a stale `?` or grade badge contradict Off/permission state.

### Options and settings

- Group controls: Monitoring & Permissions; Findings; Cookie rules; History & Data; Display; Developer/Evaluation; About. Put dangerous deletion/revoke actions in their own clearly labeled area.
- Separate **desired mode** from **actual permission coverage**. Use persistent, plain-language warnings for conflict and missing All-sites permissions. Show exact site grants from browser state, not a parallel editable allowlist.
- Save behavior must be explicit: clean/dirty/saving/saved/error, validation next to the field, disable duplicate Save, report real failure, preserve typed edits and focus. Permission prompt actions are immediate browser operations, not fake “saved settings.”
- If All-sites is denied, restore the exact previous selection and explain. If host access is revoked externally, refresh the view. “Pause” preserves grants; “Pause and revoke” explicitly removes them and verifies the result.
- Explain retention (`0` = keep forever if that remains the contract), max history cap, and effects of per-site purge versus clear-all. Show overlap resolution if a cookie name is both sensitive and ignored.

### Side panel / graph

- Keep graph stable and low-motion. Label observed vs inferred edges differently; never imply inferred relationships were directly scanned. Give nodes keyboard focus, Enter/Space activation and accessible names.
- Provide an equivalent keyboard-navigable node/edge list or table, a selected-node details panel, last-updated time and coverage status. Make refresh/loading/empty/error states clear.

### Accessibility and polish

- Keyboard-only completion of every action; visible `:focus-visible`; logical tab order; semantic buttons/labels; status announcements with restrained `aria-live`; contrast checked; no color-only meaning; 200% zoom; narrow window behavior; reduced-motion mode; no lost focus on rerender.
- Prefer CSS transitions and opacity/transform over costly blur/backdrop filters or layout-thrashing animation. Avoid adding dependencies unless they solve a measured problem.

**Exit gate:** consistent visual system; real settings/permission behavior represented truthfully; all actions keyboard accessible; stable graph/layout; motion optional; usability test of core tasks (grant site, pause, restore access, edit cookie list, change retention, delete site data) succeeds without confusion.

## WS6 — Evidence quality and useful reports

1. Extend the existing `Finding` model rather than replacing working fields. Keep **evidence provenance** (response header, redirect, cookie metadata, DOM signal, HAR/JSON, explicit CLI fetch), **confidence**, **applicability/outcome**, and **coverage** as separate concepts. Distinguish observed fact from interpretation.
2. Add `not-observed`, `not-applicable`, and partial-coverage outcomes where appropriate. A missing permission or inaccessible browser response is not a pass and not a failure; show the limitation separately. Do not initially multiply confidence into base score.
3. CLI already has HAR/SARIF and basic `--diff` in prior reviewed source; verify current branch before extending. Add user-approved baselines with schema/ruleset version, environment label, capture scope and coverage metadata. If coverage decreased, report “comparison incomplete,” not a false fixed/new issue.
4. Keep local exports explicitly user-initiated and redacted. Reuse the existing remediation catalogue and CSP evaluator if still present; do not add duplicates. Framework/product identification from passive signals stays heuristic and labeled as such.
5. Keep rule scoring deterministic/explainable. Do not put an LLM or external service in the live security decision path. Any future optional AI explanation must be opt-in, disclose data flow and operate on already-sanitized findings only; keep it outside this stabilization scope.

**Exit gate:** finding details explain evidence, uncertainty and coverage; compatible diffs compare like-for-like; secret and privacy tests pass for every format; base score remains explainable and stable.

## WS7 — Release confidence and maintenance

- Required CI on PR and main: typecheck, lint, unit tests, Chrome build, Firefox build, Playwright E2E, CLI/SARIF smoke and `npm audit`. Add `web-ext lint` and at least a Firefox runtime smoke checklist/test where feasible. Pin actions by full SHA, automate dependency updates, and review audit advisories rather than treating “zero audit output” as a guarantee.
- Keep permission API tests with controllable browser mocks and real-extension E2E. Label shimmed permissions honestly. Maintain manual QA for native consent UI, browser-managed revocation, private mode, cache/redirect/service-worker cases, keyboard/zoom/reduced motion and storage failure.
- Add property/fuzz tests for redaction idempotence, malformed/oversized headers, duplicate CSP directives, hostile HAR/JSON, schema migration, score bounds, URL token redaction and no secret canary escaping sinks. Run heavier fuzz/mutation tests nightly or before release after normal CI is stable.
- Scan built artifacts for manifest permission drift, remote code/resources, extension CSP, Chrome/Firefox boundaries and prohibited data sinks. Avoid simplistic text-grep rules that reject safe ephemeral handling; inspect persistence/message/export paths.
- Update README, privacy policy, store copy and manual QA docs whenever capture coverage, permissions, private browsing or data retention changes. Generate SBOM/checksums/attestations only if the project release process can verify and maintain them.

**Release gate:** no known P0/P1, all required gates green on the exact release commit, manual permission/privacy checklist signed off, measured performance within agreed bounds, and documentation matches behavior.

---

# 4. Feature integration test matrix (required, not optional polish)

For every feature, test both its isolated rule and its path through browser capture → permission/mode policy → storage/state → message → UI → export. At minimum verify:

- Header and cookie findings update after navigation, redirects, cookie changes and custom cookie-list edits.
- API findings respect the same capture gate and report third-party permission blind spots; no response is called “fully covered” when it is not observable.
- CSP meta/page signals arrive after startup hydration and are not injected in Off/conflict/restricted contexts.
- SRI mutation observer is incremental, deduplicated and cleaned up; unchanged DOM causes zero repeated processing.
- Auth diffs, history and graph are versioned, bounded, idempotent and respect deletion/private-browsing policies.
- Popup, Options and side panel show the same active mode, permission coverage, findings and last-updated state; a settings change or revocation updates them without manual refresh.
- CLI URL/HAR/JSON/SARIF/diff outputs use the same versioned rule semantics where intended, while clearly documenting scope differences. Secret canaries never escape.

Create automated tests for deterministic transitions and a concise manual QA checklist for browser-native UI behaviors the harness cannot drive. Do not count an isolated unit test as proof of end-to-end integration.

---

# 5. Performance targets and acceptance definitions

| Measure | Initial target / acceptance |
|---|---|
| Cached popup | interactive near 150–200 ms on baseline environment; no blocking network dependency |
| Background | handler p95 near 10 ms excluding browser permission/storage API waits; no long synchronous DOM work |
| Duplicate events | identical signal produces no second rule run, persistent write or UI broadcast |
| Updates | coalesced user-visible state update near ≤1/100 ms/tab during bursts; no dropped final state |
| Persistence | sustained session writes near ≤2/sec/tab after batching; no unbounded write queue |
| Graph | at most one active simulation; unchanged topology does not move nodes |
| Soak | 30-minute multi-tab/SPA run has bounded maps/queues, no unhandled rejection, no growing memory trend attributable to extension |
| UI | no avoidable layout jumps or lost focus under live updates; core task usable by keyboard and at 200% zoom |

---

# 6. Workstream review cadence and delivery report

At the end of each workstream, report:
1. Commit/branch and whether it is pushed (default: not pushed unless asked).
2. What behavior changed, and which existing features were wired end-to-end.
3. Files/modules changed and any deviations from this roadmap.
4. Exact commands, results, unit/E2E counts, audit result and browser versions.
5. Before/after performance measurements with workload and environment.
6. Permission/privacy/data-retention changes and tests proving them.
7. Known limitations, failed/manual-only checks and follow-up issues.
8. Confirm whether the workstream exit gate is met; do not claim bug-free.

---

# 7. Recommended sequence

1. **WS0 Baseline + contract.** Map actual code and tests; refresh assumptions against `origin/main`.
2. **WS1 Settings/permissions/capture hardening.** Close the listener-boundary, All-sites permission-loss, settings-ordering, hydration, badge and Options failure cases.
3. **WS2 Runtime recovery + integration.** Per-tab ordering, restart recovery, dedupe and end-to-end state wiring.
4. **WS3 Performance.** Baseline, incremental observers, batched state work, stable graph and soak tests.
5. **WS4 Private data/storage resilience.** Isolation, corruption/quota recovery, data inventory/deletion and canary suite.
6. **WS5 Visual UX refresh.** Apply the restrained cyber-futuristic design to a stable state and settings model.
7. **WS6 Evidence and reports.** Provenance, coverage-aware findings, approved baselines and CLI refinement.
8. **WS7 Release confidence.** Browser QA, artifact checks, docs and all release gates.
