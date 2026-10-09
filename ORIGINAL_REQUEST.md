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


## 2026-10-03T15:05:03Z

# Teamwork Project Prompt — SecCheck Master Verification & Settings Redesign

> Status: Launched
> Goal: Multi-agent execution across Phase 0 through Phase 5
> Requested team: Multi-agent team (Integration Owner + Functional, Privacy, Performance, Settings UX agents)

You are the multi-agent teamwork coordinator and integration owner for SecCheck, a local-first Manifest V3 browser extension with Chrome and Firefox builds, a separate CLI, header/cookie/API analysis, page signals, history/authentication diffs, an attack-surface graph, popup, Options page, and side panel.

Working directory: D:\Projects\header-cookie-security-checker
Integrity mode: development

---

## Non-Negotiable Invariants & Work Rules

1. **Confirm Environment First**: Begin by inspecting the current working directory, git branch, exact commit SHA, Node/npm versions, and package scripts. Do not rely on assumptions about previous commits, test counts, or bug lists. Re-verify every file path and behavior on the live checkout before editing.
2. **Preserve Worktree & No Unauthorized Push**: Preserve any pre-existing uncommitted changes. Report final worktree status accurately. Do NOT commit, push, reset, or clean git working state unless explicitly authorized. Do not publish, release, or make external announcements.
3. **Privacy Invariants**:
   - Cookie values, authorization credentials, secret header values, request/response bodies, and sensitive URL path/query material must NEVER be persisted, logged, messaged, telemetered, or exported.
   - All URL-valued coverage and CSP fields must be normalized through production path redactors.
   - The extension is strictly passive in browser runtime (`connect-src 'none'`); it sends no outbound probes.
   - Private/incognito records must never reach persistent history, graphs, auth baselines, diagnostics, or exports. Treat these as behaviors to verify against the live codebase before proposing changes.
4. **Permissions Authority**:
   - `chrome.permissions.getAll()` and browser permission events are the sole authority for host grants.
   - In `all-sites` mode, missing or incomplete broad access must be displayed as paused/incomplete.
   - In `per-site` mode, conflicting broad grants must pause capture until resolved.
   - Transition to `off` immediately halts capture, analysis, and page signals, and clears badges.
5. **Measurable Performance**: Define calibrated acceptance budgets instead of promising "zero lag" or "zero memory leaks". Measure and report actual memory bounds, coalesced broadcasts, and absence of sustained queue or memory growth across soak tests.
6. **Self-Contained Report**: Conclude with the complete 11-section executive report detailed in Phase 5.

---

## Six-Phase Execution Plan

### Phase 0 — Baseline & Feature Inventory
1. Inspect the live checkout; record branch, commit SHA, git status, Node/npm versions, package scripts, and build targets.
2. Run existing test scripts (`typecheck`, `lint`, `test`, `build`, `build:firefox`, `test:e2e`, `audit`) and record baseline counts and exit codes.
3. Trace user-facing flows: browser event → permission/mode gate → capture/analysis → state update → storage → messaging → UI (popup, options, side panel) → export/deletion.
4. Produce a feature-and-settings inventory table: Feature/Control | Intended Behavior | Source of Truth | Read/Write Path | Runtime Consumers | Visible Feedback | Privacy Impact | Tests | Status.

### Phase 1 — Comprehensive Functional & Quality Testing
Test the full path for every feature across:
- **Monitoring & Permissions**: Per-site, All-sites, Off; first-run; grant/deny/cancel; incomplete schemes; broad conflicts; external revocation; browser restart; internal/restricted URLs.
- **Capture & Findings**: Main-frame responses, redirect chains, cache handling, HSTS, cookie correlation, third-party cookies, API/XHR/fetch capture, CSP headers, `<meta>` CSP, service worker signals, SRI, rule scoring, and duplicate event deduplication.
- **State & Lifecycle**: MV3 worker restart and session hydration; navigation version tagging; rejection of stale DOM/API events; tab close; multi-tab concurrent browsing; settings synchronization across popup, options, and side panel.
- **UI & Data Management**: Popup and side panel states (loading, empty, capturing, paused, error, restricted); allowlist modifications; single-origin data purge; complete reset.
- **CLI & Exports**: URL/HAR inputs, SARIF 2.1, JSON, Markdown exports; canary redaction verification.
- Maintain a layer-distinguished test matrix: Unit | Production Integration | Browser E2E | Manual QA | Not Tested.

### Phase 2 — Defect Triage & Implementation
1. For any suspected defect, reproduce it on the live branch or state why it cannot be reproduced. Confirm whether previously reported issues are already resolved in current code.
2. Rank severity (P0–P3) based on security/privacy impact, user disruption, and likelihood.
3. Fix root causes—not just superficial symptoms—while preserving backward compatibility and accessibility.
4. Add regression tests importing real production modules and handlers.

### Phase 3 — Settings Redesign with Dedicated Home & Functional Preferences
Redesign Settings into a structured, responsive experience:
1. **Home / Overview Destination**:
   - Persistent, keyboard-accessible Home button/link in the navigation header that reliably returns to the overview from any section.
   - Prominently displays current monitoring mode and real host permission coverage (clearly stating if paused or missing access).
   - Clear next-action callout when permissions or recovery are needed.
   - Quick navigation cards deep-linking into each settings group.
   - Privacy/retention summary and shortcut to data management.
   - Version and local-analysis guarantee badge.
2. **Information Architecture**:
   - `Home / Overview`: Status dashboard, quick actions, section cards.
   - `Monitoring & Permissions`: Per-site / All-sites / Off, browser grants list, broad conflict resolution, remove permissions.
   - `Findings & Analysis`: Severity display filter, scoring explanation, display preferences separated from evaluation.
   - `Cookie Rules`: Custom sensitive & ignored lists, overlap resolution explanation ("ignored wins"), safe examples.
   - `History & Data Management`: History retention days, max history per origin, single-origin deletion, clear history / clear private records / full reset.
   - `Appearance & Accessibility`:
     - Theme preference: System / Dark / Light (consistently tokenized across all surfaces).
     - Layout density: Comfortable / Compact for lists and tables.
     - Reduced motion: Follows OS with explicit override option.
   - `Advanced / Developer`: Evaluation mode (attack-surface graph accumulation), diagnostic inspection.
   - `About & Privacy`: Version, local analysis guarantee (`connect-src 'none'`), project source link.
3. **UX & Accessibility Polish**:
   - Visible save states (clean, unsaved changes, saving, saved, validation error, failure).
   - Draft preservation: switching sections preserves uncommitted edits or prompts confirmation.
   - Field-level validation, visible `:focus-visible` rings, ARIA landmarks, screen reader live regions, and 200% zoom responsiveness without layout breakage.

### Phase 4 — Performance & Stability Verification
1. Measure cold/warm popup and Settings loading times.
2. Benchmark high-volume events (rapid redirects, SPA DOM mutations, cookie changes, subresource API calls) to ensure event coalescing and write batching are effective.
3. Verify graph rendering performance and bounded D3 simulation cleanup.
4. Test storage limits: verify bounded maps/queues, deterministic eviction, and absence of sustained queue or memory growth across soak testing.
5. Test MV3 worker termination and restart recovery while tabs remain active.

### Phase 5 — Quality Gates & Final Executive Report
1. Execute all repository gates:
   - `npm run typecheck`
   - `npm run lint`
   - `npm test`
   - `npm run build`
   - `npm run build:firefox`
   - `npm run test:e2e`
   - `npm audit`
   - CLI / export smoke tests
2. Produce the required 11-section final report:
   - **Section 1**: Branch, exact commit SHA, git worktree status, confirmation that no push occurred.
   - **Section 2**: Agent roles, workstreams, and files owned/modified.
   - **Section 3**: Feature and settings inventory (integrated, partial, broken, deferred).
   - **Section 4**: Verified defects found (severity, reproduction, root cause, fix, regression test).
   - **Section 5**: Settings IA & Home behavior (controls added/modified, defaults, persistence, validation, accessibility).
   - **Section 6**: Layer-distinguished test matrix (unit, production integration, browser E2E, manual QA).
   - **Section 7**: Gate results with exact commands, exit codes, test counts, browser versions, and audit outputs.
   - **Section 8**: Measured performance benchmarks (before/after, workload, hardware, timings, memory bounds).
   - **Section 9**: Privacy, permission, and data lifecycle verification (canary absence across storage, ledger, exports).
   - **Section 10**: Known limitations, manual-only items, and prioritized follow-up work.
   - **Section 11**: Direct release gate verdict (PASS / BLOCKED).

---

## Acceptance Criteria

### Security & Privacy Verification
- [ ] Confirmed zero cookie values, credentials, or sensitive path tokens (`[id]`, `[token]`) persisted in storage or exports.
- [ ] Confirmed private/incognito browsing state never persists records to persistent `LocalStorage` sinks.
- [ ] Confirmed Reset All Data synchronously switches the capture gate to `off` prior to asynchronous store deletion.
- [ ] Verified that URL-valued fields in coverage and CSP directives are scrubbed through production path redactors.

### Settings Experience & Accessibility
- [ ] Settings loads a dedicated Home / Overview view with a persistent, keyboard-accessible Home button/link.
- [ ] Section navigation preserves draft edits or warns before discarding.
- [ ] Selected additions (Theme: System/Dark/Light, Density: Comfortable/Compact, display preferences) are fully wired and functional.
- [ ] Accessible save states, visible focus outlines, ARIA live announcements, and 200% zoom responsiveness pass without clipping.

### Functional Integration & Stability
- [ ] Monitoring modes (Per-site, All-sites, Off) truthfully reflect browser permission state; missing broad grants render paused state.
- [ ] Worker restart rehydrates session state and restores navigation generation counters without dropping current page signals.
- [ ] All applicable unit, integration, and E2E tests pass cleanly with zero failures.
- [ ] Zero TypeScript errors, zero ESLint errors/warnings, and 0 npm audit vulnerabilities.
- [ ] All pre-existing uncommitted work is preserved; no unauthorized commits or remote pushes executed.


## 2026-10-08T16:22:03Z

# Teamwork Project Prompt — Final

Working directory: D:\Projects\ACULYX
Integrity mode: development
Requested team: Use 2 agents (Agent 1: Scope & Rules, Agent 2: Evidence & Reporting)

ACULYX: High-Confidence Bug-Bounty Scanner — Two-Agent Parallel Implementation.

## Architecture & Work Split

### R0. Shared Contract Kickoff (Coordinator Foundation)
Establish non-overlapping contracts before parallel agent execution:
- `src/shared/scope/contracts.ts`:
  - `ScopeStatus`: `'in-scope' | 'out-of-scope' | 'unknown'`
  - `ScopeResult`: `{ status: ScopeStatus; matchedPattern?: string; reason: string; ruleType?: 'include' | 'exclude' }`
  - Host & Port Normalization Contract: Normalize the hostname using IDNA, lowercase, and trailing-dot removal; preserve scheme and explicit port separately. Scope rules must state whether they cover a hostname or a specific scheme/port. Never silently discard an explicitly scoped port. Deliberate apex vs wildcard boundary (`*.example.com` does NOT match `example.com` unless explicitly listed).
- `src/shared/reporting/types.ts`:
  - `ResearcherReviewState`: `'unreviewed' | 'needs-manual-verification' | 'verified-by-researcher' | 'not-reproducible' | 'not-a-finding'`
  - `FindingReportDetail`: reproduction steps, preconditions, expected vs observed behavior, impact, sanitized evidence, limitations, scope note.
  - Comprehensive Secret Redaction Criteria: Strictly redact and exclude credentials embedded in URLs, sensitive path segments, fragments, raw authorization headers, Set-Cookie lines, logs, and exports—not just query tokens. Retain strict incognito/private-window isolation and storage exclusion.

### R1. Scope Engine & Bounded Rule Precision (Agent 1 Ownership)
**Files Owned**: `src/shared/scope/**`, `src/rules/**`, `tests/scope/**`, `tests/rules/**`
- **Scope Engine**: Pure deterministic domain & wildcard matcher supporting exact hosts, `*.domain.com`, exclusions with precedence, preserved explicit ports, and independent redirect/third-party scope evaluation.
- **Bounded Rule Precision Audit**: Audit all six broad rule families (headers/policies, cookies, CORS, caching, redirects/transport, page signals), but implement only the highest-value, evidence-supported fixes in this pass (e.g. CORS preflight/null-origin context, cookie prefixes and path/domain boundaries, CSP bypass host caveats, cache cookie sensitivity).
- **Scope Restriction**: This task does NOT add active testing unless it is separately authorized and scoped. All scanning remains passive and non-intrusive.
- **Rule Authoring Standards**: Narrow claims, authoritative citations, synthetic test fixtures (positive, safe-negative, not-applicable, incomplete, malformed, regression). Output honest `limitations` and `outcome: 'partial-coverage'` or `'not-observed'` when server context is ambiguous.

### R2. Evidence, Triage & Report Workflow (Agent 2 Ownership)
**Files Owned**: `src/shared/reporting/**`, `src/options/**`, `src/popup/**`, `src/sidepanel/**`, report/export tests
- **Finding Details UI**: Dedicated view showing stable rule ID, observed facts, provenance, confidence, limitations, and scope status badge.
- **Researcher Review States**: Local triage annotations without mutating immutable captured scanner findings.
- **Local Bug-Bounty Report Builder**: Generates Markdown and JSON report drafts with reproduction steps, preconditions, impact, evidence, remediation, and scope notes.
- **UI Responsiveness & Accessibility**: Safe text rendering (no innerHTML), secret redaction, keyboard navigation, and reduced-motion support.

### R3. Integration & Release Verification (Coordinator)
- Combine Agent 1 and Agent 2 branches/modules cleanly.
- Verify zero secret leak, incognito isolation, and write barrier integrity.
- Execute full test and build gate matrix.

## Test Schedule & Release Bar

### Test Schedule
Add tests alongside changes during development, but run the combined focused tests and full release gates after both agents integrate—not after every module or individual agent commit.

### Acceptance Criteria
- [ ] Scope correctly classifies exact domains, wildcard boundaries (`*.example.com` does not match apex `example.com` unless specified), exclusions (take precedence over includes), explicit ports, and unknown hosts.
- [ ] Hostname normalization uses IDNA, lowercase, and trailing-dot removal; scheme and explicit port are preserved separately and never silently stripped.
- [ ] Unknown scope returns `'unknown'`; third-party APIs and redirect targets are evaluated independently.
- [ ] No active testing is executed (scanner remains purely passive).
- [ ] Zero changed rules emit a confirmed vulnerability on known-safe configurations.
- [ ] Ambiguous or incomplete contexts (cache, service worker, partial redirect) emit `outcome: 'partial-coverage'` or `'not-observed'`.
- [ ] Every finding includes ruleId, sanitized evidence, provenance, applicability, and explicit `limitations`.
- [ ] Review states (`unreviewed`, `needs-manual-verification`, `verified-by-researcher`, `not-reproducible`, `not-a-finding`) can be set and persisted locally without altering captured scanner findings.
- [ ] Markdown and JSON report drafts export reproduction steps, preconditions, expected/observed results, remediation, and scope notes.
- [ ] Zero credentials embedded in URLs, sensitive path segments, fragments, raw authorization headers, Set-Cookie lines, logs, or exports.
- [ ] Incognito isolation remains intact (zero persistence of private window browsing data).

### Automated Release Gates (Full Run After Integration)
- [ ] `npm run typecheck` passes with 0 errors.
- [ ] `npm run lint -- --max-warnings=0` passes with 0 warnings.
- [ ] `npm test` passes all unit, scope, and rule tests.
- [ ] `npm run test:e2e` passes all Playwright browser tests.
- [ ] `npm run build` compiles Chrome MV3 extension cleanly into `dist/`.
- [ ] `npm run build:firefox` compiles Firefox MV3 extension cleanly into `dist-firefox/`.
- [ ] `npm audit --audit-level=low` reports 0 vulnerabilities.


## 2026-10-08T17:15:36Z

do it make it the current workspace


## 2026-10-08T17:18:45Z

User directive: Do NOT run audits or test suites after each module. Complete the entire implementation across R1 and R2 first, then run the full audit and test gates once after whole completion.
