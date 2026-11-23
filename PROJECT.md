# Project: ACULYX Frontend Remodel

## Architecture
ACULYX is a local-first Manifest V3 browser extension built with TypeScript, Vite (`@crxjs/vite-plugin`), and Vitest/Playwright test suites.
The frontend remodel establishes a focused dark investigation workspace with a restrained ninja visual language (`#070611`, `#100E1C`, `#191629`, `#9B4DFF`, `#D56BFF`) across Chrome and Firefox builds.

Key architectural boundaries:
- **Browser Entry & Routing**: Chrome toolbar action click synchronously opens `chrome.sidePanel.open` with tab-based workspace fallback (`chrome.tabs.create`); Firefox maintains `action.default_popup` targeting Firefox 142+ without `side_panel` declarations.
- **Launcher Surface (`src/popup/`)**: Fast, compact status launcher displaying origin identity, grade shield, coverage bar, gating states, Monitor/Stop toggle, top 3 teaser, and "Open Investigation Workspace" launch button.
- **Investigation Workspace (`src/sidepanel/`)**: 4-tab investigation architecture (`Overview`, `Findings`, `Surface`, `Activity`) preserving all 6 analysis capabilities (Graph, Radar, Leads, Chains, Recon, Timeline), safe cURL copying, export formats (MD, JSON, SARIF), credential/active confirmation gates, and `Ctrl+K` command palette.
- **Preferences & Contracts (`src/options/`)**: Appearance live preview / dirty / save / discard contracts; post-save navigation strictly gated on save success; 6-item interactive effective configuration summary; default-off credential liveness invariants.
- **Visual System & Assets (`src/shared/design-tokens.css`, `src/devtools/`)**: Obsidian surfaces, steel borders, katana accents, frozen severity/grade tokens, reconciled DevTools tokens, bounded motion, byte-for-byte image asset preservation.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Chrome Toolbar Action Click | Toolbar click opens browser sidepanel synchronously via `chrome.sidePanel.open` without `action.default_popup` | M1 | R1 |
| 2 | Workspace Tab Fallback | Tab-based fallback (`chrome.tabs.create`) if `chrome.sidePanel.open` is rejected or unavailable | M1 | R1 |
| 3 | Firefox Popup Entry | Firefox build preserves `action.default_popup` pointing to `src/popup/popup.html` and strips `side_panel`/`sidePanel` | M1 | R1 |
| 4 | Vite Popup Rollup Entry | Explicit `popup.html` entry in `rollupOptions.input` so Vite builds popup despite absence in Chrome manifest | M1 | R1 |
| 5 | Compact Popup Launcher | Streamlined popup: origin, grade, coverage bar, connection/permission gates, Monitor/Stop toggle, top 3 teaser, workspace launch button | M1 | R2 |
| 6 | Popup Safe Text Rendering | Pure text DOM APIs, zero innerHTML, retained origin-scoped permission request gates, no radar/spoke/drawer clutter | M1 | R2 |
| 7 | Appearance Live Preview | Theme, density, and reduced motion apply immediately to the DOM on radio change | M2 | R4 |
| 8 | Appearance Dirty Feedback | Dirty state displays clear `"Preview — unsaved"` feedback when appearance settings are modified | M2 | R4 |
| 9 | Appearance Save & Discard | Save persists preview to storage; Discard reverts live preview back to stored settings and clears dirty indicators | M2 | R4 |
| 10 | Post-Save Navigation Guard | `handleSave` returns boolean; post-save navigation strictly gated on save success; preserves unsaved edits on failure | M2 | R4 |
| 11 | Effective Configuration Summary | 6 interactive summary cards on Home (Mode, Grants, Leads, Deep Mode, Hunter, Credential Liveness) deep-linking and focusing controls | M2 | R4 |
| 12 | Staged Form Dirty Tracking | Canonical serialization and dirty tracking across all settings fields; `revertToPriorMode` updates dirty state | M2 | R4 |
| 13 | Credential Liveness Invariants | Default-off (`false`), manual-only, authorized confirmation required, cleanly tracked in dirty state | M2 | R4 |
| 14 | Ninja Visual Design Tokens | Obsidian surfaces (`#070611`, `#100E1C`, `#191629`), steel borders, violet katana accents (`#9B4DFF`), magenta highlights (`#D56BFF`) | M3 | R5 |
| 15 | Severity & Grade Token Freeze | Existing severity (`--sc-critical`, `--sc-high`, etc.) and grade tokens remain strictly byte-for-byte unchanged | M3 | R5 |
| 16 | DevTools Reconciled Palette | DevTools `panel.html` imports shared tokens; `panel.css` variables mapped to `--sc-*` tokens | M3 | R5 |
| 17 | Motion Policy | Non-continuous animations, 140-200ms durations, disabled under `prefers-reduced-motion` and application settings | M3 | R5 |
| 18 | Asset Byte-for-Byte Preservation | All PNGs in `icons/` and `src/assets/aculyx-wordmark.png` remain byte-for-byte identical | M3 | R5 |
| 19 | Sidepanel Overview Tab | Origin, apex, grade shield, coverage bar, top hygiene findings card, radar statistics card, next recommended action | M4 | R3 |
| 20 | Sidepanel Findings Tab | Lead search, filters (family, tier, scope, new, in-chain), priority ordering, expanded verdict dimensions, triage/export actions | M4 | R3 |
| 21 | Sidepanel Surface Tab | Attack surface graph with accessible node table alternative, subdomain trust & API views, chain/recon lenses | M4 | R3 |
| 22 | Sidepanel Activity Tab | Discovery timeline event stream and scan update history / coverage ledger | M4 | R3 |
| 23 | Sidepanel 6 Capabilities Parity | Complete preservation of Graph, Radar, Leads, Chains, Recon (wordlist generator), and Timeline | M4 | R3 |
| 24 | Sidepanel Security Gates | Safe cURL copy, Hunter active verification 2-step confirmation, Credential liveness 4-step confirmation, `Ctrl+K` palette | M4 | R3 |
| 25 | Sidepanel Test Compatibility | Preserves `#tab-leads` and `#view-leads` IDs/aliases for E2E tests (`sidepanel-verdict.spec.ts`) | M4 | R3 |
| 26 | Checkpoint 1 Core & Integration | Passes `npm run typecheck`, `npm run lint`, `npm test`, `npm run build:all`, and `npm run test:artifacts` | M5 | AC |
| 27 | Checkpoint 2 Final Release Gate | Passes `npm run test:e2e`, `npm run lint:amo`, `npm run pack`, and `npm run verify:pack` | M6 | AC |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Entry & Popup | Chrome action click, tab fallback, Firefox popup retention, compact popup launcher (R1, R2) | none | DONE |
| 2 | Options Contracts | Appearance live preview/discard, post-save navigation guard, effective config summary, dirty tracking (R4) | none | DONE |
| 3 | Visual System & Tokens | Obsidian surfaces, katana accents, DevTools token reconciliation, motion policy, asset integrity (R5) | none | DONE |
| 4 | Sidepanel Workspace | 4-tab shell (Overview, Findings, Surface, Activity), 6 capabilities preserved, security gates, test aliases (R3) | M3 | DONE |
| 5 | Checkpoint 1 (Core Gate) | Typecheck, lint, unit tests, build:all, test:artifacts verification | M1, M2, M4 | DONE |
| 6 | Checkpoint 2 (Release Gate) | Playwright E2E suites, AMO lint, package & verification | M5 | IN_PROGRESS |

## Interface Contracts

### Background ↔ UI Entry Contract
- `chrome.action.onClicked`: Registered in `src/background/index.ts`. On user click:
  - Synchronously invokes `chrome.sidePanel.open({ windowId: tab.windowId })`.
  - On error / rejection: falls back to `chrome.tabs.create({ url: chrome.runtime.getURL('src/sidepanel/sidepanel.html?apex=' + encodeURIComponent(apex) + '&tabId=' + tab.id) })`.
- Chrome `manifest.json`: `"action": { "default_title": "ACULYX Security Scanner" }` (NO `default_popup`).
- Firefox `manifest.firefox.json` / build: `"action": { "default_popup": "src/popup/popup.html" }` (NO `side_panel` or `sidePanel`).

### Options State & Appearance Contract
- `applyAppearance(theme, density, reducedMotion, targetDocument)`: Immediately modifies DOM attributes (`data-theme`, `classList.toggle('density-compact')`, `data-motion`).
- `updateDirtyUI()`: If form state != initial snapshot, checks if appearance fields differ:
  - If appearance modified: `#save-status` displays `"Preview — unsaved"`.
  - If other fields modified: `#save-status` displays `"Unsaved changes"`.
- `handleSave(): Promise<boolean>`: Returns `true` if storage write and background transition succeeded; `false` on validation error or rejection.
- `wireUnsavedDialog()`: `dialogSave` only calls `activateSection(target)` if `handleSave()` resolved to `true`.

### Sidepanel Workspace Tab & View Contract
- Primary Navigation Tabs:
  - `#tab-overview` -> activates `#view-overview`
  - `#tab-findings` (with alias `#tab-leads`) -> activates `#view-findings` (with alias `#view-leads`)
  - `#tab-surface` -> activates `#view-surface` (hosts Graph `#view-graph`, Chains `#view-chains`, Recon `#view-recon`)
  - `#tab-activity` -> activates `#view-activity` (hosts Timeline `#view-timeline`)
- Accessible Alternatives & Safety:
  - `#toggle-node-table-btn` toggles between SVG `#graph-svg` and table `#node-list-table`.
  - cURL copy validates URL scheme (`http:`, `https:`) and in-scope status before copying command.
  - Hunter active probes require 2-step confirmation dialog.
  - Credential checks require 4-step confirmation dialog with explicit user authorization affirmation.

## Code Layout
- `manifest.json`, `manifest.firefox.json`, `vite.config.ts`, `scripts/build-firefox.js`
- `src/background/index.ts`
- `src/popup/popup.html`, `src/popup/popup.ts`, `src/popup/popup.css`
- `src/options/options.html`, `src/options/options.ts`, `src/options/options.css`
- `src/sidepanel/sidepanel.html`, `src/sidepanel/sidepanel.ts`, `src/sidepanel/sidepanel.css`
- `src/shared/design-tokens.css`
- `src/devtools/panel.html`, `src/devtools/panel.css`
- `icons/` (byte-for-byte read-only)
- `tests/` (unit and e2e suites)
