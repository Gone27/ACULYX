/**
 * options.ts — SecCheck options page logic
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All DOM manipulation via createElement / textContent / appendChild
 *  - Only chrome.* APIs (no fetch / XHR)
 */

import type { Settings, Severity } from '../shared/types';
import { LocalStorage } from '../shared/storage';
import { sendToBackground } from '../shared/messaging';
import { SEVERITY_ORDER } from '../shared/constants';

/* ── Canonical severity values (used for form serialisation) ── */
const ALL_SEVERITIES: Severity[] = [...SEVERITY_ORDER];

/* ── DOM references ───────────────────────────────────────────── */
let modeRadios: NodeListOf<HTMLInputElement>;
let severityCheckboxes: NodeListOf<HTMLInputElement>;
let retainDaysInput: HTMLInputElement;
let alwaysSensitiveInput: HTMLTextAreaElement;
let alwaysIgnoreInput: HTMLTextAreaElement;
let allowlistEl: HTMLUListElement;
let allowlistEmptyMsg: HTMLParagraphElement;
let saveBtn: HTMLButtonElement;
let saveStatus: HTMLSpanElement;
let sectionAllowlist: HTMLElement;

/**
 * In-memory working copy of the allowedOrigins array.
 * Mutated by remove buttons; committed to storage on Save.
 */
let workingOrigins: string[] = [];

/* ================================================================
   Boot
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {
  // Bind all DOM references — throw early if markup diverges.
  modeRadios           = document.querySelectorAll<HTMLInputElement>('input[name="monitoringMode"]');
  severityCheckboxes   = document.querySelectorAll<HTMLInputElement>('input[name="severity"]');
  retainDaysInput      = getEl<HTMLInputElement>('retain-history-days');
alwaysSensitiveInput = getEl<HTMLTextAreaElement>('always-sensitive');
alwaysIgnoreInput  = getEl<HTMLTextAreaElement>('always-ignore');
  allowlistEl          = getEl<HTMLUListElement>('allowlist');
  allowlistEmptyMsg    = getEl<HTMLParagraphElement>('allowlist-empty');
  saveBtn              = getEl<HTMLButtonElement>('save-btn');
  saveStatus           = getEl<HTMLSpanElement>('save-status');
  sectionAllowlist     = getEl<HTMLElement>('section-allowlist');

  wireModeRadios();
  wireSaveButton();
  void loadAndPopulate();
});

/* ================================================================
   Load settings and populate the form
   ================================================================ */

async function loadAndPopulate(): Promise<void> {
  let settings: Settings;
  try {
    settings = await LocalStorage.getSettings();
  } catch {
    setStatus('Failed to load settings.', true);
    return;
  }

  // ── Monitoring mode ──────────────────────────────────────────
  for (const radio of modeRadios) {
    radio.checked = radio.value === settings.monitoringMode;
  }
  updateAllowlistVisibility(settings.monitoringMode);

  // ── Severity filter ──────────────────────────────────────────
  const filterSet = new Set<string>(settings.severityFilter);
  for (const cb of severityCheckboxes) {
    cb.checked = filterSet.has(cb.value);
  }

  // ── History ──────────────────────────────────────────────────
  retainDaysInput.value = String(settings.retainHistoryDays);
  alwaysSensitiveInput.value = settings.alwaysSensitiveCookies.join(', ');
  alwaysIgnoreInput.value = settings.alwaysIgnoreCookies.join(', ');

  // ── Allowlist ────────────────────────────────────────────────
  workingOrigins = [...settings.allowedOrigins];
  renderAllowlist();
}

/* ================================================================
   Save handler
   ================================================================ */

function wireSaveButton(): void {
  saveBtn.addEventListener('click', () => {
    void handleSave();
  });
}

async function handleSave(): Promise<void> {
  clearStatus();

  const settings = readFormValues();

  // Basic validation
  if (settings.retainHistoryDays < 0 || settings.retainHistoryDays > 365) {
    setStatus('Retain days must be between 0 and 365.', true);
    return;
  }

  try {
    await LocalStorage.setSettings(settings);
    await sendToBackground({ type: 'SETTINGS_CHANGED', settings });
    setStatus('Settings saved ✓', false);
  } catch {
    setStatus('Failed to save settings.', true);
    return;
  }

  // Auto-clear success message after 3 seconds.
  setTimeout(() => clearStatus(), 3000);
}

/* ================================================================
   Read current form values → Settings object
   ================================================================ */

function readFormValues(): Settings {
  // Monitoring mode
  let monitoringMode: Settings['monitoringMode'] = 'per-site';
  for (const radio of modeRadios) {
    if (radio.checked) {
      // Runtime validation — values match the union type.
      const val = radio.value;
      if (val === 'per-site' || val === 'all-sites' || val === 'off') {
        monitoringMode = val;
      }
      break;
    }
  }

  // Severity filter — collect checked values that are valid Severity members.
  const severityFilter: Severity[] = [];
  for (const cb of severityCheckboxes) {
    if (cb.checked) {
      const val = cb.value as Severity;
      if (ALL_SEVERITIES.includes(val)) {
        severityFilter.push(val);
      }
    }
  }

  // Retain history days
  const retainHistoryDays = Math.max(0, Math.min(365, parseInt(retainDaysInput.value, 10) || 0));
  const alwaysSensitiveCookies = alwaysSensitiveInput.value.split(',').map(s => s.trim()).filter(Boolean);
  const alwaysIgnoreCookies = alwaysIgnoreInput.value.split(',').map(s => s.trim()).filter(Boolean);

  return {
    monitoringMode,
    allowedOrigins: [...workingOrigins],
    severityFilter,
    retainHistoryDays,
    alwaysSensitiveCookies,
    alwaysIgnoreCookies,
  };
}

/* ================================================================
   Allowlist rendering (createElement only — no innerHTML)
   ================================================================ */

/**
 * Rebuild the allowlist <ul> from workingOrigins.
 * Clears all child nodes first, then appends fresh <li> elements.
 */
function renderAllowlist(): void {
  // Clear existing items safely.
  while (allowlistEl.firstChild) {
    allowlistEl.removeChild(allowlistEl.firstChild);
  }

  if (workingOrigins.length === 0) {
    allowlistEmptyMsg.hidden = false;
    return;
  }

  allowlistEmptyMsg.hidden = true;

  for (const origin of workingOrigins) {
    allowlistEl.appendChild(buildAllowlistItem(origin));
  }
}

/**
 * Build a single allowlist <li> row:
 *   <li class="allowlist-item">
 *     <span class="allowlist-origin">{origin}</span>
 *     <button class="btn-remove">Remove</button>
 *   </li>
 */
function buildAllowlistItem(origin: string): HTMLLIElement {
  const li = document.createElement('li');
  li.className = 'allowlist-item';

  const originSpan = document.createElement('span');
  originSpan.className = 'allowlist-origin';
  originSpan.textContent = origin;     // origin is trusted but use textContent anyway
  // Provide a title for long origins that get truncated.
  originSpan.title = origin;

  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'btn-remove';
  removeBtn.textContent = 'Remove';
  removeBtn.addEventListener('click', () => {
    removeOrigin(origin);
  });

  li.appendChild(originSpan);
  li.appendChild(removeBtn);

  return li;
}

/** Remove an origin from the working array and re-render the list. */
function removeOrigin(origin: string): void {
  workingOrigins = workingOrigins.filter((o) => o !== origin);
  renderAllowlist();
}

/* ================================================================
   Monitoring mode — show/hide allowlist section
   ================================================================ */

function wireModeRadios(): void {
  for (const radio of modeRadios) {
    radio.addEventListener('change', () => {
      if (radio.checked) {
        updateAllowlistVisibility(radio.value);
      }
    });
  }
}

/**
 * The allowlist section is only relevant when mode is 'per-site'.
 * We toggle aria-hidden and the CSS hidden attribute together.
 */
function updateAllowlistVisibility(mode: string): void {
  const visible = mode === 'per-site';
  // Use the hidden attribute — matched by CSS `[hidden] { display:none }` default.
  if (visible) {
    sectionAllowlist.removeAttribute('hidden');
  } else {
    sectionAllowlist.setAttribute('hidden', '');
  }
}

/* ================================================================
   Status message helpers
   ================================================================ */

function setStatus(msg: string, isError: boolean): void {
  saveStatus.textContent = msg;
  if (isError) {
    saveStatus.classList.add('error');
  } else {
    saveStatus.classList.remove('error');
  }
}

function clearStatus(): void {
  saveStatus.textContent = '';
  saveStatus.classList.remove('error');
}

/* ================================================================
   Utility helpers
   ================================================================ */

/** Returns a typed, non-null reference to a DOM element by ID. */
function getEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el as T;
}

