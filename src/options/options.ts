/**
 * options.ts — SecCheck options page logic
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All DOM manipulation via createElement / textContent / appendChild
 *  - Only chrome.* APIs (no fetch / XHR)
 */

import type { Settings, Severity } from '../shared/types';
import { SettingsService, normalizeCookieList, resolveCookieOverlaps } from '../shared/settings';
import { PermissionsService } from '../background/permissions';
import { LocalStorage } from '../shared/storage';
import { sendToBackground } from '../shared/messaging';
import { SEVERITY_ORDER } from '../shared/constants';

/* ── Canonical severity values (used for form serialisation) ── */
const ALL_SEVERITIES: Severity[] = [...SEVERITY_ORDER];

/* ── DOM references ───────────────────────────────────────────── */
let modeRadios: NodeListOf<HTMLInputElement>;
let severityCheckboxes: NodeListOf<HTMLInputElement>;
let retainDaysInput: HTMLInputElement;
let maxHistoryInput: HTMLInputElement;
let alwaysSensitiveInput: HTMLTextAreaElement;
let alwaysIgnoreInput: HTMLTextAreaElement;
let allowlistEl: HTMLUListElement;
let allowlistEmptyMsg: HTMLParagraphElement;
let saveBtn: HTMLButtonElement;
let saveStatus: HTMLSpanElement;
let sectionAllowlist: HTMLElement;
let proModeToggle: HTMLInputElement;
let modeConflictBanner: HTMLElement;
let btnRemoveBroadAccess: HTMLButtonElement;
let btnSwitchToAllSites: HTMLButtonElement;
let currentMode: Settings['monitoringMode'] = 'per-site';

/**
 * In-memory working copy of the allowedOrigins array.
 * Mutated by remove buttons; committed to storage on Save.
 */
let workingOrigins: string[] = [];
let initialSettingsSnapshot: string = '';

/* ================================================================
   Boot
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {
  // Bind all DOM references — throw early if markup diverges.
  modeRadios           = document.querySelectorAll<HTMLInputElement>('input[name="monitoringMode"]');
  severityCheckboxes   = document.querySelectorAll<HTMLInputElement>('input[name="severity"]');
  retainDaysInput      = getEl<HTMLInputElement>('retain-history-days');
  maxHistoryInput      = getEl<HTMLInputElement>('max-history-per-origin');
  alwaysSensitiveInput = getEl<HTMLTextAreaElement>('always-sensitive');
  alwaysIgnoreInput    = getEl<HTMLTextAreaElement>('always-ignore');
  allowlistEl          = getEl<HTMLUListElement>('allowlist');
  allowlistEmptyMsg    = getEl<HTMLParagraphElement>('allowlist-empty');
  saveBtn              = getEl<HTMLButtonElement>('save-btn');
  saveStatus           = getEl<HTMLSpanElement>('save-status');
  sectionAllowlist     = getEl<HTMLElement>('section-allowlist');
  proModeToggle        = getEl<HTMLInputElement>('pro-mode-toggle');
  modeConflictBanner   = getEl<HTMLElement>('mode-conflict-banner');
  btnRemoveBroadAccess = getEl<HTMLButtonElement>('btn-remove-broad-access');
  btnSwitchToAllSites  = getEl<HTMLButtonElement>('btn-switch-to-all-sites');

  wireModeRadios();
  wireConflictBanner();
  wireSaveButton();
  wireDirtyTracking();
  wireDataManagement();
  void loadAndPopulate();
});

/* ================================================================
   Data Management
   ================================================================ */

function wireDataManagement(): void {
  const deleteOriginInput = getEl<HTMLInputElement>('delete-origin-input');
  const btnDeleteOrigin = getEl<HTMLButtonElement>('btn-delete-origin');
  const btnClearHistory = getEl<HTMLButtonElement>('btn-clear-history');
  const btnClearPrivate = getEl<HTMLButtonElement>('btn-clear-private');
  const btnClearAll = getEl<HTMLButtonElement>('btn-clear-all');
  const dataMgmtStatus = getEl<HTMLDivElement>('data-mgmt-status');

  function showDataStatus(msg: string, isError = false): void {
    dataMgmtStatus.textContent = msg;
    dataMgmtStatus.className = 'status-message ' + (isError ? 'status-error' : 'status-success');
    setTimeout(() => { dataMgmtStatus.textContent = ''; dataMgmtStatus.className = 'status-message'; }, 4000);
  }

  btnDeleteOrigin.addEventListener('click', () => {
    const origin = deleteOriginInput.value.trim();
    if (!origin) { showDataStatus('Enter an origin first.', true); return; }
    try { new URL(origin); } catch { showDataStatus('Invalid origin URL.', true); return; }
    void LocalStorage.deleteOriginData(origin)
      .then(() => { showDataStatus(`Deleted data for ${origin}.`); deleteOriginInput.value = ''; })
      .catch((err: unknown) => { showDataStatus(`Failed: ${String(err)}`, true); });
  });

  btnClearHistory.addEventListener('click', () => {
    if (!confirm('Clear ALL history? This cannot be undone.')) return;
    void LocalStorage.deleteAllHistory()
      .then(() => showDataStatus('All history cleared.'))
      .catch((err: unknown) => showDataStatus(`Failed: ${String(err)}`, true));
  });

  btnClearPrivate.addEventListener('click', () => {
    void LocalStorage.deletePrivateRecords()
      .then(() => showDataStatus('Private records cleared.'))
      .catch((err: unknown) => showDataStatus(`Failed: ${String(err)}`, true));
  });

  btnClearAll.addEventListener('click', () => {
    if (!confirm('Clear ALL local SecCheck data? This cannot be undone.')) return;
    void LocalStorage.clearAll()
      .then(() => showDataStatus('All local data cleared. Extension will reload.'))
      .catch((err: unknown) => showDataStatus(`Failed: ${String(err)}`, true));
  });
}

/* ================================================================
   Load settings and populate the form
   ================================================================ */

async function loadAndPopulate(): Promise<void> {
  let settings: Settings;
  try {
    settings = await SettingsService.getSettings();
  } catch {
    setStatus('Failed to load settings.', true);
    return;
  }

  // ── Monitoring mode ──────────────────────────────────────────
  currentMode = settings.monitoringMode;
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
  maxHistoryInput.value = String(settings.maxHistoryPerOrigin ?? 10);
  alwaysSensitiveInput.value = (settings.sensitiveCookieNames ?? settings.alwaysSensitiveCookies ?? []).join(', ');
  alwaysIgnoreInput.value = (settings.ignoredCookieNames ?? settings.alwaysIgnoreCookies ?? []).join(', ');
  proModeToggle.checked = Boolean(settings.evaluationMode ?? settings.isPro);

  // ── Allowlist: load authoritative granted origins from chrome.permissions ──
  try {
    const granted = await PermissionsService.getAllGrantedOrigins();
    workingOrigins = granted;
  } catch {
    workingOrigins = [...(settings.legacyAllowedOrigins ?? settings.allowedOrigins ?? [])];
  }
  renderAllowlist();
  await checkAndRenderBroadConflict();

  // Snapshot after full population for dirty state checking
  initialSettingsSnapshot = getFormStateString();
  updateDirtyState();
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
  if (settings.maxHistoryPerOrigin < 1 || settings.maxHistoryPerOrigin > 50) {
    setStatus('Max history per origin must be between 1 and 50.', true);
    return;
  }

  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  try {
    await SettingsService.updateSettings(settings);
    await sendToBackground({ type: 'SETTINGS_CHANGED', settings });
    initialSettingsSnapshot = getFormStateString();
    setStatus('Settings saved ✓', false);
  } catch {
    setStatus('Failed to save settings.', true);
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save settings';
  }

  // Auto-clear success message after 3 seconds.
  setTimeout(() => {
    if (getFormStateString() === initialSettingsSnapshot) {
      clearStatus();
    }
  }, 3000);
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
  const maxHistoryPerOrigin = Math.max(1, Math.min(50, parseInt(maxHistoryInput.value, 10) || 10));
  const rawSensitive = alwaysSensitiveInput.value.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const rawIgnored = alwaysIgnoreInput.value.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const { sensitive, ignored, overlaps } = resolveCookieOverlaps(
    normalizeCookieList(rawSensitive),
    normalizeCookieList(rawIgnored),
  );

  if (overlaps.length > 0) {
    setStatus(`Notice: Cookie names in both lists are treated as ignored: ${overlaps.join(', ')}`, false);
  }

  return {
    schemaVersion: 2,
    monitoringMode,
    allowedOrigins: [...workingOrigins],
    severityFilter,
    retainHistoryDays,
    maxHistoryPerOrigin,
    sensitiveCookieNames: sensitive,
    ignoredCookieNames: ignored,
    evaluationMode: proModeToggle.checked,
    alwaysSensitiveCookies: sensitive,
    alwaysIgnoreCookies: ignored,
    isPro: proModeToggle.checked,
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
  originSpan.title = origin;

  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'allowlist-actions';

  const purgeBtn = document.createElement('button');
  purgeBtn.type = 'button';
  purgeBtn.className = 'btn-purge';
  purgeBtn.textContent = 'Delete stored data';
  purgeBtn.title = `Delete stored audit history and graph data for ${origin}`;
  purgeBtn.addEventListener('click', () => {
    void purgeOrigin(origin);
  });

  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'btn-remove';
  removeBtn.textContent = 'Remove';
  removeBtn.title = `Revoke browser host permission for ${origin}`;
  removeBtn.addEventListener('click', () => {
    removeOrigin(origin);
  });

  actionsDiv.appendChild(purgeBtn);
  actionsDiv.appendChild(removeBtn);

  li.appendChild(originSpan);
  li.appendChild(actionsDiv);

  return li;
}

/** Purge stored data for an origin without revoking permissions */
async function purgeOrigin(origin: string): Promise<void> {
  try {
    await LocalStorage.purgeOriginData(origin);
    setStatus(`Deleted stored data for ${origin}`, false);
  } catch {
    setStatus(`Failed to delete stored data for ${origin}`, true);
  }
}

/** Remove an origin from browser permissions and re-render the list. */
function removeOrigin(origin: string): void {
  void (async () => {
    try {
      const removed = await PermissionsService.removeOriginPermission(origin);
      if (removed) {
        workingOrigins = workingOrigins.filter((o) => o !== origin);
        renderAllowlist();
        setStatus(`Revoked access for ${origin}`, false);
      } else {
        setStatus(`Failed to revoke access for ${origin}`, true);
      }
    } catch {
      setStatus(`Failed to revoke access for ${origin}`, true);
    }
  })();
}

/* ================================================================
   Monitoring mode — show/hide allowlist section
   ================================================================ */

function wireModeRadios(): void {
  for (const radio of modeRadios) {
    radio.addEventListener('change', () => {
      if (!radio.checked) return;
      const targetMode = radio.value as Settings['monitoringMode'];

      if (targetMode === 'all-sites' && currentMode !== 'all-sites') {
        const revertToPriorMode = (): void => {
          for (const r of modeRadios) {
            r.checked = r.value === currentMode;
          }
          updateAllowlistVisibility(currentMode);
          void checkAndRenderBroadConflict();
          setStatus('All-sites monitoring requires permission for all URLs. Kept previous mode.', true);
        };

        if (typeof chrome !== 'undefined' && typeof chrome.permissions !== 'undefined') {
          try {
            chrome.permissions.request({ origins: ['<all_urls>'] }, (granted) => {
              if (!granted) {
                revertToPriorMode();
              } else {
                currentMode = 'all-sites';
                updateAllowlistVisibility('all-sites');
                void checkAndRenderBroadConflict();
              }
            });
          } catch {
            revertToPriorMode();
          }
        } else {
          currentMode = 'all-sites';
          updateAllowlistVisibility('all-sites');
          void checkAndRenderBroadConflict();
        }
      } else {
        currentMode = targetMode;
        updateAllowlistVisibility(targetMode);
        void checkAndRenderBroadConflict();
      }
    });
  }
}

async function checkAndRenderBroadConflict(): Promise<void> {
  const broadActive = await PermissionsService.isBroadGrantPresent();
  if (currentMode === 'per-site' && broadActive) {
    modeConflictBanner.removeAttribute('hidden');
  } else {
    modeConflictBanner.setAttribute('hidden', '');
  }
}

function wireConflictBanner(): void {
  btnRemoveBroadAccess.addEventListener('click', () => {
    btnRemoveBroadAccess.disabled = true;
    void PermissionsService.removeAllBroadGrants().then(async (success) => {
      btnRemoveBroadAccess.disabled = false;
      await checkAndRenderBroadConflict();
      if (success) {
        setStatus('Broad access removed', false);
      } else {
        setStatus('Failed to remove broad access or broad grants still remain in browser', true);
      }
    });
  });

  btnSwitchToAllSites.addEventListener('click', () => {
    currentMode = 'all-sites';
    for (const r of modeRadios) {
      r.checked = r.value === 'all-sites';
    }
    updateAllowlistVisibility('all-sites');
    modeConflictBanner.setAttribute('hidden', '');
    void handleSave();
  });
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
   Dirty state tracking
   ================================================================ */

function getFormStateString(): string {
  const current = readFormValues();
  return JSON.stringify({
    monitoringMode: current.monitoringMode,
    severityFilter: [...current.severityFilter].sort(),
    retainHistoryDays: current.retainHistoryDays,
    maxHistoryPerOrigin: current.maxHistoryPerOrigin,
    sensitiveCookieNames: [...current.sensitiveCookieNames].sort(),
    ignoredCookieNames: [...current.ignoredCookieNames].sort(),
    evaluationMode: current.evaluationMode,
  });
}

function updateDirtyState(): void {
  if (!initialSettingsSnapshot) return;
  const currentSnapshot = getFormStateString();
  const isDirty = currentSnapshot !== initialSettingsSnapshot;
  if (isDirty) {
    setStatus('Unsaved changes', false, true);
  } else if (saveStatus.classList.contains('dirty')) {
    clearStatus();
  }
}

function wireDirtyTracking(): void {
  for (const radio of modeRadios) {
    radio.addEventListener('change', updateDirtyState);
  }
  for (const cb of severityCheckboxes) {
    cb.addEventListener('change', updateDirtyState);
  }
  retainDaysInput.addEventListener('input', updateDirtyState);
  maxHistoryInput.addEventListener('input', updateDirtyState);
  alwaysSensitiveInput.addEventListener('input', updateDirtyState);
  alwaysIgnoreInput.addEventListener('input', updateDirtyState);
  proModeToggle.addEventListener('change', updateDirtyState);
}

/* ================================================================
   Status message helpers
   ================================================================ */

function setStatus(msg: string, isError: boolean, isDirty: boolean = false): void {
  saveStatus.textContent = msg;
  saveStatus.className = 'save-status';
  if (isError) {
    saveStatus.classList.add('error');
  } else if (isDirty) {
    saveStatus.classList.add('dirty');
  }
}

function clearStatus(): void {
  saveStatus.textContent = '';
  saveStatus.className = 'save-status';
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

if (typeof chrome !== 'undefined' && typeof chrome.permissions !== 'undefined') {
  if (typeof chrome.permissions.onRemoved !== 'undefined') {
    chrome.permissions.onRemoved.addListener(() => {
      void PermissionsService.getAllGrantedOrigins().then((origins) => {
        workingOrigins = origins;
        renderAllowlist();
        void checkAndRenderBroadConflict();
      });
    });
  }
  if (typeof chrome.permissions.onAdded !== 'undefined') {
    chrome.permissions.onAdded.addListener(() => {
      void PermissionsService.getAllGrantedOrigins().then((origins) => {
        workingOrigins = origins;
        renderAllowlist();
        void checkAndRenderBroadConflict();
      });
    });
  }
}


