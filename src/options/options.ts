/**
 * options.ts — ACULYX options page logic
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All DOM manipulation via createElement / textContent / appendChild
 *  - Only chrome.* APIs (no fetch / XHR)
 *  - Section router: JS-driven, no page reloads
 */

import type { Settings, Severity } from '../shared/types';
import { SettingsService, normalizeCookieList, resolveCookieOverlaps } from '../shared/settings';
import { PermissionsService } from '../background/permissions';
import { LocalStorage } from '../shared/storage';
import { sendToBackground } from '../shared/messaging';
import { SEVERITY_ORDER, DEFAULT_SETTINGS } from '../shared/constants';
import { applyAppearance } from '../shared/appearance';

/* ── Canonical severity values ───────────────────────────────────── */
const ALL_SEVERITIES: Severity[] = [...SEVERITY_ORDER];

/* ── DOM references ──────────────────────────────────────────────── */
let modeRadios: NodeListOf<HTMLInputElement>;
let severityCheckboxes: NodeListOf<HTMLInputElement>;
let retainDaysInput: HTMLInputElement;
let maxHistoryInput: HTMLInputElement;
let alwaysSensitiveInput: HTMLTextAreaElement;
let alwaysIgnoreInput: HTMLTextAreaElement;
let allowlistEl: HTMLUListElement;
let allowlistEmptyMsg: HTMLParagraphElement;
let saveBtn: HTMLButtonElement;
let discardBtn: HTMLButtonElement;
let saveStatus: HTMLSpanElement;
let sectionAllowlist: HTMLElement;
let evalModeToggle: HTMLInputElement;
let modeConflictBanner: HTMLElement;
let btnRemoveBroadAccess: HTMLButtonElement;
let btnSwitchToAllSites: HTMLButtonElement;
let navDirtyBadge: HTMLElement;
let unsavedDialog: HTMLDialogElement;
let currentMode: Settings['monitoringMode'] = 'per-site';
let pendingNavSection: string | null = null;

/** In-memory working copy of the allowedOrigins array. */
let workingOrigins: string[] = [];
let initialSettingsSnapshot: string = '';
let isDirty = false;

/* ================================================================
   Boot
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {
  // Bind DOM references
  modeRadios           = document.querySelectorAll<HTMLInputElement>('input[name="monitoringMode"]');
  severityCheckboxes   = document.querySelectorAll<HTMLInputElement>('input[name="severity"]');
  retainDaysInput      = getEl<HTMLInputElement>('retain-history-days');
  maxHistoryInput      = getEl<HTMLInputElement>('max-history-per-origin');
  alwaysSensitiveInput = getEl<HTMLTextAreaElement>('always-sensitive');
  alwaysIgnoreInput    = getEl<HTMLTextAreaElement>('always-ignore');
  allowlistEl          = getEl<HTMLUListElement>('allowlist');
  allowlistEmptyMsg    = getEl<HTMLParagraphElement>('allowlist-empty');
  saveBtn              = getEl<HTMLButtonElement>('save-btn');
  discardBtn           = getEl<HTMLButtonElement>('btn-discard');
  saveStatus           = getEl<HTMLSpanElement>('save-status');
  sectionAllowlist     = getEl<HTMLElement>('section-allowlist');
  evalModeToggle       = getEl<HTMLInputElement>('eval-mode-toggle');
  modeConflictBanner   = getEl<HTMLElement>('mode-conflict-banner');
  btnRemoveBroadAccess = getEl<HTMLButtonElement>('btn-remove-broad-access');
  btnSwitchToAllSites  = getEl<HTMLButtonElement>('btn-switch-to-all-sites');
  navDirtyBadge        = getEl<HTMLElement>('nav-dirty-badge');
  unsavedDialog        = getEl<HTMLDialogElement>('unsaved-dialog');

  wireNav();
  wireNavCards();
  wireModeRadios();
  wireConflictBanner();
  wireSaveButton();
  wireDiscardButton();
  wireDirtyTracking();
  wireDataManagement();
  wireAppearanceLivePreview();
  wireUnsavedDialog();

  // Version badge
  if (typeof chrome !== 'undefined' && typeof chrome.runtime !== 'undefined') {
    const manifest = chrome.runtime.getManifest();
    const versionEl = document.getElementById('home-version-badge');
    if (versionEl) versionEl.textContent = `ACULYX v${manifest.version}`;
    const aboutEl = document.getElementById('about-version');
    if (aboutEl) aboutEl.textContent = manifest.version;
  }

  void loadAndPopulate();
});

/* ================================================================
   Section router
   ================================================================ */

const SECTION_IDS = ['home', 'monitoring', 'findings', 'cookies', 'history', 'appearance', 'advanced', 'about'];

function navigateToSection(target: string): void {
  if (isDirty) {
    pendingNavSection = target;
    showUnsavedDialog();
  } else {
    activateSection(target);
  }
}

function wireNav(): void {
  const navItems = document.querySelectorAll<HTMLButtonElement>('.nav-item[data-section]');
  navItems.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset['section'] ?? 'home';
      navigateToSection(target);
    });
  });
}

function wireNavCards(): void {
  const cards = document.querySelectorAll<HTMLButtonElement>('.home-nav-card[data-goto]');
  cards.forEach((card) => {
    card.addEventListener('click', () => {
      const target = card.dataset['goto'] ?? 'home';
      navigateToSection(target);
    });
  });

  // Home callout action button
  const calloutAction = document.getElementById('home-callout-action');
  if (calloutAction) {
    calloutAction.addEventListener('click', () => {
      navigateToSection('monitoring');
    });
  }
}

function activateSection(sectionId: string): void {
  const target = SECTION_IDS.includes(sectionId) ? sectionId : 'home';

  // Show/hide sections
  SECTION_IDS.forEach((id) => {
    const section = document.getElementById(`section-${id}`);
    if (!section) return;
    if (id === target) {
      section.removeAttribute('hidden');
      section.classList.add('active');
    } else {
      section.setAttribute('hidden', '');
      section.classList.remove('active');
    }
  });

  // Update nav item active states
  const navItems = document.querySelectorAll<HTMLButtonElement>('.nav-item[data-section]');
  navItems.forEach((btn) => {
    const isActive = btn.dataset['section'] === target;
    btn.classList.toggle('active', isActive);
    if (isActive) {
      btn.setAttribute('aria-current', 'page');
    } else {
      btn.removeAttribute('aria-current');
    }
  });

  // Refresh home view data when navigating to it
  if (target === 'home') {
    void refreshHomeView();
  }
}

/* ================================================================
   Home / Overview view
   ================================================================ */

async function refreshHomeView(): Promise<void> {
  const modeEl = document.getElementById('home-mode-value');
  const permsEl = document.getElementById('home-perms-value');
  const callout = document.getElementById('home-callout');
  const calloutTitle = document.getElementById('home-callout-title');
  const calloutDesc = document.getElementById('home-callout-desc');
  const calloutAction = document.getElementById('home-callout-action') as HTMLButtonElement | null;

  if (!modeEl || !permsEl || !callout || !calloutTitle || !calloutDesc) return;

  // Load current settings and permissions state
  let settings: Settings;
  try {
    settings = await SettingsService.getSettings();
  } catch {
    modeEl.textContent = 'Unknown';
    return;
  }

  const modeLabels: Record<string, string> = {
    'per-site': 'Per-site opt-in',
    'all-sites': 'All sites',
    'off': 'Off',
  };
  modeEl.textContent = modeLabels[settings.monitoringMode] ?? settings.monitoringMode;

  // Permissions coverage
  let permText = '—';
  let needsAction = false;
  let actionText = '';
  let actionDesc = '';

  if (typeof chrome !== 'undefined' && typeof chrome.permissions !== 'undefined') {
    try {
      const granted = await PermissionsService.getAllGrantedOrigins();
      const hasComplete = await PermissionsService.hasCompleteBroadGrant();
      const hasBroad = await PermissionsService.isBroadGrantPresent();

      if (settings.monitoringMode === 'off') {
        permText = 'Capture disabled';
      } else if (settings.monitoringMode === 'all-sites') {
        if (hasComplete) {
          permText = 'All sites (complete)';
        } else if (hasBroad) {
          permText = '⚠ Incomplete broad access';
          needsAction = true;
          actionText = 'Fix permissions';
          actionDesc = 'All-sites mode requires complete HTTP + HTTPS broad access. Capture is paused.';
        } else {
          permText = '⚠ No broad access granted';
          needsAction = true;
          actionText = 'Grant access';
          actionDesc = 'All-sites mode requires broad host permission. Go to Monitoring to grant it.';
        }
      } else {
        // per-site
        if (hasBroad) {
          permText = '⚠ Conflict: broad access active';
          needsAction = true;
          actionText = 'Resolve conflict';
          actionDesc = 'Per-site mode is active but broad access is also granted. Capture is paused.';
        } else if (granted.length === 0) {
          permText = 'No origins granted yet';
        } else {
          permText = `${granted.length} origin${granted.length !== 1 ? 's' : ''} granted`;
        }
      }
    } catch {
      permText = 'Unable to read permissions';
    }
  } else {
    permText = 'Permissions API unavailable';
  }

  permsEl.textContent = permText;

  if (needsAction) {
    callout.removeAttribute('hidden');
    calloutTitle.textContent = actionText;
    calloutDesc.textContent = actionDesc;
    if (calloutAction) {
      calloutAction.removeAttribute('hidden');
      calloutAction.textContent = 'Go to Monitoring';
    }
  } else {
    callout.setAttribute('hidden', '');
  }
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

  // Monitoring mode
  currentMode = settings.monitoringMode;
  for (const radio of modeRadios) {
    radio.checked = radio.value === settings.monitoringMode;
  }
  updateAllowlistVisibility(settings.monitoringMode);

  // Severity filter
  const filterSet = new Set<string>(settings.severityFilter);
  for (const cb of severityCheckboxes) {
    cb.checked = filterSet.has(cb.value);
  }

  // History
  retainDaysInput.value = String(settings.retainHistoryDays);
  maxHistoryInput.value = String(settings.maxHistoryPerOrigin ?? DEFAULT_SETTINGS.maxHistoryPerOrigin);
  alwaysSensitiveInput.value = settings.sensitiveCookieNames.join(', ');
  alwaysIgnoreInput.value = settings.ignoredCookieNames.join(', ');
  evalModeToggle.checked = Boolean(settings.evaluationMode);

  // Appearance
  applyThemeRadio(settings.theme ?? DEFAULT_SETTINGS.theme ?? 'system');
  applyDensityRadio(settings.density ?? DEFAULT_SETTINGS.density ?? 'comfortable');
  applyMotionRadio(settings.reducedMotion ?? DEFAULT_SETTINGS.reducedMotion ?? 'system');
  applyTheme(settings.theme ?? 'system');
  applyDensity(settings.density ?? 'comfortable');
  applyMotion(settings.reducedMotion ?? 'system');

  // Allowlist
  try {
    const granted = await PermissionsService.getAllGrantedOrigins();
    workingOrigins = granted;
  } catch {
    workingOrigins = [];
  }
  renderAllowlist();
  await checkAndRenderBroadConflict();

  // Populate home view
  await refreshHomeView();

  // Snapshot for dirty tracking
  initialSettingsSnapshot = getFormStateString();
  isDirty = false;
  updateDirtyUI();
}

function applyThemeRadio(value: string): void {
  const radios = document.querySelectorAll<HTMLInputElement>('input[name="theme"]');
  radios.forEach((r) => { r.checked = r.value === value; });
}

function applyDensityRadio(value: string): void {
  const radios = document.querySelectorAll<HTMLInputElement>('input[name="density"]');
  radios.forEach((r) => { r.checked = r.value === value; });
}

function applyMotionRadio(value: string): void {
  const radios = document.querySelectorAll<HTMLInputElement>('input[name="reducedMotion"]');
  radios.forEach((r) => { r.checked = r.value === value; });
}

/* ================================================================
   Appearance — live preview (applied immediately on change)
   ================================================================ */

function wireAppearanceLivePreview(): void {
  const themeRadios = document.querySelectorAll<HTMLInputElement>('input[name="theme"]');
  themeRadios.forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) applyTheme(r.value);
    });
  });

  const densityRadios = document.querySelectorAll<HTMLInputElement>('input[name="density"]');
  densityRadios.forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) applyDensity(r.value);
    });
  });

  const motionRadios = document.querySelectorAll<HTMLInputElement>('input[name="reducedMotion"]');
  motionRadios.forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) applyMotion(r.value);
    });
  });
}

function applyTheme(theme: string): void {
  applyAppearance(theme as 'system' | 'dark' | 'light');
}

function applyDensity(density: string): void {
  applyAppearance(undefined, density as 'comfortable' | 'compact');
}

function applyMotion(motion: string): void {
  applyAppearance(undefined, undefined, motion as 'system' | 'always' | 'never');
}

/* ================================================================
   Save handler
   ================================================================ */

function wireSaveButton(): void {
  saveBtn.addEventListener('click', () => { void handleSave(); });
}

function wireDiscardButton(): void {
  discardBtn.addEventListener('click', () => { void loadAndPopulate(); });
}

async function handleSave(): Promise<void> {
  clearStatus();

  const settings = readFormValues();

  if (settings.retainHistoryDays < 0 || settings.retainHistoryDays > 365) {
    setStatus('Retain days must be between 0 and 365.', true); return;
  }
  if (settings.maxHistoryPerOrigin < 1 || settings.maxHistoryPerOrigin > 50) {
    setStatus('Max history per origin must be between 1 and 50.', true); return;
  }

  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  try {
    await SettingsService.updateSettings(settings);
    const resp = (await sendToBackground({ type: 'SETTINGS_CHANGED', settings })) as {
      success?: boolean;
      error?: string;
    };
    if (resp?.success === false) {
      throw new Error(resp.error ?? 'Failed to apply settings transition');
    }
    initialSettingsSnapshot = getFormStateString();
    isDirty = false;
    updateDirtyUI();
    setStatus('Settings saved ✓', false);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : 'Failed to save settings.';
    setStatus(`Failed to save settings: ${errorMsg}`, true);
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save settings';
  }

  setTimeout(() => {
    if (getFormStateString() === initialSettingsSnapshot) clearStatus();
  }, 3000);
}

/* ================================================================
   Read current form values → Settings object
   ================================================================ */

function readFormValues(): Settings {
  let monitoringMode: Settings['monitoringMode'] = 'per-site';
  for (const radio of modeRadios) {
    if (radio.checked) {
      const val = radio.value;
      if (val === 'per-site' || val === 'all-sites' || val === 'off') {
        monitoringMode = val;
      }
      break;
    }
  }

  const severityFilter: Severity[] = [];
  for (const cb of severityCheckboxes) {
    if (cb.checked) {
      const val = cb.value as Severity;
      if (ALL_SEVERITIES.includes(val)) severityFilter.push(val);
    }
  }

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

  // Appearance
  let theme: Settings['theme'] = 'system';
  const themeRadios = document.querySelectorAll<HTMLInputElement>('input[name="theme"]');
  themeRadios.forEach((r) => { if (r.checked && (r.value === 'system' || r.value === 'dark' || r.value === 'light')) theme = r.value; });

  let density: Settings['density'] = 'comfortable';
  const densityRadios = document.querySelectorAll<HTMLInputElement>('input[name="density"]');
  densityRadios.forEach((r) => { if (r.checked && (r.value === 'comfortable' || r.value === 'compact')) density = r.value; });

  let reducedMotion: Settings['reducedMotion'] = 'system';
  const motionRadios = document.querySelectorAll<HTMLInputElement>('input[name="reducedMotion"]');
  motionRadios.forEach((r) => { if (r.checked && (r.value === 'system' || r.value === 'always' || r.value === 'never')) reducedMotion = r.value; });

  return {
    schemaVersion: 2,
    monitoringMode,
    allowedOrigins: [...workingOrigins],
    severityFilter,
    retainHistoryDays,
    maxHistoryPerOrigin,
    sensitiveCookieNames: sensitive,
    ignoredCookieNames: ignored,
    evaluationMode: evalModeToggle.checked,
    theme,
    density,
    reducedMotion,
  };
}

/* ================================================================
   Allowlist rendering (createElement only — no innerHTML)
   ================================================================ */

function renderAllowlist(): void {
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

function buildAllowlistItem(origin: string): HTMLLIElement {
  const li = document.createElement('li');
  li.className = 'allowlist-item';

  const originSpan = document.createElement('span');
  originSpan.className = 'allowlist-origin';
  originSpan.textContent = origin;
  originSpan.title = origin;

  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'allowlist-actions';

  const purgeBtn = document.createElement('button');
  purgeBtn.type = 'button';
  purgeBtn.className = 'btn-purge';
  purgeBtn.textContent = 'Delete stored data';
  purgeBtn.title = `Delete stored audit history and graph data for ${origin}`;
  purgeBtn.setAttribute('aria-label', `Delete stored audit history and graph data for ${origin}`);
  purgeBtn.addEventListener('click', () => { void purgeOrigin(origin); });

  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'btn-remove';
  removeBtn.textContent = 'Remove';
  removeBtn.title = `Revoke browser host permission for ${origin}`;
  removeBtn.setAttribute('aria-label', `Revoke browser host permission for ${origin}`);
  removeBtn.addEventListener('click', () => { removeOrigin(origin); });

  actionsDiv.appendChild(purgeBtn);
  actionsDiv.appendChild(removeBtn);
  li.appendChild(originSpan);
  li.appendChild(actionsDiv);
  return li;
}

async function purgeOrigin(origin: string): Promise<void> {
  try {
    await LocalStorage.purgeOriginData(origin);
    setStatus(`Deleted stored data for ${origin}`, false);
  } catch {
    setStatus(`Failed to delete stored data for ${origin}`, true);
  }
}

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
          for (const r of modeRadios) { r.checked = r.value === currentMode; }
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
  const hasComplete = await PermissionsService.hasCompleteBroadGrant();

  if (currentMode === 'per-site' && broadActive) {
    modeConflictBanner.removeAttribute('hidden');
  } else if (currentMode === 'all-sites' && !hasComplete) {
    modeConflictBanner.setAttribute('hidden', '');
    setStatus('All-sites mode requires complete broad permissions. Capture is currently paused.', true);
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
    for (const r of modeRadios) { r.checked = r.value === 'all-sites'; }
    updateAllowlistVisibility('all-sites');
    modeConflictBanner.setAttribute('hidden', '');
    void handleSave();
  });
}

function updateAllowlistVisibility(mode: string): void {
  const visible = mode === 'per-site';
  if (visible) {
    sectionAllowlist.removeAttribute('hidden');
  } else {
    sectionAllowlist.setAttribute('hidden', '');
  }
}

/* ================================================================
   Data management
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
    if (!confirm('Reset ALL local ACULYX data? This cannot be undone.')) return;
    void sendToBackground({ type: 'RESET_ALL_DATA' })
      .then(() => {
        showDataStatus('All data reset. Reloading…');
        setTimeout(() => window.location.reload(), 1500);
      })
      .catch((err: unknown) => showDataStatus(`Failed: ${String(err)}`, true));
  });
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
    theme: current.theme ?? 'system',
    density: current.density ?? 'comfortable',
    reducedMotion: current.reducedMotion ?? 'system',
  });
}

function updateDirtyState(): void {
  if (!initialSettingsSnapshot) return;
  isDirty = getFormStateString() !== initialSettingsSnapshot;
  updateDirtyUI();
}

function updateDirtyUI(): void {
  navDirtyBadge.hidden = !isDirty;
  navDirtyBadge.setAttribute('aria-hidden', String(!isDirty));
  discardBtn.hidden = !isDirty;
  if (isDirty) {
    setStatus('Unsaved changes', false, true);
  } else if (saveStatus.classList.contains('dirty')) {
    clearStatus();
  }
}

function wireDirtyTracking(): void {
  for (const radio of modeRadios) { radio.addEventListener('change', updateDirtyState); }
  for (const cb of severityCheckboxes) { cb.addEventListener('change', updateDirtyState); }
  retainDaysInput.addEventListener('input', updateDirtyState);
  maxHistoryInput.addEventListener('input', updateDirtyState);
  alwaysSensitiveInput.addEventListener('input', updateDirtyState);
  alwaysIgnoreInput.addEventListener('input', updateDirtyState);
  evalModeToggle.addEventListener('change', updateDirtyState);

  const allAppearanceRadios = document.querySelectorAll<HTMLInputElement>(
    'input[name="theme"], input[name="density"], input[name="reducedMotion"]'
  );
  allAppearanceRadios.forEach((r) => r.addEventListener('change', updateDirtyState));
}

/* ================================================================
   Unsaved changes dialog
   ================================================================ */

function wireUnsavedDialog(): void {
  const dialogSave = getEl<HTMLButtonElement>('dialog-save');
  const dialogDiscard = getEl<HTMLButtonElement>('dialog-discard');
  const dialogCancel = getEl<HTMLButtonElement>('dialog-cancel');

  dialogSave.addEventListener('click', () => {
    unsavedDialog.close();
    void handleSave().then(() => {
      if (pendingNavSection !== null) {
        const target = pendingNavSection;
        pendingNavSection = null;
        activateSection(target);
      }
    });
  });

  dialogDiscard.addEventListener('click', () => {
    unsavedDialog.close();
    void loadAndPopulate().then(() => {
      if (pendingNavSection !== null) {
        const target = pendingNavSection;
        pendingNavSection = null;
        activateSection(target);
      }
    });
  });

  dialogCancel.addEventListener('click', () => {
    unsavedDialog.close();
    pendingNavSection = null;
  });
}

function showUnsavedDialog(): void {
  if (typeof unsavedDialog.showModal === 'function') {
    unsavedDialog.showModal();
  }
}

/* ================================================================
   Status message helpers
   ================================================================ */

function setStatus(msg: string, isError: boolean, dirtyFlag: boolean = false): void {
  saveStatus.textContent = msg;
  saveStatus.className = 'save-status';
  if (isError) {
    saveStatus.classList.add('error');
  } else if (dirtyFlag) {
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

function getEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el as T;
}

/* Permissions change listeners */
if (typeof chrome !== 'undefined' && typeof chrome.permissions !== 'undefined') {
  if (typeof chrome.permissions.onRemoved !== 'undefined') {
    chrome.permissions.onRemoved.addListener(() => {
      void PermissionsService.getAllGrantedOrigins().then((origins) => {
        workingOrigins = origins;
        renderAllowlist();
        void checkAndRenderBroadConflict();
        void refreshHomeView();
      });
    });
  }
  if (typeof chrome.permissions.onAdded !== 'undefined') {
    chrome.permissions.onAdded.addListener(() => {
      void PermissionsService.getAllGrantedOrigins().then((origins) => {
        workingOrigins = origins;
        renderAllowlist();
        void checkAndRenderBroadConflict();
        void refreshHomeView();
      });
    });
  }
}
