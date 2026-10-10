/**
 * options.ts — ACULYX options page logic
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All DOM manipulation via createElement / textContent / appendChild
 *  - Only chrome.* APIs (no fetch / XHR)
 *  - Section router: JS-driven, no page reloads
 */

import type { Settings, Severity, ScopeProfile } from '../shared/types';
import { SettingsService, normalizeCookieList, resolveCookieOverlaps } from '../shared/settings';
import { PermissionsService } from '../background/permissions';
import { LocalStorage } from '../shared/storage';
import { sendToBackground } from '../shared/messaging';
import { SEVERITY_ORDER, DEFAULT_SETTINGS } from '../shared/constants';
import { applyAppearance } from '../shared/appearance';
import { TriageStore } from '../shared/reporting';
import { validateScopeRule } from '../shared/scope/validate';

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
let triageCountBadge: HTMLSpanElement;
let btnClearTriage: HTMLButtonElement;
let activeScopeProfileSelect: HTMLSelectElement;
let scopeProfilesContainer: HTMLElement;
let btnAddScopeProfile: HTMLButtonElement;
let leadsEnabledToggle: HTMLInputElement;
let deepModeToggle: HTMLInputElement;
let optionsReconHostsCount: HTMLElement;
let optionsReconEndpointsCount: HTMLElement;
let optionsReconParamsCount: HTMLElement;
let btnResetReconMemory: HTMLButtonElement;
let reconResetStatus: HTMLSpanElement;
let hunterEnabledToggle: HTMLInputElement;
let hunterUserAgent: HTMLInputElement;
let hunterMaxRps: HTMLInputElement;
let hunterCustomHeaders: HTMLTextAreaElement;
let currentMode: Settings['monitoringMode'] = 'per-site';
let pendingNavSection: string | null = null;

/** In-memory working copy of the allowedOrigins array. */
let workingOrigins: string[] = [];
let workingScopeProfiles: ScopeProfile[] = [];
let workingActiveScopeProfileId: string | null = null;
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
  triageCountBadge     = getEl<HTMLSpanElement>('triage-count-badge');
  btnClearTriage       = getEl<HTMLButtonElement>('btn-clear-triage');
  activeScopeProfileSelect = getEl<HTMLSelectElement>('active-scope-profile-select');
  scopeProfilesContainer   = getEl<HTMLElement>('scope-profiles-container');
  btnAddScopeProfile       = getEl<HTMLButtonElement>('btn-add-scope-profile');

  leadsEnabledToggle         = getEl<HTMLInputElement>('leads-enabled-toggle');
  deepModeToggle             = getEl<HTMLInputElement>('deep-mode-toggle');
  optionsReconHostsCount     = getEl<HTMLElement>('options-recon-hosts-count');
  optionsReconEndpointsCount = getEl<HTMLElement>('options-recon-endpoints-count');
  optionsReconParamsCount    = getEl<HTMLElement>('options-recon-params-count');
  btnResetReconMemory        = getEl<HTMLButtonElement>('btn-reset-recon-memory');
  reconResetStatus           = getEl<HTMLSpanElement>('recon-reset-status');
  hunterEnabledToggle        = getEl<HTMLInputElement>('hunter-enabled-toggle');
  hunterUserAgent            = getEl<HTMLInputElement>('hunter-user-agent');
  hunterMaxRps               = getEl<HTMLInputElement>('hunter-max-rps');
  hunterCustomHeaders        = getEl<HTMLTextAreaElement>('hunter-custom-headers');

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
  wireTriageManagement();
  wireScopeManagement();
  wireLeadsAndReconManagement();

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

const SECTION_IDS = ['home', 'monitoring', 'findings', 'cookies', 'history', 'scope', 'appearance', 'advanced', 'about'];

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

  // Scope profiles
  workingScopeProfiles = settings.scopeProfiles !== undefined
    ? settings.scopeProfiles.map((p) => ({ ...p, rules: p.rules.map((r) => ({ ...r })) }))
    : [];
  workingActiveScopeProfileId = settings.activeScopeProfileId ?? null;
  renderScopeProfiles();

  // Leads & Recon
  leadsEnabledToggle.checked = Boolean(settings.leadsEnabled);
  deepModeToggle.checked = Boolean(settings.deepModeEnabled);
  hunterEnabledToggle.checked = Boolean(settings.hunterConfig?.enabled);
  hunterUserAgent.value = settings.hunterConfig?.customUserAgent ?? '';
  hunterMaxRps.value = String(settings.hunterConfig?.maxRequestsPerSecond ?? 1);
  if (settings.hunterConfig?.customHeaders) {
    const lines = Object.entries(settings.hunterConfig.customHeaders).map(([k, v]) => `${k}: ${v}`).join('\n');
    hunterCustomHeaders.value = lines;
  } else {
    hunterCustomHeaders.value = '';
  }
  void refreshReconCounts();

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
    scopeProfiles: [...workingScopeProfiles],
    activeScopeProfileId: workingActiveScopeProfileId,
    leadsEnabled: leadsEnabledToggle.checked,
    deepModeEnabled: deepModeToggle.checked,
    hunterConfig: {
      enabled: hunterEnabledToggle.checked,
      customUserAgent: hunterUserAgent.value.trim() || undefined,
      maxRequestsPerSecond: Math.max(0.1, Math.min(5, parseFloat(hunterMaxRps.value) || 1)),
      customHeaders: (() => {
        const headers: Record<string, string> = {};
        for (const line of hunterCustomHeaders.value.split('\n')) {
          const idx = line.indexOf(':');
          if (idx > 0) {
            const k = line.slice(0, idx).trim();
            const v = line.slice(idx + 1).trim();
            if (k) headers[k] = v;
          }
        }
        return Object.keys(headers).length > 0 ? headers : undefined;
      })(),
    },
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
    activeScopeProfileId: current.activeScopeProfileId ?? null,
    scopeProfiles: current.scopeProfiles ?? [],
    leadsEnabled: current.leadsEnabled,
    deepModeEnabled: current.deepModeEnabled,
    hunterConfig: current.hunterConfig,
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
  leadsEnabledToggle.addEventListener('change', updateDirtyState);
  deepModeToggle.addEventListener('change', updateDirtyState);
  hunterEnabledToggle.addEventListener('change', updateDirtyState);
  hunterUserAgent.addEventListener('input', updateDirtyState);
  hunterMaxRps.addEventListener('input', updateDirtyState);
  hunterCustomHeaders.addEventListener('input', updateDirtyState);

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
   Researcher Triage Management
   ================================================================ */

function wireTriageManagement(): void {
  const refreshTriageCount = async (): Promise<void> => {
    try {
      const annotations = await TriageStore.getAnnotations();
      const count = Object.keys(annotations).length;
      triageCountBadge.textContent = `${count} triaged finding${count === 1 ? '' : 's'}`;
    } catch {
      triageCountBadge.textContent = '0 triaged findings';
    }
  };

  btnClearTriage.addEventListener('click', () => {
    const confirmed = window.confirm('Reset all researcher triage annotations and notes? This cannot be undone.');
    if (confirmed) {
      void TriageStore.clearAll().then(() => refreshTriageCount());
    }
  });

  void refreshTriageCount();
}

/* ================================================================
   Scope Profiles Management (Bug-Bounty Programs)
   ================================================================ */

function wireScopeManagement(): void {
  activeScopeProfileSelect.addEventListener('change', () => {
    workingActiveScopeProfileId = activeScopeProfileSelect.value.length > 0 ? activeScopeProfileSelect.value : null;
    updateDirtyState();
  });

  btnAddScopeProfile.addEventListener('click', () => {
    const newId = `profile-${Date.now()}`;
    const newProfile: ScopeProfile = {
      id: newId,
      name: `Program ${workingScopeProfiles.length + 1}`,
      rules: [
        {
          pattern: '*.example.com',
          type: 'include',
        },
      ],
      lastReviewed: Date.now(),
    };
    workingScopeProfiles.push(newProfile);
    if (workingActiveScopeProfileId === null || workingActiveScopeProfileId.length === 0) {
      workingActiveScopeProfileId = newId;
    }
    renderScopeProfiles();
    updateDirtyState();
  });
}

function renderScopeProfiles(): void {
  // 1. Populate dropdown
  while (activeScopeProfileSelect.firstChild !== null) {
    activeScopeProfileSelect.removeChild(activeScopeProfileSelect.firstChild);
  }

  const noneOpt = document.createElement('option');
  noneOpt.value = '';
  noneOpt.textContent = '(None — Global Unscoped Monitoring)';
  activeScopeProfileSelect.appendChild(noneOpt);

  for (const prof of workingScopeProfiles) {
    const opt = document.createElement('option');
    opt.value = prof.id;
    opt.textContent = prof.name;
    if (prof.id === workingActiveScopeProfileId) {
      opt.selected = true;
    }
    activeScopeProfileSelect.appendChild(opt);
  }

  if (workingActiveScopeProfileId === null || workingActiveScopeProfileId.length === 0) {
    noneOpt.selected = true;
  }

  // 2. Populate profiles list
  while (scopeProfilesContainer.firstChild !== null) {
    scopeProfilesContainer.removeChild(scopeProfilesContainer.firstChild);
  }

  if (workingScopeProfiles.length === 0) {
    const emptyP = document.createElement('p');
    emptyP.className = 'field-hint';
    emptyP.textContent = 'No scope profiles defined yet. Click "+ New Profile" to configure authorized targets for a bounty program.';
    scopeProfilesContainer.appendChild(emptyP);
    return;
  }

  workingScopeProfiles.forEach((profile, profIdx) => {
    const card = document.createElement('div');
    card.className = 'scope-profile-card field-row';
    card.style.flexDirection = 'column';
    card.style.alignItems = 'stretch';
    card.style.border = '1px solid var(--border-color, #2a2e39)';
    card.style.borderRadius = '6px';
    card.style.padding = '12px';
    card.style.marginBottom = '12px';

    // Header with name input and delete button
    const headerDiv = document.createElement('div');
    headerDiv.className = 'flex-between';
    headerDiv.style.display = 'flex';
    headerDiv.style.justifyContent = 'space-between';
    headerDiv.style.alignItems = 'center';
    headerDiv.style.marginBottom = '8px';

    const nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.className = 'text-input';
    nameInput.value = profile.name;
    nameInput.placeholder = 'Program / Profile Name';
    nameInput.style.fontWeight = 'bold';
    nameInput.style.maxWidth = '240px';
    nameInput.addEventListener('input', () => {
      profile.name = nameInput.value.trim() || `Program ${profIdx + 1}`;
      updateDirtyState();
      const opt = activeScopeProfileSelect.querySelector(`option[value="${profile.id}"]`);
      if (opt) opt.textContent = profile.name;
    });

    const delProfBtn = document.createElement('button');
    delProfBtn.type = 'button';
    delProfBtn.className = 'btn-danger btn-sm';
    delProfBtn.textContent = 'Delete Profile';
    delProfBtn.addEventListener('click', () => {
      workingScopeProfiles.splice(profIdx, 1);
      if (workingActiveScopeProfileId === profile.id) {
        workingActiveScopeProfileId = workingScopeProfiles[0]?.id ?? null;
      }
      renderScopeProfiles();
      updateDirtyState();
    });

    headerDiv.appendChild(nameInput);
    headerDiv.appendChild(delProfBtn);
    card.appendChild(headerDiv);

    // Rules list
    const rulesTable = document.createElement('div');
    rulesTable.className = 'scope-rules-table';

    profile.rules.forEach((rule, ruleIdx) => {
      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.style.gap = '8px';
      row.style.marginBottom = '4px';

      const typeBadge = document.createElement('span');
      typeBadge.textContent = rule.type.toUpperCase();
      typeBadge.style.fontSize = '11px';
      typeBadge.style.padding = '2px 6px';
      typeBadge.style.borderRadius = '3px';
      typeBadge.style.fontWeight = 'bold';
      typeBadge.style.color = '#fff';
      typeBadge.style.backgroundColor = rule.type === 'include' ? '#27ae60' : '#c0392b';

      const patternSpan = document.createElement('code');
      patternSpan.textContent = rule.pattern;
      patternSpan.style.flex = '1';

      const delRuleBtn = document.createElement('button');
      delRuleBtn.type = 'button';
      delRuleBtn.className = 'btn-sm btn-remove';
      delRuleBtn.textContent = '×';
      delRuleBtn.title = 'Remove rule';
      delRuleBtn.addEventListener('click', () => {
        profile.rules.splice(ruleIdx, 1);
        renderScopeProfiles();
        updateDirtyState();
      });

      row.appendChild(typeBadge);
      row.appendChild(patternSpan);
      row.appendChild(delRuleBtn);
      rulesTable.appendChild(row);
    });

    card.appendChild(rulesTable);

    // Add Rule inline form
    const addRuleDiv = document.createElement('div');
    addRuleDiv.style.display = 'flex';
    addRuleDiv.style.alignItems = 'center';
    addRuleDiv.style.gap = '8px';
    addRuleDiv.style.marginTop = '8px';

    const rulePatternInput = document.createElement('input');
    rulePatternInput.type = 'text';
    rulePatternInput.placeholder = '*.domain.com or host:port';
    rulePatternInput.className = 'text-input';
    rulePatternInput.style.flex = '1';

    const ruleTypeSelect = document.createElement('select');
    ruleTypeSelect.className = 'select-input';
    const incOpt = document.createElement('option');
    incOpt.value = 'include';
    incOpt.textContent = 'Include';
    const excOpt = document.createElement('option');
    excOpt.value = 'exclude';
    excOpt.textContent = 'Exclude';
    ruleTypeSelect.appendChild(incOpt);
    ruleTypeSelect.appendChild(excOpt);

    const addRuleBtn = document.createElement('button');
    addRuleBtn.type = 'button';
    addRuleBtn.className = 'btn-secondary btn-sm';
    addRuleBtn.textContent = 'Add Rule';

    const ruleErrorMsg = document.createElement('span');
    ruleErrorMsg.style.color = '#e74c3c';
    ruleErrorMsg.style.fontSize = '12px';
    ruleErrorMsg.style.marginLeft = '8px';

    addRuleBtn.addEventListener('click', () => {
      ruleErrorMsg.textContent = '';
      const pat = rulePatternInput.value.trim();
      const typ = ruleTypeSelect.value as 'include' | 'exclude';
      const validRes = validateScopeRule({ pattern: pat, type: typ });
      if (!validRes.valid) {
        ruleErrorMsg.textContent = validRes.error ?? 'Invalid rule pattern';
        return;
      }
      profile.rules.push({ pattern: pat, type: typ });
      rulePatternInput.value = '';
      renderScopeProfiles();
      updateDirtyState();
    });

    addRuleDiv.appendChild(rulePatternInput);
    addRuleDiv.appendChild(ruleTypeSelect);
    addRuleDiv.appendChild(addRuleBtn);
    card.appendChild(addRuleDiv);
    card.appendChild(ruleErrorMsg);

    scopeProfilesContainer.appendChild(card);
  });
}

/* ================================================================
   Lead Radar & Recon Intelligence
   ================================================================ */

function wireLeadsAndReconManagement(): void {
  btnResetReconMemory.addEventListener('click', () => {
    const confirmed = window.confirm('Reset all accumulated reconnaissance memory across all origins?');
    if (!confirmed) return;

    btnResetReconMemory.disabled = true;
    void sendToBackground({ type: 'RECON_RESET' })
      .then(() => {
        optionsReconHostsCount.textContent = '0';
        optionsReconEndpointsCount.textContent = '0';
        optionsReconParamsCount.textContent = '0';
        reconResetStatus.textContent = 'Recon memory cleared ✓';
        reconResetStatus.className = 'status-message status-success';
      })
      .catch((err: unknown) => {
        reconResetStatus.textContent = `Failed to reset: ${String(err)}`;
        reconResetStatus.className = 'status-message status-error';
      })
      .finally(() => {
        btnResetReconMemory.disabled = false;
        setTimeout(() => {
          reconResetStatus.textContent = '';
          reconResetStatus.className = 'status-message';
        }, 3000);
      });
  });
}

async function refreshReconCounts(): Promise<void> {
  try {
    const res = await sendToBackground({ type: 'RECON_GET' }) as {
      type: string;
      memory?: {
        hosts?: unknown[];
        endpoints?: unknown[];
        params?: unknown[];
      };
    };
    if (res && res.type === 'RECON_GET_RESPONSE' && res.memory) {
      optionsReconHostsCount.textContent = String(res.memory.hosts?.length ?? 0);
      optionsReconEndpointsCount.textContent = String(res.memory.endpoints?.length ?? 0);
      optionsReconParamsCount.textContent = String(res.memory.params?.length ?? 0);
    }
  } catch {
    // Background service worker might not be responding yet
  }
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
