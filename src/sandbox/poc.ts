/**
 * poc.ts — Client-side verification sandbox logic
 *
 * Runs inside a sandboxed iframe/tab with unique origin (null / sandboxed origin).
 * Strictly ethical verification tool for defensive testing.
 *
 * Rules:
 *  - ZERO innerHTML
 *  - Only safe DOM manipulation (textContent, createElement, etc.)
 */

function getEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`Required element #${id} not found in DOM`);
  }
  return el as T;
}

document.addEventListener('DOMContentLoaded', () => {
  const gateOverlay = getEl<HTMLDivElement>('gate-overlay');
  const gateCheckbox = getEl<HTMLInputElement>('gate-agree-checkbox');
  const gateProceedBtn = getEl<HTMLButtonElement>('gate-proceed-btn');

  const targetUrlDisplay = getEl<HTMLSpanElement>('target-url-display');
  const pocTypeBadge = getEl<HTMLSpanElement>('poc-type-badge');

  const tabClickjacking = getEl<HTMLButtonElement>('tab-clickjacking');
  const tabCoop = getEl<HTMLButtonElement>('tab-coop');
  const sectionClickjacking = getEl<HTMLElement>('section-clickjacking');
  const sectionCoop = getEl<HTMLElement>('section-coop');

  const opacitySlider = getEl<HTMLInputElement>('opacity-slider');
  const opacityVal = getEl<HTMLSpanElement>('opacity-val');
  const frameWrapper = getEl<HTMLDivElement>('frame-wrapper');
  const targetIframe = getEl<HTMLIFrameElement>('target-iframe');
  const frameStatusText = getEl<HTMLSpanElement>('frame-status-text');
  const decoyBtn = getEl<HTMLButtonElement>('decoy-btn');
  const decoyClickCounter = getEl<HTMLDivElement>('decoy-click-counter');

  const coopLaunchBtn = getEl<HTMLButtonElement>('coop-launch-btn');
  const coopTestBtn = getEl<HTMLButtonElement>('coop-test-btn');
  const coopStatusText = getEl<HTMLSpanElement>('coop-status-text');
  const coopResults = getEl<HTMLDivElement>('coop-results');
  const coopChildState = getEl<HTMLSpanElement>('coop-child-state');
  const coopCouplingState = getEl<HTMLSpanElement>('coop-coupling-state');
  const coopVulnAssessment = getEl<HTMLSpanElement>('coop-vuln-assessment');

  // Parse parameters
  const params = new URLSearchParams(window.location.search);
  const rawTarget = params.get('target') ?? '';
  const initialType = (params.get('type') ?? 'clickjacking').toLowerCase();

  let targetUrl = '';
  try {
    const parsed = new URL(rawTarget);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      targetUrl = parsed.href;
    }
  } catch {
    targetUrl = '';
  }

  if (targetUrl.length === 0) {
    targetUrlDisplay.textContent = 'Invalid or missing target URL parameter';
    frameStatusText.textContent = 'Error: Invalid target URL provided.';
    return;
  }

  targetUrlDisplay.textContent = targetUrl;

  // Per-load authorization confirmation (zero localStorage dependency in sandboxed context)
  gateOverlay.hidden = false;
  gateCheckbox.addEventListener('change', () => {
    gateProceedBtn.disabled = !gateCheckbox.checked;
  });

  gateProceedBtn.addEventListener('click', () => {
    gateOverlay.hidden = true;
    initializePoc();
  });

  function initializePoc(): void {
    // Select initial tab
    if (initialType === 'coop') {
      selectTab('coop');
    } else {
      selectTab('clickjacking');
    }

    // Set iframe source
    targetIframe.src = targetUrl;
    frameStatusText.textContent =
      'Target URL loaded in frame. If the frame remains blank or fails to load, XFO or CSP frame-ancestors is active.';

    targetIframe.addEventListener('load', () => {
      frameStatusText.textContent =
        'Frame load event fired. If content is visible, page is vulnerable to UI redressing (Clickjacking).';
    });

    targetIframe.addEventListener('error', () => {
      frameStatusText.textContent =
        'Frame loading blocked by browser security policy (X-Frame-Options or Content-Security-Policy).';
    });
  }

  // Tab switching
  function selectTab(type: 'clickjacking' | 'coop'): void {
    if (type === 'clickjacking') {
      tabClickjacking.classList.add('active');
      tabCoop.classList.remove('active');
      sectionClickjacking.hidden = false;
      sectionCoop.hidden = true;
      pocTypeBadge.textContent = 'Clickjacking Verification';
    } else {
      tabCoop.classList.add('active');
      tabClickjacking.classList.remove('active');
      sectionCoop.hidden = false;
      sectionClickjacking.hidden = true;
      pocTypeBadge.textContent = 'COOP Verification';
    }
  }

  tabClickjacking.addEventListener('click', () => selectTab('clickjacking'));
  tabCoop.addEventListener('click', () => selectTab('coop'));

  // Clickjacking Controls
  opacitySlider.addEventListener('input', () => {
    const val = parseInt(opacitySlider.value, 10);
    const opacityFloat = val / 100;
    frameWrapper.style.opacity = opacityFloat.toString();
    opacityVal.textContent = `${val}%`;
  });

  let decoyClicks = 0;
  decoyBtn.addEventListener('click', () => {
    decoyClicks++;
    decoyClickCounter.textContent = `Clicks registered on decoy: ${decoyClicks}`;
  });

  // COOP Reverse-Tabnabbing Controls
  let openedWindow: Window | null = null;

  coopLaunchBtn.addEventListener('click', () => {
    try {
      openedWindow = window.open(targetUrl, '_blank');
      if (openedWindow !== null) {
        coopStatusText.textContent =
          'Child window opened. Click "2. Test Opener Coupling" to evaluate window.opener isolation.';
        coopTestBtn.disabled = false;
      } else {
        coopStatusText.textContent =
          'Popup was blocked by the browser. Please allow popups for this sandboxed tool and retry.';
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      coopStatusText.textContent = `Error launching window: ${msg}`;
    }
  });

  coopTestBtn.addEventListener('click', () => {
    if (openedWindow === null) {
      coopStatusText.textContent = 'No active window launched. Click Step 1 first.';
      return;
    }

    coopResults.hidden = false;

    if (openedWindow.closed) {
      coopChildState.textContent = 'Closed by user';
      coopCouplingState.textContent = 'N/A';
      coopVulnAssessment.textContent = 'Window was closed. Re-launch to test.';
      coopVulnAssessment.className = 'result-value';
      return;
    }

    coopChildState.textContent = 'Active (Open)';

    // In browsers where COOP is not same-origin, openedWindow maintains opener coupling
    try {
      // If Cross-Origin-Opener-Policy: same-origin was set, openedWindow.closed is true or window reference is severed/null
      const isStillCoupled = !openedWindow.closed;
      if (isStillCoupled) {
        coopCouplingState.textContent = 'Coupled (Browsing context group shared)';
        coopVulnAssessment.textContent =
          'VULNERABLE — Page lacks COOP: same-origin; opener context is coupled to opener.';
        coopVulnAssessment.className = 'result-value vulnerable';
        coopStatusText.textContent =
          'Vulnerability confirmed: External opener maintains a reference to the opened target browsing context.';
      } else {
        coopCouplingState.textContent = 'Decoupled (Opener severed by COOP)';
        coopVulnAssessment.textContent = 'PROTECTED — COOP isolated the browsing context.';
        coopVulnAssessment.className = 'result-value protected';
        coopStatusText.textContent = 'Protection confirmed: Opener context decoupled.';
      }
    } catch {
      coopCouplingState.textContent = 'Cross-origin restricted';
      coopVulnAssessment.textContent = 'Opener coupling active across origin boundary';
      coopVulnAssessment.className = 'result-value vulnerable';
    }
  });
});
