/**
 * sidepanel.ts — Investigation Workspace & Attack Surface controller.
 *
 * Architecture:
 *  - 4-tab investigation model: Overview, Findings, Surface, Activity
 *  - Full functional parity: Graph, Radar, Leads, Chains, Recon, Timeline
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML (pure DOM & SVG text APIs)
 *  - d3-force simulation layout for Attack Surface Graph
 *  - Accessible table alternative (#node-list-table) via #toggle-node-table-btn
 *  - Security confirmation gates: Hunter 2-step gate, Credential liveness 4-step gate
 *  - Safe in-scope cURL export
 *  - Keyboard shortcuts (Ctrl+K palette, j/k navigation, p pin, v triage)
 */

import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type Simulation,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from 'd3-force';
import type {
  GraphNode,
  GraphEdge,
  AttackSurfaceGraph,
  TabState,
  SettingsV2,
  ApiEndpointState,
} from '../shared/types';
import type { Lead, ChainRule, ReconMemory } from '../leads/types';
import { sendToBackground } from '../shared/messaging';
import type {
  LeadStateUpdateMessage,
  PlanCredentialCheckResponse,
  ConfirmCredentialCheckResponse,
} from '../shared/messaging';
import { SIDEPANEL_PORT_NAME, DEFAULT_SETTINGS } from '../shared/constants';
import { SettingsService } from '../shared/settings';
import { PermissionsService, patternFromOrigin } from '../background/permissions';
import { isModeCaptureAllowed, isRestrictedUrl } from '../shared/gating';
import { registrableDomain } from '../rules/headers/subdomain-trust';
import { bootstrapAppearance, applyAppearance } from '../shared/appearance';
import {
  generateNameOnlyWordlist,
  formatLeadsReportMarkdown,
  formatLeadsReportJson,
  formatLeadsReportSarif,
} from '../leads/export/export';
import { CHAINS } from '../leads/chains/chains';
import { activeCapabilityOf, planActiveProbe } from '../leads/verify/active';

const SVG_NS = 'http://www.w3.org/2000/svg';
const WIDTH = 600;
const HEIGHT = 450;

interface SimNode extends SimulationNodeDatum, GraphNode {
  id: string;
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  source: SimNode | string;
  target: SimNode | string;
  type: GraphEdge['type'];
  severity: GraphEdge['severity'];
}

function getEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

function getSvgEl<T extends SVGElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing SVG element #${id}`);
  return el as unknown as T;
}

let activeSimulation: Simulation<SimNode, undefined> | null = null;
const nodePositions = new Map<string, { x: number; y: number }>();
let lastGraphKey = '';
let currentSettings: SettingsV2 = { ...DEFAULT_SETTINGS };

function graphTopologyKey(nodes: GraphNode[], edges: GraphEdge[]): string {
  const nodeIds = nodes.map((n) => n.hostname).sort().join(',');
  const edgeIds = edges.map((e) => `${e.source}>${e.target}`).sort().join(',');
  return `${nodeIds}|${edgeIds}`;
}

const FAMILIES: Array<{ id: string; name: string }> = [
  { id: 'F1', name: 'Secrets' },
  { id: 'F2', name: 'Endpoints' },
  { id: 'F3', name: 'Source Maps' },
  { id: 'F4', name: 'Auth' },
  { id: 'F5', name: 'Params' },
  { id: 'F6', name: 'CORS/Headers' },
  { id: 'F7', name: 'Response Body' },
  { id: 'F8', name: 'Cloud/Recon' },
];

document.addEventListener('DOMContentLoaded', () => {
  // ── Primary Navigation Tabs ──────────────────────────────────
  const tabOverview = getEl<HTMLButtonElement>('tab-overview');
  const tabFindings = getEl<HTMLButtonElement>('tab-findings');
  const tabSurface = getEl<HTMLButtonElement>('tab-surface');
  const tabActivity = getEl<HTMLButtonElement>('tab-activity');

  // Tab badges
  const tabLeadsBadge = getEl<HTMLSpanElement>('tab-leads-badge');
  const tabChainsBadge = getEl<HTMLSpanElement>('tab-chains-badge');
  const tabActivityBadge = getEl<HTMLSpanElement>('tab-activity-badge');

  // Views
  const viewOverview = getEl<HTMLDivElement>('view-overview');
  const viewFindings = getEl<HTMLDivElement>('view-findings');
  const viewSurface = getEl<HTMLDivElement>('view-surface');
  const viewActivity = getEl<HTMLDivElement>('view-activity');

  // Header controls
  const tierBadge = getEl<HTMLSpanElement>('tier-badge');
  const refreshBtn = getEl<HTMLButtonElement>('refresh-btn');
  const optionsLink = getEl<HTMLAnchorElement>('options-link');
  const paletteOpenBtn = getEl<HTMLButtonElement>('palette-open-btn');

  // Overview elements
  const overviewOriginVal = getEl<HTMLSpanElement>('overview-origin-val');
  const overviewModePill = getEl<HTMLSpanElement>('overview-mode-pill');
  const overviewApexVal = getEl<HTMLSpanElement>('overview-apex-val');
  const overviewGradeBadge = getEl<HTMLDivElement>('overview-grade-badge');
  const overviewScoreVal = getEl<HTMLSpanElement>('overview-score-val');
  const overviewQualityVal = getEl<HTMLSpanElement>('overview-quality-val');
  const spCaptureBar = getEl<HTMLDivElement>('sp-capture-bar');
  const spScanShuriken = document.getElementById('sp-scan-shuriken') as unknown as SVGSVGElement;
  const spCaptureStatus = getEl<HTMLSpanElement>('sp-capture-status');
  const spCaptureBtn = getEl<HTMLButtonElement>('sp-capture-btn');
  const spReloadCaptureBtn = getEl<HTMLButtonElement>('sp-reload-capture-btn');

  const overviewActionIcon = getEl<HTMLSpanElement>('overview-action-icon');
  const overviewActionText = getEl<HTMLParagraphElement>('overview-action-text');
  const overviewActionCta = getEl<HTMLButtonElement>('overview-action-cta');

  const overviewCoverageStatus = getEl<HTMLSpanElement>('overview-coverage-status');
  const overviewHopsVal = getEl<HTMLSpanElement>('overview-hops-val');
  const overviewCacheVal = getEl<HTMLSpanElement>('overview-cache-val');
  const overviewSwVal = getEl<HTMLSpanElement>('overview-sw-val');
  const overviewScopeVal = getEl<HTMLSpanElement>('overview-scope-val');
  const overviewBlindspotsContainer = getEl<HTMLDivElement>('overview-blindspots-container');
  const overviewBlindspotsList = getEl<HTMLUListElement>('overview-blindspots-list');

  const overviewHygieneCount = getEl<HTMLSpanElement>('overview-hygiene-count');
  const overviewHygieneList = getEl<HTMLDivElement>('overview-hygiene-list');
  const overviewHygieneEmpty = getEl<HTMLDivElement>('overview-hygiene-empty');

  const radarSeverityFilter = getEl<HTMLSelectElement>('radar-severity-filter');
  const spRadarRings = getSvgEl<SVGGElement>('sp-radar-rings');
  const spRadarAxes = getSvgEl<SVGGElement>('sp-radar-axes');
  const spRadarBlips = getSvgEl<SVGGElement>('sp-radar-blips');
  const statCountCritical = getEl<HTMLSpanElement>('stat-count-critical');
  const statCountHigh = getEl<HTMLSpanElement>('stat-count-high');
  const statCountMedium = getEl<HTMLSpanElement>('stat-count-medium');
  const statCountLow = getEl<HTMLSpanElement>('stat-count-low');
  const statCountInfo = getEl<HTMLSpanElement>('stat-count-info');

  // Surface Subnav & Lenses
  const surfaceSubtabGraph = getEl<HTMLButtonElement>('surface-subtab-graph');
  const surfaceSubtabChains = getEl<HTMLButtonElement>('surface-subtab-chains');
  const surfaceSubtabRecon = getEl<HTMLButtonElement>('surface-subtab-recon');
  const surfaceSubtabSubdomains = getEl<HTMLButtonElement>('surface-subtab-subdomains');
  const surfaceChainsCount = getEl<HTMLSpanElement>('surface-chains-count');

  const viewGraph = getEl<HTMLDivElement>('view-graph');
  const viewChains = getEl<HTMLDivElement>('view-chains');
  const viewRecon = getEl<HTMLDivElement>('view-recon');
  const viewSubdomains = getEl<HTMLDivElement>('view-subdomains');

  // Graph elements
  const toggleNodeTableBtn = (document.getElementById('toggle-node-table-btn') ??
    document.getElementById('view-toggle-btn')) as HTMLButtonElement;
  const evalBanner = getEl<HTMLDivElement>('eval-banner');
  const apexDomainVal = getEl<HTMLSpanElement>('apex-domain-val');
  const nodesCountVal = getEl<HTMLSpanElement>('nodes-count-val');
  const edgesCountVal = getEl<HTMLSpanElement>('edges-count-val');
  const graphLoading = getEl<HTMLDivElement>('graph-loading');
  const graphEmpty = getEl<HTMLDivElement>('graph-empty');
  const edgesGroup = getSvgEl<SVGGElement>('edges-group');
  const nodesGroup = getSvgEl<SVGGElement>('nodes-group');

  // Node details drawer
  const nodeDetails = getEl<HTMLElement>('node-details');
  const nodeHostname = getEl<HTMLHeadingElement>('node-hostname');
  const closeDetailsBtn = getEl<HTMLButtonElement>('close-details-btn');
  const nodeRole = getEl<HTMLSpanElement>('node-role');
  const nodeDiscoveredVia = getEl<HTMLSpanElement>('node-discovered-via');
  const nodeGrade = getEl<HTMLSpanElement>('node-grade');
  const nodeScope = getEl<HTMLSpanElement>('node-scope');
  const nodeLastSeen = getEl<HTMLSpanElement>('node-last-seen');

  // Findings elements
  const leadsSearchInput = getEl<HTMLInputElement>('leads-search-input');
  const leadsFilterFamily = getEl<HTMLSelectElement>('leads-filter-family');
  const leadsFilterTier = getEl<HTMLSelectElement>('leads-filter-tier');
  const leadsFilterScope = getEl<HTMLSelectElement>('leads-filter-scope');
  const leadsFilterNewOnly = getEl<HTMLInputElement>('leads-filter-new-only');
  const leadsFilterChainOnly = getEl<HTMLInputElement>('leads-filter-chain-only');
  const exportLeadsMdBtn = getEl<HTMLButtonElement>('export-leads-md-btn');
  const exportLeadsJsonBtn = getEl<HTMLButtonElement>('export-leads-json-btn');
  const exportLeadsSarifBtn = getEl<HTMLButtonElement>('export-leads-sarif-btn');
  const spLeadsEmpty = getEl<HTMLDivElement>('sp-leads-empty');
  const spLeadsList = getEl<HTMLDivElement>('sp-leads-list');

  // Chains elements
  const chainsActiveBadge = getEl<HTMLSpanElement>('chains-active-badge');
  const chainsListContainer = getEl<HTMLDivElement>('chains-list-container');

  // Recon elements
  const downloadWordlistBtn = getEl<HTMLButtonElement>('download-wordlist-btn');
  const resetReconBtn = getEl<HTMLButtonElement>('reset-recon-btn');
  const reconHostsCount = getEl<HTMLSpanElement>('recon-hosts-count');
  const reconEndpointsCount = getEl<HTMLSpanElement>('recon-endpoints-count');
  const reconParamsCount = getEl<HTMLSpanElement>('recon-params-count');
  const reconBucketsCount = getEl<HTMLSpanElement>('recon-buckets-count');
  const reconSubtabEndpoints = getEl<HTMLButtonElement>('recon-subtab-endpoints');
  const reconSubtabParams = getEl<HTMLButtonElement>('recon-subtab-params');
  const reconSubtabHosts = getEl<HTMLButtonElement>('recon-subtab-hosts');
  const reconSubtabBuckets = getEl<HTMLButtonElement>('recon-subtab-buckets');
  const reconSectionEndpoints = getEl<HTMLDivElement>('recon-section-endpoints');
  const reconSectionParams = getEl<HTMLDivElement>('recon-section-params');
  const reconSectionHosts = getEl<HTMLDivElement>('recon-section-hosts');
  const reconSectionBuckets = getEl<HTMLDivElement>('recon-section-buckets');
  const reconEndpointsList = getEl<HTMLDivElement>('recon-endpoints-list');
  const reconParamsList = getEl<HTMLDivElement>('recon-params-list');
  const reconHostsList = getEl<HTMLDivElement>('recon-hosts-list');
  const reconBucketsList = getEl<HTMLDivElement>('recon-buckets-list');

  // Subdomain & API elements
  const subdomainEscalationPill = getEl<HTMLSpanElement>('subdomain-escalation-pill');
  const subdomainVectorsList = getEl<HTMLDivElement>('subdomain-vectors-list');
  const subdomainVectorsEmpty = getEl<HTMLDivElement>('subdomain-vectors-empty');
  const apiEndpointsCount = getEl<HTMLSpanElement>('api-endpoints-count');
  const apiEndpointsList = getEl<HTMLDivElement>('api-endpoints-list');
  const apiEndpointsEmpty = getEl<HTMLDivElement>('api-endpoints-empty');

  // Activity subnav & streams
  const activitySubtabTimeline = getEl<HTMLButtonElement>('activity-subtab-timeline');
  const activitySubtabLedger = getEl<HTMLButtonElement>('activity-subtab-ledger');
  const viewTimeline = getEl<HTMLDivElement>('view-timeline');
  const viewLedger = getEl<HTMLDivElement>('view-ledger');
  const timelineCountBadge = getEl<HTMLSpanElement>('timeline-count-badge');
  const ledgerCountBadge = getEl<HTMLSpanElement>('ledger-count-badge');
  const timelineEmpty = getEl<HTMLDivElement>('timeline-empty');
  const timelineStream = getEl<HTMLDivElement>('timeline-stream');
  const ledgerEmpty = getEl<HTMLDivElement>('ledger-empty');
  const ledgerStream = getEl<HTMLDivElement>('ledger-stream');

  // Command palette elements
  const cmdPaletteDialog = getEl<HTMLDialogElement>('command-palette-dialog');
  const cmdPaletteCloseBtn = getEl<HTMLButtonElement>('cmd-palette-close-btn');
  const cmdPaletteInput = getEl<HTMLInputElement>('cmd-palette-input');
  const cmdPaletteResults = getEl<HTMLUListElement>('cmd-palette-results');

  // In-Panel Settings elements
  const viewSettings = getEl<HTMLDivElement>('view-settings');
  const settingsCloseBtn = getEl<HTMLButtonElement>('settings-close-btn');
  const spSettingsSaveBtn = getEl<HTMLButtonElement>('sp-settings-save-btn');
  const spSettingsDiscardBtn = getEl<HTMLButtonElement>('sp-settings-discard-btn');
  const spSettingsStatus = getEl<HTMLSpanElement>('sp-settings-status');
  const spOpenFullOptionsBtn = getEl<HTMLButtonElement>('sp-open-full-options-btn');
  const spModePerSite = getEl<HTMLInputElement>('sp-mode-per-site');
  const spModeAllSites = getEl<HTMLInputElement>('sp-mode-all-sites');
  const spModeOff = getEl<HTMLInputElement>('sp-mode-off');
  const spSettingLeads = getEl<HTMLInputElement>('sp-setting-leads');
  const spSettingDeep = getEl<HTMLInputElement>('sp-setting-deep');
  const spSettingCred = getEl<HTMLInputElement>('sp-setting-cred');
  const spSettingHunter = getEl<HTMLInputElement>('sp-setting-hunter');
  const spSettingTheme = getEl<HTMLSelectElement>('sp-setting-theme');
  const spSettingDensity = getEl<HTMLSelectElement>('sp-setting-density');
  const spSettingMotion = getEl<HTMLSelectElement>('sp-setting-motion');

  // In-Panel Settings state
  interface InPanelSettingsSnapshot {
    monitoringMode: 'per-site' | 'all-sites' | 'off';
    leadsEnabled: boolean;
    deepMode: boolean;
    credentialLivenessEnabled: boolean;
    hunterEnabled: boolean;
    theme: 'system' | 'dark' | 'light';
    density: 'comfortable' | 'compact';
    reducedMotion: 'system' | 'always' | 'never';
  }

  let inPanelSettingsSnapshot: InPanelSettingsSnapshot | null = null;
  let initialAppearanceSnapshot = {
    theme: 'system' as 'system' | 'dark' | 'light',
    density: 'comfortable' as 'comfortable' | 'compact',
    reducedMotion: 'system' as 'system' | 'always' | 'never',
  };
  let lastActiveTabBeforeSettings: string = 'tab-overview';
  let lastFocusedElementBeforeSettings: HTMLElement | null = null;

  // State
  let activeTabId: number | null = null;
  let activeTabUrl: string = '';
  let activeApexDomain: string = '';
  let activeOrigin: string = '';
  let isListView = false;
  let currentTabState: TabState | null = null;
  let tabStateResolved = false;
  let captureControlsSeq = 0;
  const grantedReloadOrigins = new Set<string>();
  const deniedCaptureOrigins = new Set<string>();
  const seenLeadCardIds = new Set<string>();
  const seenRadarLeadIds = new Set<string>();
  let seenMotionOrigin = '';

  let currentLeads: Lead[] = [];
  let activeChains: Array<{ chain: ChainRule; matchedLeads: Lead[] }> = [];
  let currentRecon: ReconMemory = { hosts: [], params: [], endpoints: [], buckets: [] };
  let selectedLeadIndex = -1;

  // ── Navigation Tab Switching ─────────────────────────────────
  function switchTab(tabId: string): void {
    let resolvedId = tabId;
    if (tabId === 'tab-leads') resolvedId = 'tab-findings';
    if (tabId === 'tab-graph') resolvedId = 'tab-surface';
    if (tabId === 'tab-radar') resolvedId = 'tab-overview';
    if (tabId === 'tab-chains') {
      resolvedId = 'tab-surface';
      switchSurfaceSubtab('surface-subtab-chains');
    }
    if (tabId === 'tab-recon') {
      resolvedId = 'tab-surface';
      switchSurfaceSubtab('surface-subtab-recon');
    }
    if (tabId === 'tab-timeline') {
      resolvedId = 'tab-activity';
      switchActivitySubtab('activity-subtab-timeline');
    }

    const primaryTabs = [
      { id: 'tab-overview', btn: tabOverview, view: viewOverview, bodyClass: 'view-overview' },
      { id: 'tab-findings', btn: tabFindings, view: viewFindings, bodyClass: 'view-findings' },
      { id: 'tab-surface', btn: tabSurface, view: viewSurface, bodyClass: 'view-surface' },
      { id: 'tab-activity', btn: tabActivity, view: viewActivity, bodyClass: 'view-activity' },
    ];

    for (const t of primaryTabs) {
      const isSelected = t.id === resolvedId;
      t.btn.classList.toggle('active', isSelected);
      t.btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      t.view.hidden = !isSelected;
      t.view.classList.toggle('active', isSelected);
      document.body.classList.toggle(t.bodyClass, isSelected);
    }

    viewSettings.hidden = true;
    optionsLink.classList.remove('active');

    // Trigger rendering for activated view
    if (resolvedId === 'tab-overview') {
      renderOverviewView();
    } else if (resolvedId === 'tab-findings') {
      renderLeadsList();
    } else if (resolvedId === 'tab-surface') {
      const activeSurfaceLens = document.querySelector('.surface-subtab.active')?.id ?? 'surface-subtab-graph';
      switchSurfaceSubtab(activeSurfaceLens);
    } else if (resolvedId === 'tab-activity') {
      renderTimeline();
      renderCoverageLedger();
    }
  }

  tabOverview.addEventListener('click', () => switchTab('tab-overview'));
  tabFindings.addEventListener('click', () => switchTab('tab-findings'));
  tabSurface.addEventListener('click', () => switchTab('tab-surface'));
  tabActivity.addEventListener('click', () => switchTab('tab-activity'));

  // ── Surface Subtabs ──────────────────────────────────────────
  function switchSurfaceSubtab(subtabId: string): void {
    const subtabs = [
      { id: 'surface-subtab-graph', btn: surfaceSubtabGraph, panel: viewGraph },
      { id: 'surface-subtab-chains', btn: surfaceSubtabChains, panel: viewChains },
      { id: 'surface-subtab-recon', btn: surfaceSubtabRecon, panel: viewRecon },
      { id: 'surface-subtab-subdomains', btn: surfaceSubtabSubdomains, panel: viewSubdomains },
    ];

    for (const st of subtabs) {
      const isActive = st.id === subtabId;
      st.btn.classList.toggle('active', isActive);
      st.btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
      st.panel.hidden = !isActive;
      st.panel.classList.toggle('active', isActive);
    }

    if (subtabId === 'surface-subtab-graph') {
      if (activeApexDomain.length > 0) {
        void fetchAndRenderGraph(activeApexDomain, activeTabId);
      }
    } else if (subtabId === 'surface-subtab-chains') {
      renderChainsView();
    } else if (subtabId === 'surface-subtab-recon') {
      void fetchAndRenderRecon();
    } else if (subtabId === 'surface-subtab-subdomains') {
      renderSubdomainTrustAndApis();
    }
  }

  surfaceSubtabGraph.addEventListener('click', () => switchSurfaceSubtab('surface-subtab-graph'));
  surfaceSubtabChains.addEventListener('click', () => switchSurfaceSubtab('surface-subtab-chains'));
  surfaceSubtabRecon.addEventListener('click', () => switchSurfaceSubtab('surface-subtab-recon'));
  surfaceSubtabSubdomains.addEventListener('click', () => switchSurfaceSubtab('surface-subtab-subdomains'));

  // ── Activity Subtabs ─────────────────────────────────────────
  function switchActivitySubtab(subtabId: string): void {
    const isTimeline = subtabId === 'activity-subtab-timeline';
    activitySubtabTimeline.classList.toggle('active', isTimeline);
    activitySubtabTimeline.setAttribute('aria-selected', isTimeline ? 'true' : 'false');
    viewTimeline.hidden = !isTimeline;
    viewTimeline.classList.toggle('active', isTimeline);

    activitySubtabLedger.classList.toggle('active', !isTimeline);
    activitySubtabLedger.setAttribute('aria-selected', !isTimeline ? 'true' : 'false');
    viewLedger.hidden = isTimeline;
    viewLedger.classList.toggle('active', !isTimeline);

    if (isTimeline) {
      renderTimeline();
    } else {
      renderCoverageLedger();
    }
  }

  activitySubtabTimeline.addEventListener('click', () => switchActivitySubtab('activity-subtab-timeline'));
  activitySubtabLedger.addEventListener('click', () => switchActivitySubtab('activity-subtab-ledger'));

  // ── View Toggle (Graph vs List for graph view) ───────────────
  toggleNodeTableBtn.addEventListener('click', () => {
    isListView = !isListView;
    document.body.classList.toggle('view-graph', !isListView);
    document.body.classList.toggle('view-list', isListView);
    toggleNodeTableBtn.textContent = isListView ? 'Graph view' : 'List view';
    toggleNodeTableBtn.setAttribute('aria-pressed', isListView ? 'true' : 'false');
  });

  function getInPanelFormState(): InPanelSettingsSnapshot {
    let mode: 'per-site' | 'all-sites' | 'off' = 'per-site';
    if (spModeAllSites.checked) mode = 'all-sites';
    else if (spModeOff.checked) mode = 'off';

    return {
      monitoringMode: mode,
      leadsEnabled: spSettingLeads.checked,
      deepMode: spSettingDeep.checked,
      credentialLivenessEnabled: spSettingCred.checked,
      hunterEnabled: spSettingHunter.checked,
      theme: (spSettingTheme.value as 'system' | 'dark' | 'light') || 'system',
      density: (spSettingDensity.value as 'comfortable' | 'compact') || 'comfortable',
      reducedMotion: (spSettingMotion.value as 'system' | 'always' | 'never') || 'system',
    };
  }

  function setInPanelFormState(state: InPanelSettingsSnapshot): void {
    if (state.monitoringMode === 'all-sites') spModeAllSites.checked = true;
    else if (state.monitoringMode === 'off') spModeOff.checked = true;
    else spModePerSite.checked = true;

    spSettingLeads.checked = state.leadsEnabled;
    spSettingDeep.checked = state.deepMode;
    spSettingCred.checked = state.credentialLivenessEnabled;
    spSettingHunter.checked = state.hunterEnabled;
    spSettingTheme.value = state.theme;
    spSettingDensity.value = state.density;
    spSettingMotion.value = state.reducedMotion;
  }

  function isInPanelSettingsDirty(): boolean {
    if (!inPanelSettingsSnapshot) return false;
    const current = getInPanelFormState();
    return JSON.stringify(current) !== JSON.stringify(inPanelSettingsSnapshot);
  }

  async function openInPanelSettings(): Promise<void> {
    lastFocusedElementBeforeSettings = document.activeElement as HTMLElement | null;
    const currentActiveTabEl = document.querySelector('.nav-tab.active');
    lastActiveTabBeforeSettings = currentActiveTabEl?.id ?? 'tab-overview';

    try {
      currentSettings = await SettingsService.getSettings();
    } catch {
      // fallback to in-memory currentSettings
    }

    const snapshot: InPanelSettingsSnapshot = {
      monitoringMode: currentSettings.monitoringMode ?? 'per-site',
      leadsEnabled: currentSettings.leadsEnabled ?? true,
      deepMode: currentSettings.deepModeEnabled ?? false,
      credentialLivenessEnabled: currentSettings.credentialLivenessEnabled ?? false,
      hunterEnabled: currentSettings.hunterConfig?.enabled ?? false,
      theme: currentSettings.theme ?? 'system',
      density: currentSettings.density ?? 'comfortable',
      reducedMotion: currentSettings.reducedMotion ?? 'system',
    };

    inPanelSettingsSnapshot = snapshot;
    initialAppearanceSnapshot = {
      theme: snapshot.theme,
      density: snapshot.density,
      reducedMotion: snapshot.reducedMotion,
    };

    setInPanelFormState(snapshot);
    spSettingsStatus.hidden = true;

    viewOverview.hidden = true;
    viewFindings.hidden = true;
    viewSurface.hidden = true;
    viewActivity.hidden = true;
    viewSettings.hidden = false;
    optionsLink.classList.add('active');
    settingsCloseBtn.focus();
  }

  function closeInPanelSettingsView(): void {
    viewSettings.hidden = true;
    optionsLink.classList.remove('active');
    switchTab(lastActiveTabBeforeSettings);
    if (lastFocusedElementBeforeSettings && typeof lastFocusedElementBeforeSettings.focus === 'function') {
      lastFocusedElementBeforeSettings.focus();
    }
  }

  function discardInPanelSettings(): void {
    if (inPanelSettingsSnapshot) {
      setInPanelFormState(inPanelSettingsSnapshot);
    }
    applyAppearance(
      initialAppearanceSnapshot.theme,
      initialAppearanceSnapshot.density,
      initialAppearanceSnapshot.reducedMotion,
    );
    closeInPanelSettingsView();
  }

  async function saveInPanelSettings(): Promise<void> {
    const form = getInPanelFormState();
    const updated: SettingsV2 = {
      ...currentSettings,
      monitoringMode: form.monitoringMode,
      leadsEnabled: form.leadsEnabled,
      deepModeEnabled: form.deepMode,
      credentialLivenessEnabled: form.credentialLivenessEnabled,
      hunterConfig: {
        ...(currentSettings.hunterConfig ?? { maxRequestsPerSecond: 1 }),
        enabled: form.hunterEnabled,
      },
      theme: form.theme,
      density: form.density,
      reducedMotion: form.reducedMotion,
    };

    try {
      await SettingsService.updateSettings(updated);
      await sendToBackground({ type: 'SETTINGS_CHANGED', settings: updated });
      currentSettings = { ...currentSettings, ...updated };
      inPanelSettingsSnapshot = form;
      initialAppearanceSnapshot = {
        theme: form.theme,
        density: form.density,
        reducedMotion: form.reducedMotion,
      };
      void updateSidepanelCaptureControls();

      spSettingsStatus.textContent = 'Saved';
      spSettingsStatus.hidden = false;
      setTimeout(() => {
        spSettingsStatus.hidden = true;
        closeInPanelSettingsView();
      }, 350);
    } catch {
      spSettingsStatus.textContent = 'Save failed';
      spSettingsStatus.hidden = false;
    }
  }

  async function handleCloseSettings(): Promise<void> {
    if (isInPanelSettingsDirty()) {
      const confirmDiscard = await promptGeneralConfirm(
        'Discard Unsaved Settings?',
        'You have unsaved changes in Settings. Do you want to discard them?'
      );
      if (confirmDiscard) {
        discardInPanelSettings();
      }
    } else {
      closeInPanelSettingsView();
    }
  }

  // Appearance live preview on change
  const previewAppearance = () => {
    const themeVal =
      spSettingTheme.value === 'dark' || spSettingTheme.value === 'light'
        ? spSettingTheme.value
        : 'system';
    const densityVal =
      spSettingDensity.value === 'compact' ? 'compact' : 'comfortable';
    const motionVal =
      spSettingMotion.value === 'always' || spSettingMotion.value === 'never'
        ? spSettingMotion.value
        : 'system';
    applyAppearance(themeVal, densityVal, motionVal);
  };
  spSettingTheme.addEventListener('change', previewAppearance);
  spSettingDensity.addEventListener('change', previewAppearance);
  spSettingMotion.addEventListener('change', previewAppearance);

  settingsCloseBtn.addEventListener('click', () => {
    void handleCloseSettings();
  });
  spSettingsDiscardBtn.addEventListener('click', () => {
    discardInPanelSettings();
  });
  spSettingsSaveBtn.addEventListener('click', () => {
    void saveInPanelSettings();
  });
  spOpenFullOptionsBtn.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage !== undefined) {
      void chrome.runtime.openOptionsPage();
    }
  });

  optionsLink.addEventListener('click', (e) => {
    e.preventDefault();
    if (viewSettings.hidden) {
      void openInPanelSettings();
    } else {
      void handleCloseSettings();
    }
  });

  refreshBtn.addEventListener('click', () => {
    if (activeApexDomain.length > 0) {
      void fetchAndRenderGraph(activeApexDomain, activeTabId);
    }
    void fetchLeads();
    void fetchAndRenderRecon();
    if (activeTabId !== null) {
      port.postMessage({ type: 'REQUEST_STATE', tabId: activeTabId });
    }
  });

  closeDetailsBtn.addEventListener('click', () => {
    nodeDetails.hidden = true;
  });

  // ── Port Connection for Live Updates ────────────────────────
  const port = chrome.runtime.connect({ name: SIDEPANEL_PORT_NAME });
  port.onMessage.addListener((msg: unknown) => {
    if (typeof msg === 'object' && msg !== null && (msg as { type?: string }).type === 'SETTINGS_CHANGED') {
      const newSettings = (msg as { settings?: SettingsV2 }).settings;
      if (newSettings !== undefined) {
        currentSettings = newSettings;
        applyAppearance(newSettings.theme, newSettings.density, newSettings.reducedMotion);
        renderOverviewView();
        renderLeadsList();
        void updateSidepanelCaptureControls();
      }
      return;
    }

    if (typeof msg === 'object' && msg !== null && (msg as { type?: string }).type === 'LEAD_STATE_UPDATE') {
      const leadMsg = msg as LeadStateUpdateMessage;
      handleLeadStateUpdate(leadMsg);
      return;
    }

    const message = msg as { type?: string; state?: TabState };
    if (message.type === 'TAB_STATE_UPDATE' && message.state !== undefined) {
      handleTabState(message.state);
    }
  });

  chrome.runtime.onMessage.addListener((msg: unknown, _sender, sendResponse) => {
    if (typeof msg === 'object' && msg !== null && (msg as { type?: string }).type === 'LEAD_STATE_UPDATE') {
      handleLeadStateUpdate(msg as LeadStateUpdateMessage);
      sendResponse({ received: true });
    }
  });

  void SettingsService.getSettings()
    .then((s) => {
      currentSettings = s;
      renderOverviewView();
      renderLeadsList();
      void updateSidepanelCaptureControls();
    })
    .catch(() => {
      // fallback to DEFAULT_SETTINGS
    });

  void bootstrapAppearance();

  async function updateSidepanelCaptureControls(): Promise<void> {
    const seq = ++captureControlsSeq;
    const setShuriken = (scanning: boolean): void => {
      spScanShuriken.toggleAttribute('hidden', !scanning);
      spScanShuriken.setAttribute('data-scanning', scanning ? 'true' : 'false');
    };

    const targetUrl = activeTabUrl.length > 0 ? activeTabUrl : (currentTabState?.url ?? '');
    const targetOrigin = activeOrigin;

    if (targetUrl.length === 0 || isRestrictedUrl(targetUrl) || targetOrigin.length === 0) {
      spCaptureBar.dataset['captureState'] = 'restricted';
      setShuriken(false);
      spCaptureStatus.textContent = 'This page cannot be inspected. Navigate to an HTTP/HTTPS website to capture headers.';
      spCaptureBtn.hidden = true;
      spCaptureBtn.disabled = true;
      spReloadCaptureBtn.hidden = true;
      return;
    }

    if (currentSettings.monitoringMode === 'off') {
      spCaptureBar.dataset['captureState'] = 'warning';
      setShuriken(false);
      spCaptureStatus.textContent = 'Monitoring is Off — enable Per-site or All-sites in Settings to capture.';
      spCaptureBtn.hidden = true;
      spReloadCaptureBtn.hidden = true;
      return;
    }

    let broadActive = false;
    let completeBroad = false;
    let exactOriginPermitted = false;
    try {
      broadActive = await PermissionsService.isBroadGrantPresent();
      completeBroad = await PermissionsService.hasCompleteBroadGrant();
      exactOriginPermitted = await PermissionsService.hasPermissionForOrigin(targetOrigin);
    } catch {
      // Fallback safely when permissions API unavailable
    }

    if (seq !== captureControlsSeq) return;

    const gate = isModeCaptureAllowed(targetUrl, currentSettings, broadActive, undefined, completeBroad);
    if (!gate.allowed) {
      if (gate.reason === 'broad-access-conflict') {
        spCaptureBar.dataset['captureState'] = 'warning';
        setShuriken(false);
        spCaptureStatus.textContent = 'Capture paused — broad and per-site permissions conflict.';
        spCaptureBtn.hidden = true;
        spReloadCaptureBtn.hidden = true;
        return;
      }
      if (gate.reason === 'all-sites-missing-grant') {
        spCaptureBar.dataset['captureState'] = 'warning';
        setShuriken(false);
        spCaptureStatus.textContent = 'All-sites permission missing — grant host access in Settings.';
        spCaptureBtn.hidden = true;
        spReloadCaptureBtn.hidden = true;
        return;
      }
      if (gate.reason === 'restricted-url') {
        spCaptureBar.dataset['captureState'] = 'restricted';
        setShuriken(false);
        spCaptureStatus.textContent = 'This URL cannot be inspected by browser extensions.';
        spCaptureBtn.hidden = true;
        spReloadCaptureBtn.hidden = true;
        return;
      }
    }

    if (currentSettings.monitoringMode === 'per-site' && !exactOriginPermitted) {
      spCaptureBar.dataset['captureState'] = deniedCaptureOrigins.has(targetOrigin) ? 'denied' : 'permission-needed';
      setShuriken(false);
      spCaptureStatus.textContent = deniedCaptureOrigins.has(targetOrigin)
        ? 'Permission was denied — click "Capture this site" to try again.'
        : 'Read response headers and cookie metadata for this site.';
      spCaptureBtn.disabled = false;
      spCaptureBtn.hidden = false;
      spReloadCaptureBtn.hidden = true;
      return;
    }

    const hopsCaptured = currentTabState?.coverage?.hopsCaptured ?? 0;
    if (hopsCaptured > 0) {
      grantedReloadOrigins.delete(targetOrigin);
      deniedCaptureOrigins.delete(targetOrigin);
      spCaptureBar.dataset['captureState'] = 'capturing';
      setShuriken(false);
      spCaptureStatus.textContent = 'Capturing';
      spCaptureBtn.hidden = true;
      spReloadCaptureBtn.hidden = true;
      return;
    }

    if (grantedReloadOrigins.has(targetOrigin) || (tabStateResolved && hopsCaptured === 0)) {
      spCaptureBar.dataset['captureState'] = 'access-granted-reload';
      setShuriken(false);
      spCaptureStatus.textContent = 'Access granted — reload to capture initial response headers.';
      spCaptureBtn.hidden = true;
      spReloadCaptureBtn.hidden = activeTabId === null;
      return;
    }

    spCaptureBar.dataset['captureState'] = 'scanning';
    setShuriken(true);
    spCaptureStatus.textContent = 'Capturing response headers & telemetry…';
    spCaptureBtn.hidden = true;
    spReloadCaptureBtn.hidden = true;
  }

  spCaptureBtn.addEventListener('click', () => {
    const reqTabId = activeTabId;
    const reqOrigin = activeOrigin;
    const reqUrl = activeTabUrl;
    if (reqOrigin.length === 0 || isRestrictedUrl(reqUrl)) return;

    const pattern = patternFromOrigin(reqOrigin);
    if (pattern.length === 0) return;

    spCaptureBtn.disabled = true;
    chrome.permissions.request({ origins: [pattern] }, (granted) => {
      const apiError = chrome.runtime.lastError;
      if (activeTabId !== reqTabId || activeOrigin !== reqOrigin) {
        // Stale tab/navigation race guard: do not mutate new tab's UI
        void updateSidepanelCaptureControls();
        return;
      }
      if (apiError != null || granted !== true) {
        deniedCaptureOrigins.add(reqOrigin);
        grantedReloadOrigins.delete(reqOrigin);
        spCaptureBtn.disabled = false;
        void updateSidepanelCaptureControls();
        return;
      }

      deniedCaptureOrigins.delete(reqOrigin);
      grantedReloadOrigins.add(reqOrigin);
      void sendToBackground({
        type: 'PERMISSIONS_CHANGED',
        granted: true,
        origins: [pattern],
      }).catch(() => undefined);
      if (reqTabId !== null) {
        port.postMessage({ type: 'REQUEST_STATE', tabId: reqTabId });
      }
      void updateSidepanelCaptureControls();
    });
  });

  spReloadCaptureBtn.addEventListener('click', () => {
    if (activeTabId === null) return;
    const targetOrigin = activeOrigin;
    chrome.tabs.reload(activeTabId, {}, () => {
      if (chrome.runtime.lastError == null) {
        grantedReloadOrigins.delete(targetOrigin);
      }
      void updateSidepanelCaptureControls();
    });
  });

  function syncActiveBrowserTab(tab: chrome.tabs.Tab | undefined): void {
    const targetId = tab?.id ?? null;
    if (targetId !== activeTabId) {
      currentTabState = null;
    }
    tabStateResolved = false;

    if (tab !== undefined && tab.id !== undefined && tab.url !== undefined && tab.url.length > 0 &&
        !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('moz-extension://')) {
      const switchedTabId = tab.id;
      activeTabId = switchedTabId;
      activeTabUrl = tab.url;
      try {
        const origin = new URL(tab.url).origin;
        activeOrigin = origin;
        const hostname = new URL(origin).hostname;
        activeApexDomain = registrableDomain(hostname) ?? hostname;
      } catch {
        activeOrigin = '';
        activeApexDomain = '';
      }
      port.postMessage({ type: 'REQUEST_STATE', tabId: switchedTabId });
      void sendToBackground({ type: 'REQUEST_STATE', tabId: switchedTabId })
        .then((res) => {
          if (activeTabId !== switchedTabId) return;
          tabStateResolved = true;
          if (res.type === 'STATE_RESPONSE') {
            if (res.state) {
              handleTabState(res.state);
            } else {
              currentTabState = null;
              void updateSidepanelCaptureControls();
            }
          }
        })
        .catch(() => {
          if (activeTabId === switchedTabId) {
            tabStateResolved = true;
            void updateSidepanelCaptureControls();
          }
        });
      if (activeApexDomain.length > 0) {
        void fetchAndRenderGraph(activeApexDomain, switchedTabId);
      }
      void fetchLeads();
      void fetchAndRenderRecon();
      renderOverviewView();
      void updateSidepanelCaptureControls();
    } else {
      activeTabId = targetId;
      activeTabUrl = tab?.url ?? '';
      activeOrigin = '';
      activeApexDomain = '';
      tabStateResolved = true;
      graphLoading.hidden = true;
      graphEmpty.textContent = 'No inspectable tab active. Open a website to view its attack surface graph.';
      graphEmpty.hidden = false;
      renderOverviewView();
      void updateSidepanelCaptureControls();
    }
  }

  if (typeof chrome.tabs?.onActivated?.addListener === 'function') {
    chrome.tabs.onActivated.addListener((activeInfo) => {
      chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (chrome.runtime.lastError != null) return;
        syncActiveBrowserTab(tab);
      });
    });
  }

  if (typeof chrome.tabs?.onUpdated?.addListener === 'function') {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (tabId === activeTabId && (changeInfo.url !== undefined || changeInfo.status === 'complete')) {
        syncActiveBrowserTab(tab);
      }
    });
  }

  // ── Query Active Tab Initially ──────────────────────────────
  void (async () => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const paramApex = urlParams.get('apex');
      const paramTabId = urlParams.get('tabId');

      if (paramApex !== null && paramApex.length > 0) {
        const cleanApex = registrableDomain(paramApex) ?? paramApex;
        activeApexDomain = cleanApex;
        const tabIdNum = paramTabId !== null && paramTabId.length > 0 ? parseInt(paramTabId, 10) : null;
        activeTabId = Number.isNaN(tabIdNum) ? null : tabIdNum;
        if (activeTabId !== null) {
          port.postMessage({ type: 'REQUEST_STATE', tabId: activeTabId });
          try {
            const paramTab = await chrome.tabs.get(activeTabId);
            activeTabUrl = paramTab.url ?? '';
            if (activeTabUrl.length > 0) {
              activeOrigin = new URL(activeTabUrl).origin;
            }
          } catch {
            // Ignore tab lookup fallback
          }
        }
        void fetchAndRenderGraph(cleanApex, activeTabId);
        void fetchLeads();
        void fetchAndRenderRecon();
        renderOverviewView();
        void updateSidepanelCaptureControls();
        return;
      }

      if (paramTabId !== null && paramTabId.length > 0) {
        const tabIdNum = parseInt(paramTabId, 10);
        if (!Number.isNaN(tabIdNum)) {
          try {
            const explicitTab = await chrome.tabs.get(tabIdNum);
            syncActiveBrowserTab(explicitTab);
            return;
          } catch {
            // Fall through to active tab query
          }
        }
      }

      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      syncActiveBrowserTab(tabs[0]);
    } catch {
      graphLoading.hidden = true;
      graphEmpty.textContent = 'Unable to query active tab.';
      graphEmpty.hidden = false;
      renderOverviewView();
      void updateSidepanelCaptureControls();
    }
  })();

  let lastLeadsFetchOrigin = '';
  let lastLeadsFetchGen = -1;

  function handleTabState(state: TabState): void {
    try {
      const prevOrigin = lastLeadsFetchOrigin;
      const prevGen = lastLeadsFetchGen;
      tabStateResolved = true;
      currentTabState = state;
      activeTabId = state.tabId;
      activeTabUrl = state.url;
      activeOrigin = state.origin;
      const host = new URL(state.origin).hostname;
      const apex = registrableDomain(host) ?? host;
      if (apex !== activeApexDomain) {
        activeApexDomain = apex;
        void fetchAndRenderGraph(apex, state.tabId);
        void fetchAndRenderRecon();
      }
      const nextGen = state.navigationGeneration ?? -1;
      if (state.origin !== prevOrigin || nextGen !== prevGen) {
        lastLeadsFetchOrigin = state.origin;
        lastLeadsFetchGen = nextGen;
        void fetchLeads();
      }
      renderOverviewView();
      renderSubdomainTrustAndApis();
      renderCoverageLedger();
      void updateSidepanelCaptureControls();
    } catch {
      // Ignore URL parsing errors
    }
  }

  function handleLeadStateUpdate(msg: LeadStateUpdateMessage): void {
    currentLeads = msg.leads ?? [];
    activeChains = msg.activeChains ?? [];

    if (currentLeads.length > 0) {
      tabLeadsBadge.textContent = currentLeads.length.toString();
      tabLeadsBadge.hidden = false;
      tabActivityBadge.textContent = currentLeads.length.toString();
      tabActivityBadge.hidden = false;
      timelineCountBadge.textContent = currentLeads.length.toString();
    } else {
      tabLeadsBadge.hidden = true;
      tabActivityBadge.hidden = true;
      timelineCountBadge.textContent = '0';
    }

    if (activeChains.length > 0) {
      tabChainsBadge.textContent = activeChains.length.toString();
      tabChainsBadge.hidden = false;
      surfaceChainsCount.textContent = activeChains.length.toString();
    } else {
      tabChainsBadge.hidden = true;
      surfaceChainsCount.textContent = '0';
    }

    // Update active views
    renderOverviewView();

    const activeTabEl = document.querySelector('.nav-tab.active');
    if (activeTabEl?.id === 'tab-findings') {
      renderLeadsList();
    } else if (activeTabEl?.id === 'tab-surface') {
      const activeSurfaceSubtab = document.querySelector('.surface-subtab.active')?.id;
      if (activeSurfaceSubtab === 'surface-subtab-chains') {
        renderChainsView();
      }
    } else if (activeTabEl?.id === 'tab-activity') {
      renderTimeline();
    }
  }

  async function fetchLeads(): Promise<void> {
    try {
      const res = await sendToBackground({
        type: 'GET_LEADS_STATE',
        tabId: activeTabId ?? undefined,
        origin: typeof activeOrigin === 'string' && activeOrigin.length > 0 ? activeOrigin : undefined,
      });
      if (typeof res === 'object' && res !== null && res.type === 'LEAD_STATE_UPDATE') {
        handleLeadStateUpdate(res);
      }
    } catch {
      // SW might be warming up
    }
  }

  // ── Overview View Rendering ──────────────────────────────────
  function renderOverviewView(): void {
    // 1. Monitored origin, apex, mode
    overviewOriginVal.textContent = activeOrigin.length > 0 ? activeOrigin : '—';
    overviewApexVal.textContent = activeApexDomain.length > 0 ? `Apex: ${activeApexDomain}` : 'Apex: —';

    const mode = currentSettings.monitoringMode ?? 'per-site';
    overviewModePill.textContent = mode === 'all-sites' ? 'All-sites' : mode === 'off' ? 'Off' : 'Per-site';
    overviewModePill.className = `posture-mode-pill mode-${mode}`;

    // 2. Grade and Scores
    const grade = currentTabState?.grade ?? '?';
    overviewGradeBadge.textContent = grade;
    overviewGradeBadge.className = `grade-badge-circle grade-${grade.toLowerCase()}`;

    overviewScoreVal.textContent = currentTabState?.score !== undefined ? `${currentTabState.score}/100` : '—/100';
    overviewQualityVal.textContent =
      currentTabState?.qualityScore !== undefined
        ? `Quality: ${currentTabState.qualityScore}/100`
        : 'Quality: —';

    // 3. Coverage status
    if (currentTabState?.coverage) {
      const cov = currentTabState.coverage;
      overviewHopsVal.textContent = `${cov.hopsCaptured} / ${cov.hopsExpected}`;
      overviewCacheVal.textContent = cov.hasCache ? 'Active (Cached)' : 'None';
      overviewSwVal.textContent = cov.hasServiceWorker
        ? cov.serviceWorkerStatus === 'controlled'
          ? 'Controlled'
          : 'Active'
        : 'None';
      overviewScopeVal.textContent = currentTabState.scopeStatus ?? 'Unknown';

      overviewCoverageStatus.textContent = cov.isRestricted
        ? 'Restricted URL'
        : cov.hopsCaptured < cov.hopsExpected
          ? 'Partial Capture'
          : 'Full Capture';
      overviewCoverageStatus.className = `status-indicator-pill ${
        cov.isRestricted || cov.hopsCaptured < cov.hopsExpected ? 'pill-warning' : 'pill-success'
      }`;

      // Blind spots list
      while (overviewBlindspotsList.firstChild) {
        overviewBlindspotsList.removeChild(overviewBlindspotsList.firstChild);
      }
      if (cov.blindSpots && cov.blindSpots.length > 0) {
        overviewBlindspotsContainer.hidden = false;
        for (const spot of cov.blindSpots) {
          const li = document.createElement('li');
          li.textContent = spot;
          overviewBlindspotsList.appendChild(li);
        }
      } else {
        overviewBlindspotsContainer.hidden = true;
      }
    } else {
      overviewHopsVal.textContent = '0 / 0';
      overviewCacheVal.textContent = 'None';
      overviewSwVal.textContent = 'None';
      overviewScopeVal.textContent = 'Unknown';
      overviewCoverageStatus.textContent = 'Awaiting Capture';
      overviewCoverageStatus.className = 'status-indicator-pill pill-neutral';
      overviewBlindspotsContainer.hidden = true;
    }

    // 4. Key Hygiene Findings (CSP, HSTS, Cookie security)
    while (overviewHygieneList.firstChild) {
      overviewHygieneList.removeChild(overviewHygieneList.firstChild);
    }

    const findings = currentTabState?.findings ?? [];
    const hygieneRules = findings.filter(
      (f) =>
        (f.category === 'header' || f.category === 'cookie' || f.category === 'transport') &&
        f.severity !== 'info' &&
        f.severity !== 'pass' &&
        f.outcome !== 'pass'
    );
    const infoHardeningNotes = findings.filter(
      (f) =>
        (f.category === 'header' || f.category === 'cookie' || f.category === 'transport') &&
        f.severity === 'info'
    );

    overviewHygieneCount.textContent = hygieneRules.length.toString();

    if (hygieneRules.length === 0) {
      overviewHygieneEmpty.textContent = infoHardeningNotes.length > 0
        ? `No actionable header/cookie issues (${infoHardeningNotes.length} optional hardening suggestion(s) recorded).`
        : 'No critical hygiene violations detected.';
      overviewHygieneEmpty.hidden = false;
      overviewHygieneList.appendChild(overviewHygieneEmpty);
    } else {
      overviewHygieneEmpty.hidden = true;
      const topHygiene = hygieneRules.slice(0, 4);
      for (const h of topHygiene) {
        const item = document.createElement('div');
        item.className = 'hygiene-item';

        const head = document.createElement('div');
        head.className = 'hygiene-item-head';

        const sev = document.createElement('span');
        sev.className = `hygiene-sev-pill sev-${h.severity}`;
        sev.textContent = h.severity.toUpperCase();
        head.appendChild(sev);

        const ruleSpan = document.createElement('span');
        ruleSpan.className = 'hygiene-rule-id';
        ruleSpan.textContent = h.ruleId;
        head.appendChild(ruleSpan);

        item.appendChild(head);

        const title = document.createElement('div');
        title.className = 'hygiene-item-title';
        title.textContent = h.title;
        item.appendChild(title);

        if (h.recommendation && h.recommendation.length > 0) {
          const rec = document.createElement('div');
          rec.className = 'hygiene-item-rec';
          rec.textContent = h.recommendation;
          item.appendChild(rec);
        }

        overviewHygieneList.appendChild(item);
      }
    }

    // 5. Radar statistics & Polar SVG
    let crit = 0;
    let high = 0;
    let med = 0;
    let low = 0;
    let info = 0;

    for (const lead of currentLeads) {
      if (lead.potential === 'critical') crit++;
      else if (lead.potential === 'high') high++;
      else if (lead.potential === 'medium') med++;
      else if (lead.potential === 'low') low++;
      else if (lead.potential === 'info') info++;
    }

    statCountCritical.textContent = crit.toString();
    statCountHigh.textContent = high.toString();
    statCountMedium.textContent = med.toString();
    statCountLow.textContent = low.toString();
    statCountInfo.textContent = info.toString();

    const overviewRadarTotal = document.getElementById('overview-radar-total');
    if (overviewRadarTotal) {
      overviewRadarTotal.textContent = `${currentLeads.length} lead${currentLeads.length === 1 ? '' : 's'}`;
    }

    renderSidepanelRadar();

    // 6. Dynamic Next Recommended Action Callout
    const criticalInScopeLeads = currentLeads.filter(
      (l) => l.potential === 'critical' && l.scopeStatus === 'in-scope'
    );
    const hasActiveChains = activeChains.length > 0;
    const isBlindSpot =
      currentTabState?.coverage?.hasCache === true ||
      currentTabState?.coverage?.hasServiceWorker === true ||
      (currentTabState?.coverage?.blindSpots !== undefined && currentTabState.coverage.blindSpots.length > 0);

    if (criticalInScopeLeads.length > 0) {
      overviewActionIcon.textContent = '🚨';
      overviewActionText.textContent = `${criticalInScopeLeads.length} critical in-scope lead(s) identified. Immediate verification recommended.`;
      overviewActionCta.textContent = 'Review In Findings →';
      overviewActionCta.hidden = false;
      overviewActionCta.onclick = () => {
        switchTab('tab-findings');
      };
    } else if (hasActiveChains) {
      overviewActionIcon.textContent = '⛓';
      overviewActionText.textContent = `${activeChains.length} attack vector chain(s) active with correlated leads. Explore multi-stage exploit paths.`;
      overviewActionCta.textContent = 'Inspect Chains in Surface →';
      overviewActionCta.hidden = false;
      overviewActionCta.onclick = () => {
        switchTab('tab-surface');
        switchSurfaceSubtab('surface-subtab-chains');
      };
    } else if (isBlindSpot) {
      overviewActionIcon.textContent = '⚠️';
      overviewActionText.textContent =
        'Page response was served from cache or service worker. Perform a hard refresh to capture wire response headers.';
      overviewActionCta.textContent = 'Reload Monitored Tab 🔄';
      overviewActionCta.hidden = false;
      overviewActionCta.onclick = () => {
        if (activeTabId !== null) {
          void chrome.tabs.reload(activeTabId, { bypassCache: true });
        }
      };
    } else if (hygieneRules.length > 0) {
      overviewActionIcon.textContent = '🛡';
      overviewActionText.textContent = `${hygieneRules.length} security hygiene violation(s) observed on headers and cookies.`;
      overviewActionCta.textContent = 'Explore Hygiene Findings →';
      overviewActionCta.hidden = false;
      overviewActionCta.onclick = () => {
        switchTab('tab-findings');
      };
    } else {
      overviewActionIcon.textContent = '💡';
      overviewActionText.textContent =
        'Security posture baseline captured. Continue browsing the target application to accumulate attack surface intelligence.';
      overviewActionCta.hidden = true;
      overviewActionCta.onclick = null;
    }

    renderRecentFindings(currentLeads);
  }

  function renderRecentFindings(leads: Lead[]): void {
    const container = document.getElementById('overview-recent-list');
    const countBadge = document.getElementById('overview-recent-count');
    if (container === null || countBadge === null) return;

    countBadge.textContent = leads.length.toString();
    while (container.firstChild) container.removeChild(container.firstChild);

    if (leads.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-hint';
      empty.id = 'overview-recent-empty';
      empty.textContent = 'No findings yet';
      container.appendChild(empty);
      return;
    }

    const recent = [...leads].slice(-3).reverse();
    const list = document.createElement('div');
    list.className = 'recent-findings-list';

    for (const lead of recent) {
      const item = document.createElement('div');
      item.className = 'recent-finding-item';
      item.setAttribute('tabindex', '0');
      item.setAttribute('role', 'button');
      item.setAttribute('aria-label', `View finding: ${lead.title}`);

      const sevPill = document.createElement('span');
      sevPill.className = `hygiene-sev-pill sev-${lead.potential}`;
      sevPill.textContent = lead.potential.toUpperCase();

      const famBadge = document.createElement('span');
      famBadge.className = 'lead-family-icon';
      famBadge.textContent = lead.family;

      const titleSpan = document.createElement('span');
      titleSpan.className = 'recent-finding-title';
      titleSpan.textContent = lead.title;

      item.appendChild(sevPill);
      item.appendChild(famBadge);
      item.appendChild(titleSpan);

      const onSelect = () => {
        switchTab('tab-findings');
        focusLeadCardInSidepanel(lead.id);
      };
      item.addEventListener('click', onSelect);
      item.addEventListener('keydown', (e: KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      });

      list.appendChild(item);
    }

    container.appendChild(list);
  }

  // ── Attack Surface Graph Implementation ──────────────────────
  async function fetchAndRenderGraph(apexDomain: string, tabId: number | null): Promise<void> {
    graphLoading.hidden = false;
    graphEmpty.hidden = true;
    apexDomainVal.textContent = apexDomain;

    try {
      const msg: import('../shared/messaging').RequestGraphMessage =
        tabId !== null
          ? { type: 'REQUEST_GRAPH', apexDomain, tabId }
          : { type: 'REQUEST_GRAPH', apexDomain };
      const response = await sendToBackground(msg);

      if (response.type === 'GRAPH_RESPONSE' && response.graph !== undefined) {
        renderGraph(response.graph);
      } else {
        graphLoading.hidden = true;
        graphEmpty.hidden = false;
      }
    } catch (err: unknown) {
      graphLoading.hidden = true;
      graphEmpty.textContent = `Failed to load graph: ${err instanceof Error ? err.message : String(err)}`;
      graphEmpty.hidden = false;
    }
  }

  function renderGraph(graph: AttackSurfaceGraph): void {
    graphLoading.hidden = true;

    const isEvaluation = Boolean(graph.isEvaluation ?? graph.isPro);
    if (isEvaluation) {
      tierBadge.textContent = 'Evaluation';
      tierBadge.className = 'tier-badge evaluation';
      evalBanner.hidden = true;
    } else {
      tierBadge.textContent = 'Standard';
      tierBadge.className = 'tier-badge standard';
      evalBanner.hidden = false;
    }

    nodesCountVal.textContent = graph.nodes.length.toString();
    edgesCountVal.textContent = graph.edges.length.toString();

    while (edgesGroup.firstChild) {
      edgesGroup.removeChild(edgesGroup.firstChild);
    }
    while (nodesGroup.firstChild) {
      nodesGroup.removeChild(nodesGroup.firstChild);
    }

    if (graph.nodes.length === 0) {
      graphEmpty.hidden = false;
      return;
    }
    graphEmpty.hidden = true;

    const centerX = WIDTH / 2;
    const centerY = HEIGHT / 2;

    const simNodes: SimNode[] = graph.nodes.map((n) => {
      const isApex = n.isApex;
      return {
        ...n,
        id: n.hostname,
        x: isApex ? centerX : centerX + (Math.random() - 0.5) * 200,
        y: isApex ? centerY : centerY + (Math.random() - 0.5) * 200,
      };
    });

    const nodeMap = new Map<string, SimNode>(simNodes.map((n) => [n.hostname, n]));
    const simLinks: SimLink[] = graph.edges
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((e) => ({
        source: e.source,
        target: e.target,
        type: e.type,
        severity: e.severity,
      }));

    const lineElements: SVGLineElement[] = simLinks.map((link) => {
      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('class', `edge-line edge-${link.type}`);
      line.setAttribute('stroke-width', '1.5');
      const title = document.createElementNS(SVG_NS, 'title');
      const sHost = typeof link.source === 'string' ? link.source : link.source.hostname;
      const tHost = typeof link.target === 'string' ? link.target : link.target.hostname;
      title.textContent = `Vector: ${link.type.toUpperCase()} from ${sHost} to ${tHost}`;
      line.appendChild(title);
      edgesGroup.appendChild(line);
      return line;
    });

    const nodeGroups: SVGGElement[] = simNodes.map((node) => {
      const g = document.createElementNS(SVG_NS, 'g');
      g.setAttribute('class', 'node-group');

      const circle = document.createElementNS(SVG_NS, 'circle');
      circle.setAttribute('class', 'node-circle');
      circle.setAttribute('r', node.isApex ? '14' : '9');

      let fillColor = '#64748b';
      if (node.isApex) {
        fillColor = '#f59e0b';
      } else if (node.grade === 'A') {
        fillColor = '#10b981';
      } else if (node.grade === 'B') {
        fillColor = '#3b82f6';
      } else if (node.grade === 'C') {
        fillColor = '#f59e0b';
      } else if (node.grade === 'D') {
        fillColor = '#f97316';
      } else if (node.grade === 'F') {
        fillColor = '#ef4444';
      }
      circle.setAttribute('fill', fillColor);
      circle.setAttribute('stroke', node.isApex ? '#fbbf24' : '#1e293b');
      circle.setAttribute('stroke-width', node.isApex ? '2.5' : '1.5');

      const text = document.createElementNS(SVG_NS, 'text');
      text.setAttribute('class', `node-label ${node.isApex ? 'apex' : ''}`);
      text.setAttribute('y', node.isApex ? '24' : '18');
      text.setAttribute('text-anchor', 'middle');
      text.textContent = formatNodeLabel(node.hostname, node.isApex);

      g.appendChild(circle);
      g.appendChild(text);

      g.addEventListener('click', () => {
        showNodeDetails(node);
      });

      nodesGroup.appendChild(g);
      return g;
    });

    const topoKey = graphTopologyKey(graph.nodes, graph.edges);
    const topologyUnchanged = topoKey === lastGraphKey;
    lastGraphKey = topoKey;

    if (activeSimulation !== null) {
      activeSimulation.stop();
      activeSimulation = null;
    }

    const applyPositions = () => {
      for (let i = 0; i < simLinks.length; i++) {
        const link = simLinks[i];
        const line = lineElements[i];
        if (link !== undefined && line !== undefined) {
          const sId = typeof link.source === 'string' ? link.source : link.source.id;
          const tId = typeof link.target === 'string' ? link.target : link.target.id;
          const sPos = nodePositions.get(sId) ?? { x: centerX, y: centerY };
          const tPos = nodePositions.get(tId) ?? { x: centerX, y: centerY };
          line.setAttribute('x1', clamp(sPos.x, 15, WIDTH - 15).toString());
          line.setAttribute('y1', clamp(sPos.y, 15, HEIGHT - 15).toString());
          line.setAttribute('x2', clamp(tPos.x, 15, WIDTH - 15).toString());
          line.setAttribute('y2', clamp(tPos.y, 15, HEIGHT - 15).toString());
        }
      }
      for (let i = 0; i < simNodes.length; i++) {
        const node = simNodes[i];
        const g = nodeGroups[i];
        if (node !== undefined && g !== undefined) {
          const pos = nodePositions.get(node.id) ?? { x: centerX, y: centerY };
          const cx = clamp(pos.x, 20, WIDTH - 20);
          const cy = clamp(pos.y, 20, HEIGHT - 20);
          g.setAttribute('transform', `translate(${cx}, ${cy})`);
        }
      }
    };

    if (topologyUnchanged) {
      applyPositions();
    } else {
      for (const node of simNodes) {
        const saved = nodePositions.get(node.id);
        if (saved) {
          node.x = saved.x;
          node.y = saved.y;
        }
      }

      activeSimulation = forceSimulation<SimNode>(simNodes)
        .force('link', forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(85))
        .force('charge', forceManyBody().strength(-220))
        .force('center', forceCenter(centerX, centerY))
        .force('collide', forceCollide().radius(26));

      const sim = activeSimulation;

      sim.on('tick', () => {
        for (const node of simNodes) {
          if (node.x !== undefined && node.y !== undefined) {
            nodePositions.set(node.id, { x: node.x, y: node.y });
          }
        }
        applyPositions();
      });

      sim.on('end', () => {
        for (const node of simNodes) {
          if (node.x !== undefined && node.y !== undefined) {
            nodePositions.set(node.id, { x: node.x, y: node.y });
          }
        }
      });

      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (prefersReducedMotion) {
        sim.tick(50);
        sim.stop();
      }
    }

    renderNodeList(graph.nodes);

    const apexNode = simNodes.find((n) => n.isApex);
    if (apexNode !== undefined) {
      showNodeDetails(apexNode);
    }
  }

  function formatNodeLabel(hostname: string, isApex: boolean): string {
    if (isApex) return hostname;
    const parts = hostname.split('.');
    if (parts.length > 2) {
      return parts[0] ?? hostname;
    }
    return hostname;
  }

  function showNodeDetails(node: GraphNode): void {
    nodeHostname.textContent = node.hostname;
    nodeRole.textContent = node.isApex ? '👑 Apex Domain (Central Authority)' : 'Subdomain';
    nodeDiscoveredVia.textContent = node.discoveredVia.join(', ');
    nodeGrade.textContent =
      node.grade !== undefined && node.score !== undefined
        ? `${node.grade} (${node.score}/100)`
        : 'Passive discovery (no direct visit yet)';
    nodeScope.textContent = node.scopeStatus !== undefined ? node.scopeStatus : '—';
    nodeLastSeen.textContent = new Date(node.lastSeen).toLocaleTimeString();
    nodeDetails.hidden = false;
  }

  function clamp(val: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, val));
  }

  function renderNodeList(nodes: GraphNode[]): void {
    const tbody = getEl<HTMLTableSectionElement>('node-list-body');
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    for (const node of nodes) {
      const tr = document.createElement('tr');
      tr.setAttribute('role', 'row');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('aria-selected', 'false');

      const tdHost = document.createElement('td');
      tdHost.textContent = node.hostname;

      const tdRole = document.createElement('td');
      tdRole.textContent = node.isApex ? 'Apex' : 'Subdomain';

      const tdGrade = document.createElement('td');
      tdGrade.className = 'grade-cell';
      tdGrade.textContent =
        node.grade !== undefined && node.score !== undefined ? `${node.grade} (${node.score})` : '—';

      const tdSeen = document.createElement('td');
      tdSeen.textContent = new Date(node.lastSeen).toLocaleTimeString();

      tr.appendChild(tdHost);
      tr.appendChild(tdRole);
      tr.appendChild(tdGrade);
      tr.appendChild(tdSeen);

      tr.addEventListener('click', () => {
        for (const r of Array.from(tbody.rows)) {
          r.setAttribute('aria-selected', 'false');
        }
        tr.setAttribute('aria-selected', 'true');
        showNodeDetails(node);
      });

      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          tr.click();
        }
      });

      tbody.appendChild(tr);
    }
  }

  // ── Polar Radar Implementation ───────────────────────────────
  function renderSidepanelRadar(): void {
    while (spRadarRings.firstChild) spRadarRings.removeChild(spRadarRings.firstChild);
    while (spRadarAxes.firstChild) spRadarAxes.removeChild(spRadarAxes.firstChild);
    while (spRadarBlips.firstChild) spRadarBlips.removeChild(spRadarBlips.firstChild);

    const radii = [25, 50, 75, 100];
    for (const r of radii) {
      const circle = document.createElementNS(SVG_NS, 'circle');
      circle.setAttribute('cx', '0');
      circle.setAttribute('cy', '0');
      circle.setAttribute('r', r.toString());
      circle.setAttribute('class', 'radar-ring');
      // Defensive SVG paint — complement CSS in case stylesheets fail to load
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', '#232038');
      circle.setAttribute('stroke-width', r === 100 ? '1.2' : '1');
      spRadarRings.appendChild(circle);
    }

    for (let i = 0; i < 8; i++) {
      const angle = (i * 45 * Math.PI) / 180;
      const x2 = 100 * Math.cos(angle);
      const y2 = 100 * Math.sin(angle);

      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('x1', '0');
      line.setAttribute('y1', '0');
      line.setAttribute('x2', x2.toString());
      line.setAttribute('y2', y2.toString());
      line.setAttribute('class', 'radar-axis');
      // Defensive SVG paint
      line.setAttribute('stroke', '#232038');
      line.setAttribute('stroke-width', '0.5');
      line.setAttribute('stroke-opacity', '0.5');
      spRadarAxes.appendChild(line);

      const fam = FAMILIES[i];
      if (fam) {
        const lx = 112 * Math.cos(angle);
        const ly = 112 * Math.sin(angle);
        const text = document.createElementNS(SVG_NS, 'text');
        text.setAttribute('x', lx.toString());
        text.setAttribute('y', (ly + 3).toString());
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('class', 'radar-axis-label');
        // Defensive SVG fill for labels
        text.setAttribute('fill', '#7e9ab0');
        text.setAttribute('font-size', '8');
        text.textContent = fam.id;
        spRadarAxes.appendChild(text);
      }
    }

    const sevFilter = radarSeverityFilter.value;
    const leadsToPlot = currentLeads.filter((l) => {
      if (sevFilter === 'all') return true;
      return l.potential === sevFilter;
    });

    const angleMap: Record<string, number> = {
      F1: 0,
      F2: 45,
      F3: 90,
      F4: 135,
      F5: 180,
      F6: 225,
      F7: 270,
      F8: 315,
    };

    const radiusMap: Record<string, number> = {
      critical: 28,
      high: 48,
      medium: 68,
      low: 84,
      info: 96,
    };

    if (activeOrigin !== seenMotionOrigin) {
      seenMotionOrigin = activeOrigin;
      seenLeadCardIds.clear();
      seenRadarLeadIds.clear();
    }

    for (const lead of leadsToPlot) {
      const baseAngleDeg = angleMap[lead.family] ?? 0;
      const baseRadius = radiusMap[lead.potential] ?? 70;

      let hash = 0;
      for (let j = 0; j < lead.id.length; j++) {
        hash = (hash * 31 + lead.id.charCodeAt(j)) & 0xffffffff;
      }
      const angleJitter = ((hash % 100) / 100 - 0.5) * 20;
      const radiusJitter = (((hash >> 8) % 100) / 100 - 0.5) * 12;

      const angleRad = ((baseAngleDeg + angleJitter) * Math.PI) / 180;
      const radius = clamp(baseRadius + radiusJitter, 15, 100);

      const bx = radius * Math.cos(angleRad);
      const by = radius * Math.sin(angleRad);

      const blip = document.createElementNS(SVG_NS, 'circle');
      blip.setAttribute('cx', bx.toFixed(1));
      blip.setAttribute('cy', by.toFixed(1));
      blip.setAttribute('r', '4');
      blip.setAttribute('class', `radar-blip blip-${lead.potential}`);
      // Keyboard-focusable blips with accessible names
      blip.setAttribute('tabindex', '0');
      blip.setAttribute('role', 'button');
      blip.setAttribute('aria-label', `${lead.potential} ${lead.family}: ${lead.title}`);

      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = `[${lead.family}] ${lead.title} (${lead.potential})`;
      blip.appendChild(title);

      blip.addEventListener('click', () => {
        switchTab('tab-findings');
        focusLeadCardInSidepanel(lead.id);
      });
      blip.addEventListener('keydown', (e: KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          switchTab('tab-findings');
          focusLeadCardInSidepanel(lead.id);
        }
      });

      spRadarBlips.appendChild(blip);

      // One-shot radar ping ring for genuinely newly appeared lead IDs
      if (!seenRadarLeadIds.has(lead.id)) {
        seenRadarLeadIds.add(lead.id);
        const ping = document.createElementNS(SVG_NS, 'circle');
        ping.setAttribute('cx', bx.toFixed(1));
        ping.setAttribute('cy', by.toFixed(1));
        ping.setAttribute('r', '5');
        ping.setAttribute('class', 'radar-blip-ping');
        const removePing = () => {
          ping.remove();
        };
        ping.addEventListener('animationend', removePing, { once: true });
        setTimeout(removePing, 600);
        spRadarBlips.appendChild(ping);
      }
    }

    // Show empty-state when no blips match filter
    const radarContainer = document.querySelector('.radar-panel-container');
    if (radarContainer !== null) {
      let emptyEl = radarContainer.querySelector<HTMLElement>('.radar-empty-state');
      if (leadsToPlot.length === 0) {
        if (emptyEl === null) {
          emptyEl = document.createElement('div');
          emptyEl.className = 'radar-empty-state';
          const icon = document.createElement('span');
          icon.className = 'radar-empty-icon';
          icon.textContent = '📡';
          emptyEl.appendChild(icon);
          const text = document.createElement('span');
          text.className = 'radar-empty-text';
          emptyEl.appendChild(text);
          radarContainer.appendChild(emptyEl);
        }
        const textEl = emptyEl.querySelector<HTMLElement>('.radar-empty-text');
        if (textEl !== null) {
          textEl.textContent =
            sevFilter !== 'all'
              ? `No ${sevFilter} leads to display. Try adjusting the severity filter.`
              : 'No leads detected yet. Browse the target application to accumulate attack surface intelligence.';
        }
        emptyEl.hidden = false;
      } else if (emptyEl !== null) {
        emptyEl.hidden = true;
      }
    }
  }

  radarSeverityFilter.addEventListener('change', renderSidepanelRadar);

  // ── Radar sweep pause when hidden, in settings, or reduced motion ──
  const radarSweepEl = document.getElementById('sp-radar-sweep');
  function updateRadarSweepState(): void {
    if (!radarSweepEl) return;
    const motionReduced = document.documentElement.getAttribute('data-motion') === 'reduce';
    const overviewVisible =
      !viewOverview.hidden &&
      viewSettings.hidden &&
      document.visibilityState === 'visible' &&
      !motionReduced;
    radarSweepEl.style.animationPlayState = overviewVisible ? 'running' : 'paused';
  }
  document.addEventListener('visibilitychange', updateRadarSweepState);
  // Monitor Overview, Settings, and reduced-motion attribute changes
  const radarViewObserver = new MutationObserver(updateRadarSweepState);
  radarViewObserver.observe(viewOverview, { attributes: true, attributeFilter: ['hidden'] });
  radarViewObserver.observe(viewSettings, { attributes: true, attributeFilter: ['hidden'] });
  radarViewObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-motion'] });
  updateRadarSweepState();

  // ── Leads View Filtering & Rendering ─────────────────────────
  function getFilteredLeads(): Lead[] {
    const q = leadsSearchInput.value.toLowerCase().trim();
    const fam = leadsFilterFamily.value;
    const tier = leadsFilterTier.value;
    const scope = leadsFilterScope.value;
    const newOnly = leadsFilterNewOnly.checked;
    const chainOnly = leadsFilterChainOnly.checked;

    return currentLeads
      .filter((lead) => {
        if (q.length > 0) {
          const matchTitle = lead.title.toLowerCase().includes(q);
          const matchRule = lead.ruleId.toLowerCase().includes(q);
          const matchTag = lead.tags.some((t) => t.toLowerCase().includes(q));
          if (!matchTitle && !matchRule && !matchTag) return false;
        }
        if (fam !== 'all' && lead.family !== fam) return false;
        if (tier !== 'all' && lead.tier !== tier) return false;
        if (scope !== 'all' && lead.scopeStatus !== scope) return false;
        if (newOnly && lead.pinned === true) return false;
        if (chainOnly && (!lead.chainIds || lead.chainIds.length === 0)) return false;
        return true;
      })
      .sort((a, b) => {
        if (a.pinned === true && b.pinned !== true) return -1;
        if (b.pinned === true && a.pinned !== true) return 1;
        const pOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        const pa = pOrder[a.potential] ?? 0;
        const pb = pOrder[b.potential] ?? 0;
        if (pb !== pa) return pb - pa;
        return b.timestamp - a.timestamp;
      });
  }

  function renderLeadsList(): void {
    while (spLeadsList.firstChild) {
      spLeadsList.removeChild(spLeadsList.firstChild);
    }

    const filtered = getFilteredLeads();

    if (filtered.length === 0) {
      spLeadsEmpty.hidden = false;
      return;
    }
    spLeadsEmpty.hidden = true;

    let animatedCount = 0;
    filtered.forEach((lead, index) => {
      const card = renderLeadCard(lead, index);
      if (!seenLeadCardIds.has(lead.id) && animatedCount < 8) {
        seenLeadCardIds.add(lead.id);
        card.classList.add('motion-smoke-enter');
        card.style.setProperty('--smoke-delay', `${animatedCount * 24}ms`);
        animatedCount++;
        const cleanupCardMotion = () => card.classList.remove('motion-smoke-enter');
        card.addEventListener('animationend', cleanupCardMotion, { once: true });
        setTimeout(cleanupCardMotion, 450);
      } else {
        seenLeadCardIds.add(lead.id);
      }
      spLeadsList.appendChild(card);
    });
  }

  leadsSearchInput.addEventListener('input', renderLeadsList);
  leadsFilterFamily.addEventListener('change', renderLeadsList);
  leadsFilterTier.addEventListener('change', renderLeadsList);
  leadsFilterScope.addEventListener('change', renderLeadsList);
  leadsFilterNewOnly.addEventListener('change', renderLeadsList);
  leadsFilterChainOnly.addEventListener('change', renderLeadsList);

  function renderLeadCard(lead: Lead, index: number): HTMLElement {
    const card = document.createElement('div');
    card.className = `lead-card lead-card-${lead.potential}`;
    card.id = `sp-lead-card-${lead.id}`;
    if (lead.pinned === true) card.classList.add('lead-pinned');

    // Header line
    const header = document.createElement('div');
    header.className = 'lead-card-header';

    const badgesLeft = document.createElement('div');
    badgesLeft.className = 'lead-badges-left';

    const famBadge = document.createElement('span');
    famBadge.className = 'lead-family-icon';
    famBadge.textContent = lead.family;
    badgesLeft.appendChild(famBadge);

    const tierBadgeEl = document.createElement('span');
    tierBadgeEl.className = `lead-tier-badge tier-${lead.tier}`;
    tierBadgeEl.textContent = lead.tier;
    badgesLeft.appendChild(tierBadgeEl);

    if (lead.scopeStatus) {
      const scopeBadge = document.createElement('span');
      scopeBadge.className = `lead-scope-badge scope-${lead.scopeStatus}`;
      scopeBadge.textContent = lead.scopeStatus;
      badgesLeft.appendChild(scopeBadge);
    }

    // Verdict Badge
    if (lead.verdict !== undefined) {
      const vBadge = document.createElement('span');
      vBadge.className = `lead-verdict-badge verdict-${lead.verdict.status}`;
      if (lead.verdict.status === 'uncertain') {
        vBadge.textContent = '? Uncertain';
      } else if (lead.verdict.status === 'likely') {
        vBadge.textContent = 'Likely bug';
      } else if (lead.verdict.status === 'confirmed') {
        vBadge.textContent = '✔ Confirmed bug';
      } else if (lead.verdict.status === 'informational') {
        vBadge.textContent = 'Info only';
      } else if (lead.verdict.status === 'false_positive') {
        vBadge.textContent = '✘ False positive';
      }
      badgesLeft.appendChild(vBadge);
    }

    header.appendChild(badgesLeft);

    const potDot = document.createElement('span');
    potDot.className = `lead-tier-badge dot-${lead.potential}`;
    potDot.textContent = lead.potential.toUpperCase();
    header.appendChild(potDot);

    card.appendChild(header);

    // Title
    const title = document.createElement('h3');
    title.className = 'lead-title';
    title.textContent = lead.title;
    card.appendChild(title);

    // Evidence Preview
    if (lead.evidence !== undefined && typeof lead.evidence.preview === 'string' && lead.evidence.preview.length > 0) {
      const prev = document.createElement('pre');
      prev.className = 'lead-evidence-preview';
      prev.textContent = lead.evidence.preview;
      card.appendChild(prev);
    }

    // Location
    if (lead.evidence !== undefined && typeof lead.evidence.location === 'string' && lead.evidence.location.length > 0) {
      const locLine = document.createElement('div');
      locLine.className = 'lead-detail-line';
      const locLabel = document.createElement('span');
      locLabel.className = 'lead-detail-label';
      locLabel.textContent = 'Location: ';
      locLine.appendChild(locLabel);
      const locVal = document.createTextNode(lead.evidence.location);
      locLine.appendChild(locVal);
      card.appendChild(locLine);
    }

    // Correlated Chain
    if (lead.chainIds !== undefined && lead.chainIds.length > 0) {
      const chainLine = document.createElement('div');
      chainLine.className = 'lead-detail-line';
      const chainLabel = document.createElement('span');
      chainLabel.className = 'lead-detail-label';
      chainLabel.textContent = '⛓ Correlated Chain: ';
      chainLine.appendChild(chainLabel);
      const chainVal = document.createTextNode(lead.chainIds.join(', '));
      chainLine.appendChild(chainVal);
      card.appendChild(chainLine);
    }

    // Verdict details & dimensions line
    if (lead.verdict !== undefined) {
      const vLine = document.createElement('div');
      vLine.className = 'lead-detail-line lead-verdict-line';
      const vLabel = document.createElement('span');
      vLabel.className = 'lead-detail-label';
      vLabel.textContent = `Self-check (${lead.verdict.method}): `;
      vLine.appendChild(vLabel);
      vLine.appendChild(document.createTextNode(lead.verdict.summary));
      card.appendChild(vLine);

      const dimLine = document.createElement('div');
      dimLine.className = 'lead-detail-line lead-dimensions-line';

      const assessLabel = document.createElement('span');
      assessLabel.className = 'lead-detail-label';
      assessLabel.textContent = 'Assessment: ';
      dimLine.appendChild(assessLabel);

      const assessVal = document.createElement('span');
      assessVal.className = `lead-dim-val dim-assessment-${lead.verdict.securityAssessment}`;
      assessVal.textContent = lead.verdict.securityAssessment;
      dimLine.appendChild(assessVal);

      dimLine.appendChild(document.createTextNode(' · '));

      const evidLabel = document.createElement('span');
      evidLabel.className = 'lead-detail-label';
      evidLabel.textContent = 'Evidence: ';
      dimLine.appendChild(evidLabel);

      const evidVal = document.createElement('span');
      evidVal.className = `lead-dim-val dim-evidence-${lead.verdict.evidenceStatus}`;
      evidVal.textContent = lead.verdict.evidenceStatus;
      dimLine.appendChild(evidVal);

      dimLine.appendChild(document.createTextNode(' · '));

      const scopeLabel = document.createElement('span');
      scopeLabel.className = 'lead-detail-label';
      scopeLabel.textContent = 'Scope: ';
      dimLine.appendChild(scopeLabel);

      const scopeVal = document.createElement('span');
      scopeVal.className = `lead-dim-val dim-scope-${lead.verdict.scopeStatus}`;
      scopeVal.textContent = lead.verdict.scopeStatus;
      dimLine.appendChild(scopeVal);

      card.appendChild(dimLine);

      const failed = lead.verdict.checks.filter((c) => c.outcome !== 'pass');
      if (failed.length > 0) {
        const det = document.createElement('details');
        det.className = 'lead-verdict-checks';
        const sum = document.createElement('summary');
        sum.textContent = `Why? ${lead.verdict.checks.length} checks`;
        det.appendChild(sum);
        for (const c of lead.verdict.checks) {
          const li = document.createElement('div');
          li.className = `verdict-check check-${c.outcome}`;
          li.textContent = `${c.outcome === 'pass' ? '✔' : c.outcome === 'fail' ? '✘' : '?'} ${c.detail}`;
          det.appendChild(li);
        }
        card.appendChild(det);
      }
      if (lead.verdict.missing.length > 0) {
        const mLine = document.createElement('div');
        mLine.className = 'lead-detail-line';
        const mLabel = document.createElement('span');
        mLabel.className = 'lead-detail-label';
        mLabel.textContent = 'Still needed: ';
        mLine.appendChild(mLabel);
        mLine.appendChild(document.createTextNode(lead.verdict.missing.join('; ')));
        card.appendChild(mLine);
      }
    } else if (lead.needs !== undefined && lead.needs.length > 0) {
      const needsLine = document.createElement('div');
      needsLine.className = 'lead-detail-line';
      const needsLabel = document.createElement('span');
      needsLabel.className = 'lead-detail-label';
      needsLabel.textContent = 'Verification Needed: ';
      needsLine.appendChild(needsLabel);
      const needsVal = document.createTextNode(lead.needs.join('; '));
      needsLine.appendChild(needsVal);
      card.appendChild(needsLine);
    }

    if (lead.credentialCheck !== undefined) {
      const credLine = document.createElement('div');
      credLine.className = 'lead-detail-line lead-credential-check-line';

      const credLabel = document.createElement('span');
      credLabel.className = 'lead-detail-label';
      credLabel.textContent = 'Credential Liveness: ';
      credLine.appendChild(credLabel);

      const statusBadge = document.createElement('span');
      statusBadge.className = `cred-status-badge cred-${lead.credentialCheck.status}`;
      statusBadge.textContent = lead.credentialCheck.status;
      credLine.appendChild(statusBadge);

      const detailsSpan = document.createElement('span');
      detailsSpan.className = 'cred-details-text';
      detailsSpan.textContent = ` — ${lead.credentialCheck.details} (${new Date(
        lead.credentialCheck.checkedAt
      ).toLocaleTimeString()})`;
      credLine.appendChild(detailsSpan);

      const disclaimerDiv = document.createElement('div');
      disclaimerDiv.className = 'cred-disclaimer-text';
      disclaimerDiv.textContent =
        "Notice: This reports only what the provider accepted at the time of the check. It does not establish the credential's full permissions, exploitability, or authorization to use it.";
      credLine.appendChild(disclaimerDiv);

      card.appendChild(credLine);
    }

    const actions = document.createElement('div');
    actions.className = 'lead-card-actions';

    // Credential Liveness Check action for F1 secrets (opt-in)
    if (
      lead.family === 'F1' &&
      currentSettings.credentialLivenessEnabled === true &&
      lead.scopeStatus === 'in-scope' &&
      lead.credentialCheck === undefined
    ) {
      const checkBtn = document.createElement('button');
      checkBtn.className = 'lead-btn';
      checkBtn.textContent = '🔑 Check Liveness';
      checkBtn.title =
        'Send a 1-request authenticated check to the provider (GitHub, Stripe, Slack). Never runs automatically.';
      checkBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        void performCredentialCheckFlow(lead, checkBtn);
      });
      actions.appendChild(checkBtn);
    }

    // Active self-check (only for leads that have a safe, read-only test)
    if (activeCapabilityOf(lead) !== 'none' && lead.verdict?.method !== 'active') {
      const verifyBtn = document.createElement('button');
      verifyBtn.className = 'lead-btn';
      verifyBtn.textContent = '🔍 Verify';
      verifyBtn.title =
        'Send safe read-only requests (no cookies) to test this lead. Requires in-scope target and Hunter enabled.';
      verifyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        void verifyLeadActively(lead, verifyBtn);
      });
      actions.appendChild(verifyBtn);
    }

    // Pin
    const pinBtn = document.createElement('button');
    pinBtn.className = 'lead-btn';
    pinBtn.textContent = lead.pinned === true ? '📌 Pinned' : '📍 Pin';
    if (lead.pinned === true) pinBtn.classList.add('btn-active');
    pinBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      void togglePinLead(lead);
    });
    actions.appendChild(pinBtn);

    // Triage
    const triageBtn = document.createElement('button');
    triageBtn.className = 'lead-btn';
    const triageText =
      typeof lead.triageState === 'string' && lead.triageState.length > 0 ? lead.triageState : 'Triage';
    triageBtn.textContent = `🎯 ${triageText}`;
    triageBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      void cycleTriageLead(lead);
    });
    actions.appendChild(triageBtn);

    // Copy report
    const reportBtn = document.createElement('button');
    reportBtn.className = 'lead-btn';
    reportBtn.textContent = '📄 Copy Report';
    reportBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const md = formatLeadsReportMarkdown([lead]);
      void navigator.clipboard.writeText(md).then(() => {
        const orig = reportBtn.textContent;
        reportBtn.textContent = '✔ Copied!';
        setTimeout(() => {
          reportBtn.textContent = orig;
        }, 1500);
      });
    });
    actions.appendChild(reportBtn);

    // Copy cURL (Strictly in-scope GET requests without cookies)
    const curlBtn = document.createElement('button');
    curlBtn.className = 'lead-btn';
    curlBtn.textContent = '💻 Copy cURL';
    if (isSafeCurlLead(lead)) {
      curlBtn.title = 'Copy safe in-scope GET cURL command without cookies';
      curlBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copySafeCurl(lead, curlBtn);
      });
    } else {
      curlBtn.disabled = true;
      curlBtn.style.opacity = '0.5';
      curlBtn.style.cursor = 'not-allowed';
      curlBtn.title = 'cURL export only available for in-scope GET requests without cookies';
    }
    actions.appendChild(curlBtn);

    card.appendChild(actions);

    card.addEventListener('click', () => {
      selectedLeadIndex = index;
      document.querySelectorAll('#sp-leads-list .lead-card').forEach((c) => c.classList.remove('focused-card'));
      card.classList.add('focused-card');
    });

    return card;
  }

  function isSafeCurlLead(lead: Lead): boolean {
    if (lead.scopeStatus !== 'in-scope') return false;
    if (typeof lead.url !== 'string') return false;
    // Reject newlines and null bytes
    if (/[\r\n\0]/.test(lead.url)) return false;
    try {
      const parsed = new URL(lead.url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    } catch {
      return false;
    }
    const leadMethod = (lead as unknown as { method?: string }).method;
    if (leadMethod !== undefined && leadMethod.toUpperCase() !== 'GET') {
      return false;
    }
    return true;
  }

  function copySafeCurl(lead: Lead, btn: HTMLButtonElement): void {
    if (!isSafeCurlLead(lead)) return;
    const safeUrl = lead.url.replace(/'/g, "'\\''");
    const curlCmd = "curl -s -i '" + safeUrl + "'";
    void navigator.clipboard.writeText(curlCmd).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✔ Copied!';
      setTimeout(() => {
        btn.textContent = orig;
      }, 1500);
    });
  }

  function promptHunterConfirmation(
    plan: NonNullable<ReturnType<typeof planActiveProbe>>
  ): Promise<boolean> {
    const dialog = getEl<HTMLDialogElement>('hunter-confirm-dialog');
    const descEl = getEl<HTMLElement>('hunter-plan-desc');
    const urlEl = getEl<HTMLElement>('hunter-plan-url');
    const methodEl = getEl<HTMLElement>('hunter-plan-method');
    const requestsEl = getEl<HTMLElement>('hunter-plan-requests');
    const originsRow = getEl<HTMLElement>('hunter-plan-origins-row');
    const originsEl = getEl<HTMLElement>('hunter-plan-origins');
    const check = getEl<HTMLInputElement>('hunter-confirm-check');
    const submitBtn = getEl<HTMLButtonElement>('hunter-submit-btn');
    const cancelBtn = getEl<HTMLButtonElement>('hunter-cancel-btn');
    const closeBtn = document.getElementById('hunter-close-btn');

    descEl.textContent = plan.description;
    urlEl.textContent = plan.targetUrl;
    methodEl.textContent = `${plan.method} (credentials: ${plan.credentials}, redirect: ${plan.redirect})`;
    requestsEl.textContent = String(plan.maxRequests);

    if (plan.testOrigins && plan.testOrigins.length > 0) {
      originsRow.hidden = false;
      originsEl.textContent = plan.testOrigins.join(', ');
    } else {
      originsRow.hidden = true;
      originsEl.textContent = '';
    }

    check.checked = false;
    submitBtn.disabled = true;

    return new Promise<boolean>((resolve) => {
      let resolved = false;

      const onCheckChange = () => {
        submitBtn.disabled = !check.checked;
      };

      const cleanup = () => {
        check.removeEventListener('change', onCheckChange);
        submitBtn.removeEventListener('click', onSubmit);
        cancelBtn.removeEventListener('click', onCancel);
        closeBtn?.removeEventListener('click', onCancel);
        dialog.removeEventListener('close', onClose);
        if (dialog.open) {
          dialog.close();
        }
      };

      const onSubmit = () => {
        if (!check.checked) return;
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(true);
      };

      const onCancel = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(false);
      };

      const onClose = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(false);
      };

      check.addEventListener('change', onCheckChange);
      submitBtn.addEventListener('click', onSubmit);
      cancelBtn.addEventListener('click', onCancel);
      closeBtn?.addEventListener('click', onCancel);
      dialog.addEventListener('close', onClose);

      dialog.showModal();
    });
  }

  function promptCredentialLivenessWizard(
    plan: NonNullable<PlanCredentialCheckResponse['plan']>
  ): Promise<boolean> {
    const dialog = getEl<HTMLDialogElement>('credential-liveness-dialog');
    const closeBtn = document.getElementById('cred-close-btn');

    // Steps
    const step1 = getEl<HTMLDivElement>('cred-wizard-step-1');
    const step2 = getEl<HTMLDivElement>('cred-wizard-step-2');
    const step3 = getEl<HTMLDivElement>('cred-wizard-step-3');
    const step4 = getEl<HTMLDivElement>('cred-wizard-step-4');

    // Stepper indicators
    const stepper1 = getEl<HTMLDivElement>('cred-stepper-1');
    const stepper2 = getEl<HTMLDivElement>('cred-stepper-2');
    const stepper3 = getEl<HTMLDivElement>('cred-stepper-3');
    const stepper4 = getEl<HTMLDivElement>('cred-stepper-4');

    // Step 1 fields
    const providerVal = getEl<HTMLElement>('cred-provider-val');
    const endpointVal = getEl<HTMLElement>('cred-endpoint-val');
    const secretVal = getEl<HTMLElement>('cred-secret-val');
    const tokenVal = getEl<HTMLElement>('cred-token-val');
    const originVal = getEl<HTMLElement>('cred-origin-val');
    const step1CancelBtn = getEl<HTMLButtonElement>('cred-step1-cancel-btn');
    const step1NextBtn = getEl<HTMLButtonElement>('cred-step1-next-btn');

    // Step 2 fields
    const stripeBanner = getEl<HTMLElement>('cred-stripe-warning-banner');
    const step2BackBtn = getEl<HTMLButtonElement>('cred-step2-back-btn');
    const step2NextBtn = getEl<HTMLButtonElement>('cred-step2-next-btn');

    // Step 3 fields
    const authInput = getEl<HTMLInputElement>('cred-auth-phrase-input');
    const step3BackBtn = getEl<HTMLButtonElement>('cred-step3-back-btn');
    const step3NextBtn = getEl<HTMLButtonElement>('cred-step3-next-btn');

    // Step 4 fields
    const summaryTarget = getEl<HTMLElement>('cred-summary-target');
    const summaryProvider = getEl<HTMLElement>('cred-summary-provider');
    const step4BackBtn = getEl<HTMLButtonElement>('cred-step4-back-btn');
    const submitBtn = getEl<HTMLButtonElement>('cred-submit-btn');

    // Populate data
    providerVal.textContent = plan.provider.toUpperCase();
    endpointVal.textContent = `${plan.method} ${plan.endpointUrl}`;
    secretVal.textContent = plan.maskedIdentity;
    tokenVal.textContent = plan.tokenFamily;
    originVal.textContent = plan.requiredOrigin;

    if (plan.provider === 'stripe') {
      stripeBanner.hidden = false;
    } else {
      stripeBanner.hidden = true;
    }

    summaryTarget.textContent = `${plan.method} ${plan.endpointUrl}`;
    summaryProvider.textContent = `${plan.provider.toUpperCase()} (${plan.tokenFamily})`;

    authInput.value = '';
    step3NextBtn.disabled = true;

    const setStep = (stepNumber: 1 | 2 | 3 | 4) => {
      step1.hidden = stepNumber !== 1;
      step2.hidden = stepNumber !== 2;
      step3.hidden = stepNumber !== 3;
      step4.hidden = stepNumber !== 4;

      stepper1.classList.toggle('active', stepNumber === 1);
      stepper2.classList.toggle('active', stepNumber === 2);
      stepper3.classList.toggle('active', stepNumber === 3);
      stepper4.classList.toggle('active', stepNumber === 4);
    };

    setStep(1);

    return new Promise<boolean>((resolve) => {
      let resolved = false;

      const onAuthInput = () => {
        step3NextBtn.disabled = authInput.value !== 'I AM AUTHORIZED';
      };

      const cleanup = () => {
        authInput.removeEventListener('input', onAuthInput);
        step1CancelBtn.removeEventListener('click', onCancel);
        step1NextBtn.removeEventListener('click', toStep2);
        step2BackBtn.removeEventListener('click', toStep1);
        step2NextBtn.removeEventListener('click', toStep3);
        step3BackBtn.removeEventListener('click', toStep2);
        step3NextBtn.removeEventListener('click', toStep4);
        step4BackBtn.removeEventListener('click', toStep3);
        submitBtn.removeEventListener('click', onSubmit);
        closeBtn?.removeEventListener('click', onCancel);
        dialog.removeEventListener('close', onClose);
        if (dialog.open) {
          dialog.close();
        }
      };

      const toStep1 = () => setStep(1);
      const toStep2 = () => setStep(2);
      const toStep3 = () => {
        setStep(3);
        setTimeout(() => authInput.focus(), 50);
      };
      const toStep4 = () => {
        if (authInput.value !== 'I AM AUTHORIZED') return;
        setStep(4);
      };

      const onSubmit = () => {
        if (authInput.value !== 'I AM AUTHORIZED') return;
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(true);
      };

      const onCancel = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(false);
      };

      const onClose = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(false);
      };

      authInput.addEventListener('input', onAuthInput);
      step1CancelBtn.addEventListener('click', onCancel);
      step1NextBtn.addEventListener('click', toStep2);
      step2BackBtn.addEventListener('click', toStep1);
      step2NextBtn.addEventListener('click', toStep3);
      step3BackBtn.addEventListener('click', toStep2);
      step3NextBtn.addEventListener('click', toStep4);
      step4BackBtn.addEventListener('click', toStep3);
      submitBtn.addEventListener('click', onSubmit);
      closeBtn?.addEventListener('click', onCancel);
      dialog.addEventListener('close', onClose);

      dialog.showModal();
    });
  }

  async function verifyLeadActively(lead: Lead, btn: HTMLButtonElement): Promise<void> {
    const plan = planActiveProbe(lead);
    if (!plan) return;
    const ok = await promptHunterConfirmation(plan);
    if (!ok) return;
    btn.disabled = true;
    btn.textContent = '… verifying';
    try {
      const res = (await sendToBackground({
        type: 'HUNTER_VERIFY_LEAD',
        leadId: lead.id,
        confirmedByUser: true,
        approvedPlan: {
          capability: plan.capability,
          targetUrl: plan.targetUrl,
          maxRequests: plan.maxRequests,
          method: plan.method,
          testOrigins: plan.testOrigins ? [...plan.testOrigins] : undefined,
          credentials: plan.credentials,
          redirect: plan.redirect,
        },
      })) as { verdict?: Lead['verdict'] } | undefined;
      if (res?.verdict !== undefined) lead.verdict = res.verdict;
    } finally {
      void fetchLeads();
      renderLeadsList();
    }
  }

  async function performCredentialCheckFlow(lead: Lead, btn: HTMLButtonElement): Promise<void> {
    btn.disabled = true;
    btn.textContent = '… planning';

    try {
      // Step 1: Request an opaque proposed plan from background
      const planRes = (await sendToBackground({
        type: 'PLAN_CREDENTIAL_CHECK',
        leadId: lead.id,
      })) as PlanCredentialCheckResponse | undefined;

      if (!planRes || !planRes.success || !planRes.plan) {
        alert(`Cannot check credential: ${planRes?.error ?? 'No plan available'}`);
        return;
      }

      const plan = planRes.plan;

      // Step 2: Show confirmation wizard with exact request parameters, safety warnings, and authorization affirmation
      const affirmed = await promptCredentialLivenessWizard(plan);
      if (!affirmed) return;

      // Step 3: Request runtime host permission if not already granted (fail closed if unavailable)
      if (typeof chrome === 'undefined' || typeof chrome.permissions?.request !== 'function') {
        alert('Browser permissions API is unavailable. Cannot request host permission.');
        return;
      }
      const granted = await new Promise<boolean>((resolve) => {
        try {
          chrome.permissions.request({ origins: [plan.requiredOrigin] }, (ok) => {
            resolve(ok === true);
          });
        } catch {
          resolve(false);
        }
      });
      if (!granted) {
        alert(`Host permission for "${plan.requiredOrigin}" was denied. Cannot contact provider.`);
        return;
      }

      btn.textContent = '… checking';

      // Step 4: Confirm and execute single check
      const confirmRes = (await sendToBackground({
        type: 'CONFIRM_CREDENTIAL_CHECK',
        leadId: lead.id,
        planId: plan.planId,
        confirmedByUser: true,
        affirmAuthorized: true,
      })) as ConfirmCredentialCheckResponse | undefined;

      if (!confirmRes || !confirmRes.success || !confirmRes.result) {
        alert(`Credential check failed: ${confirmRes?.error ?? 'Unknown error'}`);
        return;
      }

      lead.credentialCheck = confirmRes.result;
    } finally {
      btn.disabled = false;
      btn.textContent = '🔑 Check Liveness';
      void fetchLeads();
      renderLeadsList();
    }
  }

  async function togglePinLead(lead: Lead): Promise<void> {
    const newPinned = lead.pinned !== true;
    lead.pinned = newPinned;
    await sendToBackground({
      type: 'LEAD_ACTION',
      leadId: lead.id,
      action: newPinned ? 'pin' : 'unpin',
      pinned: newPinned,
      origin: activeOrigin,
    });
    renderLeadsList();
  }

  async function cycleTriageLead(lead: Lead): Promise<void> {
    const states: Array<NonNullable<Lead['triageState']>> = ['open', 'triaged', 'false_positive', 'resolved'];
    const currentIdx = states.indexOf(lead.triageState ?? 'open');
    const nextIdx = (currentIdx + 1) % states.length;
    const nextState = states[nextIdx] ?? 'open';
    lead.triageState = nextState;
    await sendToBackground({
      type: 'LEAD_ACTION',
      leadId: lead.id,
      action: 'triage',
      triageState: nextState,
      origin: activeOrigin,
    });
    renderLeadsList();
  }

  function focusLeadCardInSidepanel(leadId: string): void {
    const card = document.getElementById(`sp-lead-card-${leadId}`);
    if (card) {
      document.querySelectorAll('#sp-leads-list .lead-card').forEach((c) => c.classList.remove('focused-card'));
      card.classList.add('focused-card');
      card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      card.classList.add('highlight-pulse');
      setTimeout(() => card.classList.remove('highlight-pulse'), 2000);
    }
  }

  // ── Leads Exports ────────────────────────────────────────────
  exportLeadsMdBtn.addEventListener('click', () => {
    const filtered = getFilteredLeads();
    const md = formatLeadsReportMarkdown(filtered);
    downloadBlob(md, `aculyx-leads-${Date.now()}.md`, 'text/markdown');
  });

  exportLeadsJsonBtn.addEventListener('click', () => {
    const filtered = getFilteredLeads();
    const json = formatLeadsReportJson(filtered);
    downloadBlob(json, `aculyx-leads-${Date.now()}.json`, 'application/json');
  });

  exportLeadsSarifBtn.addEventListener('click', () => {
    const filtered = getFilteredLeads();
    const sarif = formatLeadsReportSarif(filtered);
    downloadBlob(sarif, `aculyx-leads-${Date.now()}.sarif`, 'application/sarif+json');
  });

  function downloadBlob(content: string, filename: string, mimeType: string): void {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Chains View Implementation ───────────────────────────────
  function renderChainsView(): void {
    while (chainsListContainer.firstChild) {
      chainsListContainer.removeChild(chainsListContainer.firstChild);
    }

    const activeMap = new Map<string, Lead[]>();
    for (const item of activeChains) {
      activeMap.set(item.chain.id, item.matchedLeads);
    }

    chainsActiveBadge.textContent = `${activeChains.length} Active`;

    for (const chain of CHAINS) {
      const isChainActive = activeMap.has(chain.id);
      const matchedLeads = activeMap.get(chain.id) ?? [];

      const card = document.createElement('div');
      card.className = `chain-card ${isChainActive ? 'chain-active' : 'chain-dormant'}`;

      const header = document.createElement('div');
      header.className = 'chain-card-header';

      const idGroup = document.createElement('div');
      idGroup.className = 'chain-id-group';

      const idBadge = document.createElement('span');
      idBadge.className = 'chain-id-badge';
      idBadge.textContent = chain.id;
      idGroup.appendChild(idBadge);

      const statusPill = document.createElement('span');
      statusPill.className = `chain-status-pill ${isChainActive ? 'chain-status-active' : 'chain-status-dormant'}`;
      statusPill.textContent = isChainActive ? 'Active Chain' : 'Dormant Template';
      idGroup.appendChild(statusPill);

      header.appendChild(idGroup);

      const potBadge = document.createElement('span');
      potBadge.className = `lead-tier-badge dot-${chain.potential}`;
      potBadge.textContent = chain.potential.toUpperCase();
      header.appendChild(potBadge);

      card.appendChild(header);

      // Needs checklist
      const needsTitle = document.createElement('div');
      needsTitle.className = 'chain-step-title';
      needsTitle.textContent = 'Required Chain Nodes:';
      card.appendChild(needsTitle);

      const needsList = document.createElement('div');
      needsList.className = 'chain-needs-list';

      for (const need of chain.needs) {
        const needItem = document.createElement('span');
        const isMatched = isChainActive && matchedLeads.some((l) => l.tags.includes(need) || l.ruleId === need);
        needItem.className = `chain-need-item ${isMatched ? 'matched' : ''}`;
        needItem.textContent = `${isMatched ? '✔ ' : '○ '}${need}`;
        needsList.appendChild(needItem);
      }
      card.appendChild(needsList);

      // Correlated leads
      if (isChainActive && matchedLeads.length > 0) {
        const matchedTitle = document.createElement('div');
        matchedTitle.className = 'chain-step-title';
        matchedTitle.textContent = `Correlated Leads (${matchedLeads.length}):`;
        card.appendChild(matchedTitle);

        const matchedList = document.createElement('div');
        matchedList.className = 'chain-needs-list';
        for (const lead of matchedLeads) {
          const leadPill = document.createElement('span');
          leadPill.className = 'chain-need-item matched';
          leadPill.textContent = `${lead.ruleId}: ${lead.title}`;
          leadPill.style.cursor = 'pointer';
          leadPill.addEventListener('click', () => {
            switchTab('tab-findings');
            focusLeadCardInSidepanel(lead.id);
          });
          matchedList.appendChild(leadPill);
        }
        card.appendChild(matchedList);
      }

      // Next steps
      if (chain.next !== undefined && chain.next.length > 0) {
        const nextTitle = document.createElement('div');
        nextTitle.className = 'chain-step-title';
        nextTitle.textContent = 'Next Manual Testing Step:';
        card.appendChild(nextTitle);

        const nextText = document.createElement('div');
        nextText.className = 'chain-step-text';
        nextText.textContent = chain.next.join('\n');
        card.appendChild(nextText);
      }

      chainsListContainer.appendChild(card);
    }
  }

  // ── Recon View Implementation ────────────────────────────────
  async function fetchAndRenderRecon(): Promise<void> {
    try {
      const res = (await sendToBackground({
        type: 'RECON_GET',
        origin: typeof activeOrigin === 'string' && activeOrigin.length > 0 ? activeOrigin : undefined,
      })) as { type?: string; memory?: ReconMemory } | undefined;

      if (typeof res === 'object' && res !== null && res.type === 'RECON_GET_RESPONSE' && res.memory) {
        currentRecon = res.memory;
        renderReconView();
      }
    } catch {
      // Background SW warming up
    }
  }

  function renderReconView(): void {
    reconHostsCount.textContent = currentRecon.hosts.length.toString();
    reconEndpointsCount.textContent = currentRecon.endpoints.length.toString();
    reconParamsCount.textContent = currentRecon.params.length.toString();
    reconBucketsCount.textContent = currentRecon.buckets.length.toString();

    // Endpoints
    while (reconEndpointsList.firstChild) reconEndpointsList.removeChild(reconEndpointsList.firstChild);
    if (currentRecon.endpoints.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'recon-item';
      empty.textContent = 'No endpoints discovered yet.';
      reconEndpointsList.appendChild(empty);
    } else {
      for (const ep of currentRecon.endpoints) {
        const item = document.createElement('div');
        item.className = 'recon-item';
        const pathSpan = document.createElement('span');
        pathSpan.textContent = `${ep.method ?? 'GET'} ${ep.path}`;
        const tagPill = document.createElement('span');
        tagPill.className = 'recon-item-pill';
        tagPill.textContent = ep.origin || 'endpoint';
        item.appendChild(pathSpan);
        item.appendChild(tagPill);
        reconEndpointsList.appendChild(item);
      }
    }

    // Parameters
    while (reconParamsList.firstChild) reconParamsList.removeChild(reconParamsList.firstChild);
    if (currentRecon.params.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'recon-item';
      empty.textContent = 'No parameters discovered yet.';
      reconParamsList.appendChild(empty);
    } else {
      for (const p of currentRecon.params) {
        const item = document.createElement('div');
        item.className = 'recon-item';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = p.name;
        const catPill = document.createElement('span');
        catPill.className = 'recon-item-pill';
        catPill.textContent = p.category ?? 'param';
        item.appendChild(nameSpan);
        item.appendChild(catPill);
        reconParamsList.appendChild(item);
      }
    }

    // Hosts
    while (reconHostsList.firstChild) reconHostsList.removeChild(reconHostsList.firstChild);
    if (currentRecon.hosts.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'recon-item';
      empty.textContent = 'No hosts discovered yet.';
      reconHostsList.appendChild(empty);
    } else {
      for (const h of currentRecon.hosts) {
        const item = document.createElement('div');
        item.className = 'recon-item';
        const hostSpan = document.createElement('span');
        hostSpan.textContent = h.hostname;
        const scopePill = document.createElement('span');
        scopePill.className = 'recon-item-pill';
        scopePill.textContent = h.scopeStatus || 'discovered';
        item.appendChild(hostSpan);
        item.appendChild(scopePill);
        reconHostsList.appendChild(item);
      }
    }

    // Buckets
    while (reconBucketsList.firstChild) reconBucketsList.removeChild(reconBucketsList.firstChild);
    if (currentRecon.buckets.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'recon-item';
      empty.textContent = 'No cloud buckets discovered yet.';
      reconBucketsList.appendChild(empty);
    } else {
      for (const b of currentRecon.buckets) {
        const item = document.createElement('div');
        item.className = 'recon-item';
        const bSpan = document.createElement('span');
        bSpan.textContent = b.bucket;
        const provPill = document.createElement('span');
        provPill.className = 'recon-item-pill';
        provPill.textContent = b.provider;
        item.appendChild(bSpan);
        item.appendChild(provPill);
        reconBucketsList.appendChild(item);
      }
    }
  }

  // Recon Subtabs
  const reconSubtabs = [
    { btn: reconSubtabEndpoints, sec: reconSectionEndpoints },
    { btn: reconSubtabParams, sec: reconSectionParams },
    { btn: reconSubtabHosts, sec: reconSectionHosts },
    { btn: reconSubtabBuckets, sec: reconSectionBuckets },
  ];

  for (const rst of reconSubtabs) {
    rst.btn.addEventListener('click', () => {
      for (const other of reconSubtabs) {
        other.btn.classList.remove('active');
        other.sec.hidden = true;
      }
      rst.btn.classList.add('active');
      rst.sec.hidden = false;
    });
  }

  downloadWordlistBtn.addEventListener('click', () => {
    const paramNames = currentRecon.params.map((p) => p.name);
    const endpointPaths = currentRecon.endpoints.map((e) => e.path);
    const list = generateNameOnlyWordlist(paramNames, endpointPaths);
    downloadBlob(list, `aculyx-wordlist-${Date.now()}.txt`, 'text/plain');
  });

  function promptGeneralConfirm(title: string, message: string): Promise<boolean> {
    const dialog = getEl<HTMLDialogElement>('confirm-modal-dialog');
    const titleEl = getEl<HTMLElement>('confirm-modal-title');
    const msgEl = getEl<HTMLElement>('confirm-modal-message');
    const confirmBtn = getEl<HTMLButtonElement>('confirm-modal-confirm-btn');
    const cancelBtn = getEl<HTMLButtonElement>('confirm-modal-cancel-btn');
    const closeBtn = document.getElementById('confirm-modal-close-btn');

    titleEl.textContent = title;
    msgEl.textContent = message;

    return new Promise<boolean>((resolve) => {
      let resolved = false;

      const cleanup = () => {
        confirmBtn.removeEventListener('click', onConfirm);
        cancelBtn.removeEventListener('click', onCancel);
        closeBtn?.removeEventListener('click', onCancel);
        dialog.removeEventListener('close', onClose);
        if (dialog.open) {
          dialog.close();
        }
      };

      const onConfirm = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(true);
      };

      const onCancel = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(false);
      };

      const onClose = () => {
        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(false);
      };

      confirmBtn.addEventListener('click', onConfirm);
      cancelBtn.addEventListener('click', onCancel);
      closeBtn?.addEventListener('click', onCancel);
      dialog.addEventListener('close', onClose);

      dialog.showModal();
    });
  }

  resetReconBtn.addEventListener('click', () => {
    void promptGeneralConfirm(
      'Reset Recon Memory',
      'Reset all remembered recon memory (hosts, endpoints, params, buckets) for this session?'
    ).then((ok) => {
      if (!ok) return;
      void sendToBackground({ type: 'RECON_RESET' }).then(() => {
        currentRecon = { hosts: [], params: [], endpoints: [], buckets: [] };
        renderReconView();
      });
    });
  });

  // ── Subdomain Trust & APIs Implementation ────────────────────
  function renderSubdomainTrustAndApis(): void {
    // 1. Subdomain Trust Analysis
    while (subdomainVectorsList.firstChild) {
      subdomainVectorsList.removeChild(subdomainVectorsList.firstChild);
    }

    const trust = currentTabState?.subdomainTrust;
    if (trust) {
      const hasEscalation = trust.hasEscalationPath === true;
      subdomainEscalationPill.textContent = hasEscalation ? 'Escalation Detected' : 'No Escalation';
      subdomainEscalationPill.className = `status-pill ${hasEscalation ? 'pill-danger' : 'pill-safe'}`;

      if (trust.vectors.length > 0) {
        subdomainVectorsEmpty.hidden = true;
        for (const vec of trust.vectors) {
          const item = document.createElement('div');
          item.className = 'subdomain-vector-item';

          const topRow = document.createElement('div');
          topRow.className = 'vector-top-row';

          const titleSpan = document.createElement('span');
          titleSpan.className = 'vector-title';
          titleSpan.textContent = vec.label;
          topRow.appendChild(titleSpan);

          const riskBadge = document.createElement('span');
          riskBadge.className = `risk-badge risk-${vec.risk}`;
          riskBadge.textContent = vec.risk.toUpperCase();
          topRow.appendChild(riskBadge);

          const presentBadge = document.createElement('span');
          if (vec.present === true) {
            presentBadge.className = 'present-badge bridge-active';
            presentBadge.textContent = '✔ Bridge Active';
          } else if (vec.present === false) {
            presentBadge.className = 'present-badge bridge-blocked';
            presentBadge.textContent = '✘ Explicitly Blocked';
          } else {
            presentBadge.className = 'present-badge bridge-na';
            presentBadge.textContent = '— N/A';
          }
          topRow.appendChild(presentBadge);

          item.appendChild(topRow);

          if (vec.detail) {
            const detailDiv = document.createElement('div');
            detailDiv.className = 'vector-detail-text';
            detailDiv.textContent = vec.detail;
            item.appendChild(detailDiv);
          }

          subdomainVectorsList.appendChild(item);
        }
      } else {
        subdomainVectorsEmpty.hidden = false;
        subdomainVectorsList.appendChild(subdomainVectorsEmpty);
      }
    } else {
      subdomainEscalationPill.textContent = 'No Escalation';
      subdomainEscalationPill.className = 'status-pill pill-neutral';
      subdomainVectorsEmpty.hidden = false;
      subdomainVectorsList.appendChild(subdomainVectorsEmpty);
    }

    // 2. API Subresource Endpoints
    while (apiEndpointsList.firstChild) {
      apiEndpointsList.removeChild(apiEndpointsList.firstChild);
    }

    const apiMap = currentTabState?.apiEndpoints;
    let endpointEntries: ApiEndpointState[] = [];
    if (apiMap instanceof Map) {
      endpointEntries = Array.from(apiMap.values());
    } else if (typeof apiMap === 'object' && apiMap !== null) {
      endpointEntries = Object.values(apiMap);
    }

    apiEndpointsCount.textContent = endpointEntries.length.toString();

    if (endpointEntries.length === 0) {
      apiEndpointsEmpty.hidden = false;
      apiEndpointsList.appendChild(apiEndpointsEmpty);
    } else {
      apiEndpointsEmpty.hidden = true;
      for (const ep of endpointEntries) {
        const item = document.createElement('div');
        item.className = 'api-endpoint-item';

        const row = document.createElement('div');
        row.className = 'api-endpoint-row';

        const methodBadge = document.createElement('span');
        methodBadge.className = `api-method-badge method-${(ep.lastHop?.method ?? 'GET').toLowerCase()}`;
        methodBadge.textContent = ep.lastHop?.method ?? 'GET';
        row.appendChild(methodBadge);

        const pathSpan = document.createElement('span');
        pathSpan.className = 'api-path-text';
        pathSpan.textContent = ep.normalizedPath;
        pathSpan.title = ep.normalizedPath;
        row.appendChild(pathSpan);

        const partyBadge = document.createElement('span');
        partyBadge.className = `party-badge ${ep.isFirstParty ? 'party-first' : 'party-third'}`;
        partyBadge.textContent = ep.isFirstParty ? '1st-party' : '3rd-party';
        row.appendChild(partyBadge);

        if (ep.lastHop?.status !== undefined) {
          const statusSpan = document.createElement('span');
          statusSpan.className = 'api-status-code';
          statusSpan.textContent = ep.lastHop.status.toString();
          row.appendChild(statusSpan);
        }

        item.appendChild(row);

        if (ep.findings.length > 0) {
          const fCount = document.createElement('div');
          fCount.className = 'api-findings-note';
          fCount.textContent = `${ep.findings.length} finding(s) associated with this endpoint`;
          item.appendChild(fCount);
        }

        apiEndpointsList.appendChild(item);
      }
    }
  }

  // ── Activity Timeline & Ledger Implementation ────────────────
  function renderTimeline(): void {
    while (timelineStream.firstChild) {
      timelineStream.removeChild(timelineStream.firstChild);
    }

    if (currentLeads.length === 0) {
      timelineEmpty.hidden = false;
      timelineStream.hidden = true;
      timelineCountBadge.textContent = '0';
      return;
    }

    timelineEmpty.hidden = true;
    timelineStream.hidden = false;
    timelineCountBadge.textContent = currentLeads.length.toString();

    const chronological = [...currentLeads].sort((a, b) => b.timestamp - a.timestamp);

    for (const lead of chronological) {
      const eventEl = document.createElement('div');
      eventEl.className = 'timeline-event';

      const header = document.createElement('div');
      header.className = 'timeline-event-header';

      const time = document.createElement('span');
      time.className = 'timeline-event-time';
      time.textContent = new Date(lead.timestamp).toLocaleTimeString();
      header.appendChild(time);

      const sensor = document.createElement('span');
      sensor.className = 'timeline-event-sensor';
      sensor.textContent = lead.sourceSensor;
      header.appendChild(sensor);

      const potBadge = document.createElement('span');
      potBadge.className = `lead-tier-badge dot-${lead.potential}`;
      potBadge.textContent = lead.potential.toUpperCase();
      header.appendChild(potBadge);

      eventEl.appendChild(header);

      const title = document.createElement('div');
      title.className = 'timeline-event-title';
      title.textContent = `[${lead.ruleId}] ${lead.title}`;
      eventEl.appendChild(title);

      if (
        lead.evidence !== undefined &&
        typeof lead.evidence.preview === 'string' &&
        lead.evidence.preview.length > 0
      ) {
        const preview = document.createElement('div');
        preview.className = 'timeline-event-preview';
        preview.textContent = lead.evidence.preview;
        eventEl.appendChild(preview);
      }

      timelineStream.appendChild(eventEl);
    }
  }

  function renderCoverageLedger(): void {
    while (ledgerStream.firstChild) {
      ledgerStream.removeChild(ledgerStream.firstChild);
    }

    const ledger = currentTabState?.coverage?.ledger ?? [];
    ledgerCountBadge.textContent = ledger.length.toString();

    if (ledger.length === 0) {
      ledgerEmpty.hidden = false;
      ledgerStream.hidden = true;
      return;
    }

    ledgerEmpty.hidden = true;
    ledgerStream.hidden = false;

    const sorted = [...ledger].sort((a, b) => b.timestamp - a.timestamp);

    for (const entry of sorted) {
      const row = document.createElement('div');
      row.className = 'ledger-event-item';

      const header = document.createElement('div');
      header.className = 'ledger-event-header';

      const time = document.createElement('span');
      time.className = 'ledger-event-time';
      time.textContent = new Date(entry.timestamp).toLocaleTimeString();
      header.appendChild(time);

      const typeBadge = document.createElement('span');
      typeBadge.className = `ledger-badge type-${entry.type}`;
      typeBadge.textContent = entry.type;
      header.appendChild(typeBadge);

      const srcBadge = document.createElement('span');
      srcBadge.className = `ledger-badge source-${entry.source}`;
      srcBadge.textContent = entry.source;
      header.appendChild(srcBadge);

      if (entry.status !== undefined) {
        const statusSpan = document.createElement('span');
        statusSpan.className = 'ledger-status-code';
        statusSpan.textContent = `HTTP ${entry.status}`;
        header.appendChild(statusSpan);
      }

      row.appendChild(header);

      const urlDiv = document.createElement('div');
      urlDiv.className = 'ledger-event-url';
      urlDiv.textContent = entry.url;
      urlDiv.title = entry.url;
      row.appendChild(urlDiv);

      if (typeof entry.notes === 'string' && entry.notes.length > 0) {
        const noteDiv = document.createElement('div');
        noteDiv.className = 'ledger-event-notes';
        noteDiv.textContent = entry.notes;
        row.appendChild(noteDiv);
      }

      ledgerStream.appendChild(row);
    }
  }

  // ── Command Palette Implementation ───────────────────────────
  function openCommandPalette(): void {
    if (typeof cmdPaletteDialog.showModal === 'function') {
      cmdPaletteDialog.showModal();
    } else {
      cmdPaletteDialog.setAttribute('open', '');
    }
    cmdPaletteInput.value = '';
    renderPaletteResults('');
    cmdPaletteInput.focus();
  }

  function closeCommandPalette(): void {
    if (typeof cmdPaletteDialog.close === 'function') {
      cmdPaletteDialog.close();
    } else {
      cmdPaletteDialog.removeAttribute('open');
    }
  }

  paletteOpenBtn.addEventListener('click', openCommandPalette);
  cmdPaletteCloseBtn.addEventListener('click', closeCommandPalette);

  cmdPaletteDialog.addEventListener('click', (e) => {
    if (e.target === cmdPaletteDialog) {
      closeCommandPalette();
    }
  });

  function renderPaletteResults(filter: string): void {
    while (cmdPaletteResults.firstChild) {
      cmdPaletteResults.removeChild(cmdPaletteResults.firstChild);
    }

    const commands = [
      { title: 'Switch to Overview', action: () => switchTab('tab-overview'), shortcut: 'Overview' },
      { title: 'Switch to Findings (Leads)', action: () => switchTab('tab-findings'), shortcut: 'Findings' },
      {
        title: 'Switch to Attack Surface Graph',
        action: () => {
          switchTab('tab-surface');
          switchSurfaceSubtab('surface-subtab-graph');
        },
        shortcut: 'Graph',
      },
      {
        title: 'Switch to Attack Vector Chains',
        action: () => {
          switchTab('tab-surface');
          switchSurfaceSubtab('surface-subtab-chains');
        },
        shortcut: 'Chains',
      },
      {
        title: 'Switch to Reconnaissance Intelligence',
        action: () => {
          switchTab('tab-surface');
          switchSurfaceSubtab('surface-subtab-recon');
        },
        shortcut: 'Recon',
      },
      {
        title: 'Switch to Subdomain Trust & APIs',
        action: () => {
          switchTab('tab-surface');
          switchSurfaceSubtab('surface-subtab-subdomains');
        },
        shortcut: 'Trust',
      },
      {
        title: 'Switch to Discovery Timeline',
        action: () => {
          switchTab('tab-activity');
          switchActivitySubtab('activity-subtab-timeline');
        },
        shortcut: 'Timeline',
      },
      {
        title: 'Switch to Coverage Ledger',
        action: () => {
          switchTab('tab-activity');
          switchActivitySubtab('activity-subtab-ledger');
        },
        shortcut: 'Ledger',
      },
      { title: 'Export Leads Report (Markdown)', action: () => exportLeadsMdBtn.click(), shortcut: 'MD' },
      { title: 'Export Leads Report (JSON)', action: () => exportLeadsJsonBtn.click(), shortcut: 'JSON' },
      { title: 'Export Leads Report (SARIF)', action: () => exportLeadsSarifBtn.click(), shortcut: 'SARIF' },
      { title: 'Download Recon Wordlist (.txt)', action: () => downloadWordlistBtn.click(), shortcut: 'TXT' },
      { title: 'Reset Recon Memory', action: () => resetReconBtn.click(), shortcut: 'Clear' },
    ];

    const matched = commands.filter((c) => c.title.toLowerCase().includes(filter.toLowerCase()));

    for (let i = 0; i < matched.length; i++) {
      const cmd = matched[i];
      if (!cmd) continue;
      const li = document.createElement('li');
      li.className = `cmd-palette-item ${i === 0 ? 'selected' : ''}`;
      li.setAttribute('role', 'option');

      const titleSpan = document.createElement('span');
      titleSpan.textContent = cmd.title;
      li.appendChild(titleSpan);

      if (cmd.shortcut) {
        const scSpan = document.createElement('span');
        scSpan.className = 'cmd-item-shortcut';
        scSpan.textContent = cmd.shortcut;
        li.appendChild(scSpan);
      }

      li.addEventListener('click', () => {
        closeCommandPalette();
        cmd.action();
      });

      cmdPaletteResults.appendChild(li);
    }
  }

  cmdPaletteInput.addEventListener('input', () => {
    renderPaletteResults(cmdPaletteInput.value);
  });

  cmdPaletteInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const selected = cmdPaletteResults.querySelector<HTMLElement>('.cmd-palette-item.selected');
      if (selected !== null) {
        selected.click();
      }
    }
  });

  // ── Keyboard Shortcuts (Ctrl+K, j/k, p, v) ────────────────────
  function updateSelectedLeadCard(filtered: Lead[]): void {
    const cards = document.querySelectorAll<HTMLElement>('#sp-leads-list .lead-card');
    cards.forEach((c) => c.classList.remove('focused-card'));
    const targetLead = filtered[selectedLeadIndex];
    if (targetLead) {
      const el = document.getElementById(`sp-lead-card-${targetLead.id}`);
      if (el) {
        el.classList.add('focused-card');
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !viewSettings.hidden) {
      e.preventDefault();
      void handleCloseSettings();
      return;
    }

    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      openCommandPalette();
      return;
    }

    const activeEl = document.activeElement;
    if (
      activeEl &&
      (activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA' || activeEl.tagName === 'SELECT')
    ) {
      return;
    }

    if (cmdPaletteDialog.open) return;

    const currentTabEl = document.querySelector('.nav-tab.active');
    if (currentTabEl?.id !== 'tab-findings') return;

    const filtered = getFilteredLeads();
    if (filtered.length === 0) return;

    if (e.key === 'j') {
      e.preventDefault();
      selectedLeadIndex = Math.min(filtered.length - 1, selectedLeadIndex + 1);
      updateSelectedLeadCard(filtered);
    } else if (e.key === 'k') {
      e.preventDefault();
      selectedLeadIndex = Math.max(0, selectedLeadIndex - 1);
      updateSelectedLeadCard(filtered);
    } else if (e.key === 'p') {
      e.preventDefault();
      if (selectedLeadIndex >= 0 && selectedLeadIndex < filtered.length) {
        const lead = filtered[selectedLeadIndex];
        if (lead) {
          void togglePinLead(lead);
        }
      }
    } else if (e.key === 'v') {
      e.preventDefault();
      if (selectedLeadIndex >= 0 && selectedLeadIndex < filtered.length) {
        const lead = filtered[selectedLeadIndex];
        if (lead) {
          void cycleTriageLead(lead);
        }
      }
    }
  });
});
