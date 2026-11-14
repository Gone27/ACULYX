/**
 * sidepanel.ts — Attack Surface Graph & Lead Radar sidepanel controller.
 *
 * Rules:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - Plain SVG and pure DOM manipulation
 *  - d3-force simulation layout for Attack Surface Graph
 *  - Leads radar, lead cards, attack chains, recon memory, and timeline views
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
import type { GraphNode, GraphEdge, AttackSurfaceGraph, TabState, SettingsV2 } from '../shared/types';
import type { Lead, ChainRule, ReconMemory } from '../leads/types';
import { sendToBackground } from '../shared/messaging';
import type { LeadStateUpdateMessage } from '../shared/messaging';
import { SIDEPANEL_PORT_NAME, DEFAULT_SETTINGS } from '../shared/constants';
import { SettingsService } from '../shared/settings';
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
  const nodeIds = nodes.map(n => n.hostname).sort().join(',');
  const edgeIds = edges.map(e => `${e.source}>${e.target}`).sort().join(',');
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
  // Navigation tabs
  const tabGraph = getEl<HTMLButtonElement>('tab-graph');
  const tabRadar = getEl<HTMLButtonElement>('tab-radar');
  const tabLeads = getEl<HTMLButtonElement>('tab-leads');
  const tabChains = getEl<HTMLButtonElement>('tab-chains');
  const tabRecon = getEl<HTMLButtonElement>('tab-recon');
  const tabTimeline = getEl<HTMLButtonElement>('tab-timeline');

  const tabLeadsBadge = getEl<HTMLSpanElement>('tab-leads-badge');
  const tabChainsBadge = getEl<HTMLSpanElement>('tab-chains-badge');

  // Header controls
  const viewToggleBtn = getEl<HTMLButtonElement>('view-toggle-btn');
  const tierBadge = getEl<HTMLSpanElement>('tier-badge');
  const refreshBtn = getEl<HTMLButtonElement>('refresh-btn');
  const optionsLink = getEl<HTMLAnchorElement>('options-link');
  const paletteOpenBtn = getEl<HTMLButtonElement>('palette-open-btn');
  const evalBanner = getEl<HTMLDivElement>('eval-banner');

  // Graph summary elements
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

  // Radar elements
  const radarSeverityFilter = getEl<HTMLSelectElement>('radar-severity-filter');
  const spRadarRings = getSvgEl<SVGGElement>('sp-radar-rings');
  const spRadarAxes = getSvgEl<SVGGElement>('sp-radar-axes');
  const spRadarBlips = getSvgEl<SVGGElement>('sp-radar-blips');
  const statCountCritical = getEl<HTMLSpanElement>('stat-count-critical');
  const statCountHigh = getEl<HTMLSpanElement>('stat-count-high');
  const statCountMedium = getEl<HTMLSpanElement>('stat-count-medium');
  const statCountLow = getEl<HTMLSpanElement>('stat-count-low');
  const statCountInfo = getEl<HTMLSpanElement>('stat-count-info');

  // Leads elements
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

  // Timeline elements
  const timelineCountBadge = getEl<HTMLSpanElement>('timeline-count-badge');
  const timelineEmpty = getEl<HTMLDivElement>('timeline-empty');
  const timelineStream = getEl<HTMLDivElement>('timeline-stream');

  // Command palette elements
  const cmdPaletteDialog = getEl<HTMLDialogElement>('command-palette-dialog');
  const cmdPaletteCloseBtn = getEl<HTMLButtonElement>('cmd-palette-close-btn');
  const cmdPaletteInput = getEl<HTMLInputElement>('cmd-palette-input');
  const cmdPaletteResults = getEl<HTMLUListElement>('cmd-palette-results');

  // State
  let activeTabId: number | null = null;
  let activeApexDomain: string = '';
  let activeOrigin: string = '';
  let isListView = false;

  let currentLeads: Lead[] = [];
  let activeChains: Array<{ chain: ChainRule; matchedLeads: Lead[] }> = [];
  let currentRecon: ReconMemory = { hosts: [], params: [], endpoints: [], buckets: [] };
  let sidepanelRadarRendered = false;
  let selectedLeadIndex = -1;

  // ── Tab Switching ───────────────────────────────────────────
  function switchTab(tabId: string): void {
    const tabs = [
      { btn: tabGraph, view: getEl<HTMLDivElement>('view-graph') },
      { btn: tabRadar, view: getEl<HTMLDivElement>('view-radar') },
      { btn: tabLeads, view: getEl<HTMLDivElement>('view-leads') },
      { btn: tabChains, view: getEl<HTMLDivElement>('view-chains') },
      { btn: tabRecon, view: getEl<HTMLDivElement>('view-recon') },
      { btn: tabTimeline, view: getEl<HTMLDivElement>('view-timeline') },
    ];

    for (const t of tabs) {
      if (t.btn.id === tabId) {
        t.btn.classList.add('active');
        t.btn.setAttribute('aria-selected', 'true');
        t.view.hidden = false;
        t.view.classList.add('active');
      } else {
        t.btn.classList.remove('active');
        t.btn.setAttribute('aria-selected', 'false');
        t.view.hidden = true;
        t.view.classList.remove('active');
      }
    }

    if (tabId === 'tab-radar') {
      renderSidepanelRadar();
    } else if (tabId === 'tab-leads') {
      renderLeadsList();
    } else if (tabId === 'tab-chains') {
      renderChainsView();
    } else if (tabId === 'tab-recon') {
      void fetchAndRenderRecon();
    } else if (tabId === 'tab-timeline') {
      renderTimeline();
    }
  }

  tabGraph.addEventListener('click', () => switchTab('tab-graph'));
  tabRadar.addEventListener('click', () => switchTab('tab-radar'));
  tabLeads.addEventListener('click', () => switchTab('tab-leads'));
  tabChains.addEventListener('click', () => switchTab('tab-chains'));
  tabRecon.addEventListener('click', () => switchTab('tab-recon'));
  tabTimeline.addEventListener('click', () => switchTab('tab-timeline'));

  // ── View Toggle (Graph vs List for graph view) ───────────────
  viewToggleBtn.addEventListener('click', () => {
    isListView = !isListView;
    document.body.classList.toggle('view-graph', !isListView);
    document.body.classList.toggle('view-list', isListView);
    viewToggleBtn.textContent = isListView ? 'Graph view' : 'List view';
    viewToggleBtn.setAttribute('aria-pressed', isListView ? 'true' : 'false');
  });

  optionsLink.addEventListener('click', (e) => {
    e.preventDefault();
    if (chrome.runtime.openOptionsPage !== undefined) {
      void chrome.runtime.openOptionsPage();
    }
  });

  refreshBtn.addEventListener('click', () => {
    if (activeApexDomain.length > 0) {
      void fetchAndRenderGraph(activeApexDomain, activeTabId);
    }
    void fetchLeads();
    void fetchAndRenderRecon();
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
        renderLeadsList();
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
      renderLeadsList();
    })
    .catch(() => {
      // fallback to DEFAULT_SETTINGS
    });

  void bootstrapAppearance();

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
        }
        void fetchAndRenderGraph(cleanApex, activeTabId);
        void fetchLeads();
        void fetchAndRenderRecon();
        return;
      }

      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (
        tab !== undefined &&
        tab.id !== undefined &&
        tab.url !== undefined &&
        tab.url.length > 0 &&
        !tab.url.startsWith('chrome-extension://') &&
        !tab.url.startsWith('moz-extension://')
      ) {
        activeTabId = tab.id;
        port.postMessage({ type: 'REQUEST_STATE', tabId: tab.id });
        const origin = new URL(tab.url).origin;
        activeOrigin = origin;
        const hostname = new URL(origin).hostname;
        const apex = registrableDomain(hostname) ?? hostname;
        activeApexDomain = apex;
        void fetchAndRenderGraph(apex, tab.id);
        void fetchLeads();
        void fetchAndRenderRecon();
      } else {
        graphLoading.hidden = true;
        graphEmpty.textContent = 'No inspectable tab active. Open a website to view its attack surface graph.';
        graphEmpty.hidden = false;
      }
    } catch {
      graphLoading.hidden = true;
      graphEmpty.textContent = 'Unable to query active tab.';
      graphEmpty.hidden = false;
    }
  })();

  function handleTabState(state: TabState): void {
    try {
      activeTabId = state.tabId;
      activeOrigin = state.origin;
      const host = new URL(state.origin).hostname;
      const apex = registrableDomain(host) ?? host;
      if (apex !== activeApexDomain) {
        activeApexDomain = apex;
        void fetchAndRenderGraph(apex, state.tabId);
        void fetchLeads();
        void fetchAndRenderRecon();
      }
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
    } else {
      tabLeadsBadge.hidden = true;
    }

    if (activeChains.length > 0) {
      tabChainsBadge.textContent = activeChains.length.toString();
      tabChainsBadge.hidden = false;
    } else {
      tabChainsBadge.hidden = true;
    }

    // Update active view
    const activeTabEl = document.querySelector('.nav-tab.active');
    if (activeTabEl?.id === 'tab-radar') {
      renderSidepanelRadar();
    } else if (activeTabEl?.id === 'tab-leads') {
      renderLeadsList();
    } else if (activeTabEl?.id === 'tab-chains') {
      renderChainsView();
    } else if (activeTabEl?.id === 'tab-timeline') {
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
    nodeGrade.textContent = node.grade !== undefined && node.score !== undefined
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
      tdGrade.textContent = node.grade !== undefined && node.score !== undefined
        ? `${node.grade} (${node.score})`
        : '—';

      const tdSeen = document.createElement('td');
      tdSeen.textContent = new Date(node.lastSeen).toLocaleTimeString();

      tr.appendChild(tdHost);
      tr.appendChild(tdRole);
      tr.appendChild(tdGrade);
      tr.appendChild(tdSeen);

      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          showNodeDetails(node);
          tbody.querySelectorAll('tr').forEach(r => r.setAttribute('aria-selected', 'false'));
          tr.setAttribute('aria-selected', 'true');
        }
      });
      tr.addEventListener('click', () => {
        showNodeDetails(node);
        tbody.querySelectorAll('tr').forEach(r => r.setAttribute('aria-selected', 'false'));
        tr.setAttribute('aria-selected', 'true');
      });

      tbody.appendChild(tr);
    }
  }

  // ── Radar View Implementation ────────────────────────────────
  function renderSidepanelRadar(): void {
    if (!sidepanelRadarRendered) {
      sidepanelRadarRendered = true;
      while (spRadarRings.firstChild) spRadarRings.removeChild(spRadarRings.firstChild);
      while (spRadarAxes.firstChild) spRadarAxes.removeChild(spRadarAxes.firstChild);

      const rings = [25, 50, 75, 100];
      for (const r of rings) {
        const circle = document.createElementNS(SVG_NS, 'circle');
        circle.setAttribute('cx', '0');
        circle.setAttribute('cy', '0');
        circle.setAttribute('r', String(r));
        circle.setAttribute('stroke', r === 100 ? 'rgba(138, 43, 226, 0.45)' : 'rgba(138, 43, 226, 0.2)');
        circle.setAttribute('stroke-width', '1');
        circle.setAttribute('fill', 'none');
        spRadarRings.appendChild(circle);
      }

      for (let i = 0; i < FAMILIES.length; i++) {
        const angle = (i * 2 * Math.PI) / FAMILIES.length - Math.PI / 2;
        const x2 = Math.round(105 * Math.cos(angle));
        const y2 = Math.round(105 * Math.sin(angle));

        const line = document.createElementNS(SVG_NS, 'line');
        line.setAttribute('x1', '0');
        line.setAttribute('y1', '0');
        line.setAttribute('x2', String(x2));
        line.setAttribute('y2', String(y2));
        line.setAttribute('stroke', 'rgba(138, 43, 226, 0.25)');
        line.setAttribute('stroke-width', '1');
        spRadarAxes.appendChild(line);

        const lx = Math.round(114 * Math.cos(angle));
        const ly = Math.round(114 * Math.sin(angle) + 3);
        const text = document.createElementNS(SVG_NS, 'text');
        text.setAttribute('x', String(lx));
        text.setAttribute('y', String(ly));
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('font-size', '8');
        text.setAttribute('font-weight', '600');
        text.setAttribute('fill', '#a78bfa');
        text.textContent = FAMILIES[i]?.id ?? '';
        spRadarAxes.appendChild(text);
      }
    }

    // Stats
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const lead of currentLeads) {
      if (lead.potential === 'critical') stats.critical++;
      else if (lead.potential === 'high') stats.high++;
      else if (lead.potential === 'medium') stats.medium++;
      else if (lead.potential === 'low') stats.low++;
      else if (lead.potential === 'info') stats.info++;
    }

    statCountCritical.textContent = stats.critical.toString();
    statCountHigh.textContent = stats.high.toString();
    statCountMedium.textContent = stats.medium.toString();
    statCountLow.textContent = stats.low.toString();
    statCountInfo.textContent = stats.info.toString();

    // Blips
    while (spRadarBlips.firstChild) {
      spRadarBlips.removeChild(spRadarBlips.firstChild);
    }

    const sevFilter = radarSeverityFilter.value;
    const leadsToRender = sevFilter === 'all'
      ? currentLeads
      : currentLeads.filter(l => l.potential === sevFilter);

    const potentialRadii: Record<Lead['potential'], number> = {
      critical: 28,
      high: 48,
      medium: 68,
      low: 84,
      info: 96,
    };

    for (const lead of leadsToRender) {
      const famIndex = Math.max(0, FAMILIES.findIndex((f) => f.id === lead.family));
      const baseAngle = (famIndex * 2 * Math.PI) / FAMILIES.length - Math.PI / 2;
      const baseRadius = potentialRadii[lead.potential] ?? 70;

      let hash = 0;
      for (let c = 0; c < lead.id.length; c++) {
        hash = ((hash << 5) - hash + lead.id.charCodeAt(c)) | 0;
      }
      const angleOffset = (((Math.abs(hash) % 13) - 6) * Math.PI) / 60;
      const radiusOffset = ((Math.abs(hash >> 3) % 9) - 4) * 2;

      const angle = baseAngle + angleOffset;
      const radius = Math.max(16, Math.min(102, baseRadius + radiusOffset));

      const cx = Math.round(radius * Math.cos(angle));
      const cy = Math.round(radius * Math.sin(angle));

      const circle = document.createElementNS(SVG_NS, 'circle');
      circle.setAttribute('cx', String(cx));
      circle.setAttribute('cy', String(cy));
      circle.setAttribute('r', '4');
      circle.setAttribute('class', `radar-blip radar-blip-${lead.potential}`);

      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = `[${lead.potential.toUpperCase()}] ${lead.title} (${lead.ruleId})`;
      circle.appendChild(title);

      circle.addEventListener('click', () => {
        switchTab('tab-leads');
        focusLeadCardInSidepanel(lead.id);
      });

      spRadarBlips.appendChild(circle);
    }
  }

  radarSeverityFilter.addEventListener('change', () => {
    renderSidepanelRadar();
  });

  // ── Leads List View Implementation ───────────────────────────
  function getFilteredLeads(): Lead[] {
    const query = (leadsSearchInput.value || '').trim().toLowerCase();
    const fam = leadsFilterFamily.value;
    const tier = leadsFilterTier.value;
    const scope = leadsFilterScope.value;
    const newOnly = leadsFilterNewOnly.checked;
    const chainOnly = leadsFilterChainOnly.checked;

    return currentLeads.filter((lead) => {
      if (fam !== 'all' && lead.family !== fam) return false;
      if (tier !== 'all' && lead.tier !== tier) return false;
      if (scope !== 'all' && lead.scopeStatus !== scope) return false;
      if (newOnly && lead.novelty === false) return false;
      if (chainOnly && (lead.chainIds === undefined || lead.chainIds.length === 0)) return false;
      if (typeof query === 'string' && query.length > 0) {
        const matchTitle = lead.title.toLowerCase().includes(query);
        const matchRule = lead.ruleId.toLowerCase().includes(query);
        const matchTags = lead.tags.some((t) => t.toLowerCase().includes(query));
        const prevText = (lead.evidence !== undefined && typeof lead.evidence.preview === 'string') ? lead.evidence.preview : '';
        const matchEvidence = prevText.toLowerCase().includes(query);
        if (!matchTitle && !matchRule && !matchTags && !matchEvidence) return false;
      }
      return true;
    });
  }

  const VERDICT_LABELS: Record<NonNullable<Lead['verdict']>['status'], string> = {
    confirmed: '✔ Confirmed bug',
    likely: 'Likely bug',
    uncertain: '? Uncertain',
    informational: 'Info only',
    false_positive: '✘ False positive',
  };

  function renderLeadsList(): void {
    const filtered = getFilteredLeads();

    while (spLeadsList.firstChild) {
      spLeadsList.removeChild(spLeadsList.firstChild);
    }

    if (filtered.length === 0) {
      spLeadsEmpty.hidden = false;
      spLeadsList.hidden = true;
      return;
    }

    spLeadsEmpty.hidden = true;
    spLeadsList.hidden = false;

    const sorted = [...filtered].sort((a, b) => {
      const aPinned = a.pinned === true;
      const bPinned = b.pinned === true;
      if (aPinned && !bPinned) return -1;
      if (!aPinned && bPinned) return 1;
      return (b.priority ?? 0) - (a.priority ?? 0);
    });

    for (let i = 0; i < sorted.length; i++) {
      const lead = sorted[i];
      if (lead) {
        spLeadsList.appendChild(createSidepanelLeadCard(lead, i));
      }
    }
  }

  function createSidepanelLeadCard(lead: Lead, index: number): HTMLDivElement {
    const card = document.createElement('div');
    card.className = 'lead-card';
    card.id = `sp-lead-card-${lead.id}`;
    card.setAttribute('tabindex', '0');
    if (lead.pinned === true) {
      card.classList.add('card-pinned');
    }
    if (index === selectedLeadIndex) {
      card.classList.add('focused-card');
    }

    const header = document.createElement('div');
    header.className = 'lead-card-header';

    const metaLeft = document.createElement('div');
    metaLeft.className = 'lead-card-meta-left';

    const famIcon = document.createElement('span');
    famIcon.className = 'lead-family-icon';
    famIcon.textContent = lead.family;
    famIcon.title = `Family ${lead.family}`;
    metaLeft.appendChild(famIcon);

    const tierBadge = document.createElement('span');
    tierBadge.className = `lead-tier-badge tier-${lead.tier}`;
    tierBadge.textContent = lead.tier;
    metaLeft.appendChild(tierBadge);

    const scopeBadge = document.createElement('span');
    scopeBadge.className = `lead-scope-chip scope-${lead.scopeStatus}`;
    scopeBadge.textContent = lead.scopeStatus === 'in-scope' ? 'In-Scope' : lead.scopeStatus === 'out-of-scope' ? 'Out-of-Scope' : 'Unknown Scope';
    metaLeft.appendChild(scopeBadge);

    header.appendChild(metaLeft);

    if (lead.verdict !== undefined) {
      const verdictBadge = document.createElement('span');
      verdictBadge.className = `lead-verdict-badge verdict-${lead.verdict.status}`;
      verdictBadge.textContent = VERDICT_LABELS[lead.verdict.status];
      verdictBadge.title = lead.verdict.summary;
      metaLeft.appendChild(verdictBadge);
    }

    const potentialBadge = document.createElement('span');
    potentialBadge.className = `lead-tier-badge dot-${lead.potential}`;
    potentialBadge.textContent = lead.potential.toUpperCase();
    header.appendChild(potentialBadge);

    card.appendChild(header);

    const title = document.createElement('div');
    title.className = 'lead-card-title';
    title.textContent = lead.title;
    card.appendChild(title);

    if (lead.evidence !== undefined && typeof lead.evidence.preview === 'string' && lead.evidence.preview.length > 0) {
      const pre = document.createElement('pre');
      pre.className = 'lead-evidence-pre';
      pre.textContent = lead.evidence.preview;
      card.appendChild(pre);
    }

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
      detailsSpan.textContent = ` — ${lead.credentialCheck.details} (${new Date(lead.credentialCheck.checkedAt).toLocaleTimeString()})`;
      credLine.appendChild(detailsSpan);

      const disclaimerDiv = document.createElement('div');
      disclaimerDiv.className = 'cred-disclaimer-text';
      disclaimerDiv.textContent = 'Notice: This reports only what the provider accepted at the time of the check. It does not establish the credential\'s full permissions, exploitability, or authorization to use it.';
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
      checkBtn.title = 'Send a 1-request authenticated check to the provider (GitHub, Stripe, Slack). Never runs automatically.';
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
      verifyBtn.title = 'Send safe read-only requests (no cookies) to test this lead. Requires in-scope target and Hunter enabled.';
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
    const triageText = typeof lead.triageState === 'string' && lead.triageState.length > 0 ? lead.triageState : 'Triage';
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
        setTimeout(() => { reportBtn.textContent = orig; }, 1500);
      });
    });
    actions.appendChild(reportBtn);

    // Copy cURL (Strictly in-scope GET requests without cookies)
    const curlBtn = document.createElement('button');
    curlBtn.className = 'lead-btn';
    curlBtn.textContent = '💻 Copy cURL';
    const isInScope = lead.scopeStatus === 'in-scope';
    const isSafeUrl = typeof lead.url === 'string' && (lead.url.startsWith('http://') || lead.url.startsWith('https://'));
    if (isInScope && isSafeUrl) {
      curlBtn.title = 'Copy safe in-scope GET cURL command without cookies';
      curlBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const curlCmd = `curl -s -i "${lead.url}"`;
        void navigator.clipboard.writeText(curlCmd).then(() => {
          const orig = curlBtn.textContent;
          curlBtn.textContent = '✔ Copied!';
          setTimeout(() => { curlBtn.textContent = orig; }, 1500);
        });
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
      document.querySelectorAll('#sp-leads-list .lead-card').forEach(c => c.classList.remove('focused-card'));
      card.classList.add('focused-card');
    });

    return card;
  }

  async function verifyLeadActively(lead: Lead, btn: HTMLButtonElement): Promise<void> {
    const plan = planActiveProbe(lead);
    if (!plan) return;
    const originsNotice = plan.testOrigins && plan.testOrigins.length > 0
      ? `\nTest Origins (${plan.testOrigins.length}):\n${plan.testOrigins.map((o) => `  • ${o}`).join('\n')}\n`
      : '';
    const ok = window.confirm(
      `Verify this lead actively?\n\n` +
      `${plan.description}\n\n` +
      `Target URL: ${plan.targetUrl}\n` +
      `Method: ${plan.method} (credentials: ${plan.credentials}, redirect: ${plan.redirect})\n` +
      `Requests: up to ${plan.maxRequests}\n` +
      originsNotice +
      `\nRequires target to be in declared scope and Hunter mode enabled. Proceed?`
    );
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
      })) as import('../shared/messaging').PlanCredentialCheckResponse | undefined;

      if (!planRes || !planRes.success || !planRes.plan) {
        alert(`Cannot check credential: ${planRes?.error ?? 'No plan available'}`);
        return;
      }

      const plan = planRes.plan;

      const stripeWarning =
        plan.provider === 'stripe'
          ? '\n\nIMPORTANT (STRIPE): This check queries the Stripe balance endpoint. ACULYX discards all financial balance amounts and the full response body immediately, retaining only the validity status and live/test mode.'
          : '';

      // Step 2: Show two-step confirmation with exact request parameters and safety warnings
      const promptText =
        `Perform authenticated credential liveness check?\n\n` +
        `Provider: ${plan.provider.toUpperCase()}\n` +
        `Endpoint: ${plan.method} ${plan.endpointUrl}\n` +
        `Target Secret: ${plan.maskedIdentity}\n` +
        `Token Family: ${plan.tokenFamily}\n` +
        `Requests: 1 request (credentials: omit, redirects: manual, 5s timeout)\n\n` +
        `WARNING: An authenticated request will be sent to ${plan.endpointUrl}. ACULYX discards all account IDs, response text, and raw secrets, persisting only the normalized provider status.${stripeWarning}\n\n` +
        `Do you affirm that you are authorized to check this credential under applicable program rules and wish to proceed?`;

      const affirmed = window.confirm(promptText);
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
      })) as import('../shared/messaging').ConfirmCredentialCheckResponse | undefined;

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
    const currentIdx = states.indexOf((lead.triageState ?? 'open'));
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
    }
  }

  function updateSelectedLeadCard(filtered: Lead[]): void {
    if (selectedLeadIndex < 0 || selectedLeadIndex >= filtered.length) return;
    const lead = filtered[selectedLeadIndex];
    if (lead) {
      focusLeadCardInSidepanel(lead.id);
    }
  }

  leadsSearchInput.addEventListener('input', () => renderLeadsList());
  leadsFilterFamily.addEventListener('change', () => renderLeadsList());
  leadsFilterTier.addEventListener('change', () => renderLeadsList());
  leadsFilterScope.addEventListener('change', () => renderLeadsList());
  leadsFilterNewOnly.addEventListener('change', () => renderLeadsList());
  leadsFilterChainOnly.addEventListener('change', () => renderLeadsList());

  exportLeadsMdBtn.addEventListener('click', () => {
    const filtered = getFilteredLeads();
    const md = formatLeadsReportMarkdown(filtered);
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aculyx-leads-${activeApexDomain || 'export'}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  exportLeadsJsonBtn.addEventListener('click', () => {
    const filtered = getFilteredLeads();
    const json = formatLeadsReportJson(filtered);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aculyx-leads-${activeApexDomain || 'export'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  exportLeadsSarifBtn.addEventListener('click', () => {
    const filtered = getFilteredLeads();
    const sarif = formatLeadsReportSarif(filtered);
    const blob = new Blob([sarif], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aculyx-leads-${activeApexDomain || 'export'}.sarif`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // ── Chains View Implementation ───────────────────────────────
  function renderChainsView(): void {
    while (chainsListContainer.firstChild) {
      chainsListContainer.removeChild(chainsListContainer.firstChild);
    }

    let activeCount = 0;

    for (const chain of CHAINS) {
      const matched = activeChains.find((c) => c.chain.id === chain.id);
      const isActive = matched !== undefined && matched.matchedLeads.length > 0;
      if (isActive) activeCount++;

      const card = document.createElement('div');
      card.className = `chain-card ${isActive ? 'chain-active' : ''}`;

      const header = document.createElement('div');
      header.className = 'chain-header';

      const idGroup = document.createElement('div');
      idGroup.className = 'chain-id-group';

      const idBadge = document.createElement('span');
      idBadge.className = 'chain-id-badge';
      idBadge.textContent = chain.id;
      idGroup.appendChild(idBadge);

      const statusPill = document.createElement('span');
      statusPill.className = `chain-status-pill ${isActive ? 'chain-status-active' : 'chain-status-dormant'}`;
      statusPill.textContent = isActive ? 'Active Chain' : 'Dormant Template';
      idGroup.appendChild(statusPill);

      header.appendChild(idGroup);

      const potBadge = document.createElement('span');
      potBadge.className = `lead-tier-badge dot-${chain.potential}`;
      potBadge.textContent = chain.potential.toUpperCase();
      header.appendChild(potBadge);

      card.appendChild(header);

      const needsTitle = document.createElement('div');
      needsTitle.className = 'chain-step-title';
      needsTitle.textContent = 'Required Chain Nodes:';
      card.appendChild(needsTitle);

      const needsList = document.createElement('div');
      needsList.className = 'chain-needs-list';

      for (const need of chain.needs) {
        const needItem = document.createElement('span');
        const isMatched = isActive && matched?.matchedLeads.some((l) => l.tags.includes(need) || l.ruleId === need);
        needItem.className = `chain-need-item ${isMatched ? 'matched' : ''}`;
        needItem.textContent = `${isMatched ? '✔ ' : '○ '}${need}`;
        needsList.appendChild(needItem);
      }
      card.appendChild(needsList);

      if (isActive && matched !== undefined && matched.matchedLeads.length > 0) {
        const matchedTitle = document.createElement('div');
        matchedTitle.className = 'chain-step-title';
        matchedTitle.textContent = `Correlated Leads (${matched.matchedLeads.length}):`;
        card.appendChild(matchedTitle);

        const matchedList = document.createElement('div');
        matchedList.className = 'chain-needs-list';
        for (const lead of matched.matchedLeads) {
          const leadPill = document.createElement('span');
          leadPill.className = 'chain-need-item matched';
          leadPill.textContent = `${lead.ruleId}: ${lead.title}`;
          leadPill.style.cursor = 'pointer';
          leadPill.addEventListener('click', () => {
            switchTab('tab-leads');
            focusLeadCardInSidepanel(lead.id);
          });
          matchedList.appendChild(leadPill);
        }
        card.appendChild(matchedList);
      }

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

    chainsActiveBadge.textContent = `${activeCount} Active`;
  }

  // ── Recon View Implementation ────────────────────────────────
  async function fetchAndRenderRecon(): Promise<void> {
    try {
      const res = await sendToBackground({
        type: 'RECON_GET',
        origin: typeof activeOrigin === 'string' && activeOrigin.length > 0 ? activeOrigin : undefined,
      });
      if (typeof res === 'object' && res !== null && res.type === 'RECON_GET_RESPONSE') {
        currentRecon = (res).memory;
        renderReconView();
      }
    } catch {
      // Background SW warming up
    }
  }

  function renderReconView(): void {
    reconHostsCount.textContent = (currentRecon.hosts.length).toString();
    reconEndpointsCount.textContent = (currentRecon.endpoints.length).toString();
    reconParamsCount.textContent = (currentRecon.params.length).toString();
    reconBucketsCount.textContent = (currentRecon.buckets.length).toString();

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

  for (const st of reconSubtabs) {
    st.btn.addEventListener('click', () => {
      for (const item of reconSubtabs) {
        if (item.btn === st.btn) {
          item.btn.classList.add('active');
          item.sec.hidden = false;
        } else {
          item.btn.classList.remove('active');
          item.sec.hidden = true;
        }
      }
    });
  }

  downloadWordlistBtn.addEventListener('click', () => {
    const paramNames = currentRecon.params.map((p) => p.name);
    const endpointPaths = currentRecon.endpoints.map((e) => e.path);
    const wordlist = generateNameOnlyWordlist(paramNames, endpointPaths);
    const blob = new Blob([wordlist], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aculyx-wordlist-${typeof activeApexDomain === 'string' && activeApexDomain.length > 0 ? activeApexDomain : 'recon'}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  resetReconBtn.addEventListener('click', () => {
    if (!confirm('Are you sure you want to reset all discovered recon memory?')) return;
    void sendToBackground({ type: 'RECON_RESET' }).then(() => {
      currentRecon = { hosts: [], params: [], endpoints: [], buckets: [] };
      renderReconView();
    });
  });

  // ── Timeline View Implementation ─────────────────────────────
  function renderTimeline(): void {
    while (timelineStream.firstChild) {
      timelineStream.removeChild(timelineStream.firstChild);
    }

    if (currentLeads.length === 0) {
      timelineEmpty.hidden = false;
      timelineStream.hidden = true;
      timelineCountBadge.textContent = '0 events';
      return;
    }

    timelineEmpty.hidden = true;
    timelineStream.hidden = false;
    timelineCountBadge.textContent = `${currentLeads.length} event${currentLeads.length === 1 ? '' : 's'}`;

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

      if (lead.evidence !== undefined && typeof lead.evidence.preview === 'string' && lead.evidence.preview.length > 0) {
        const preview = document.createElement('div');
        preview.className = 'timeline-event-preview';
        preview.textContent = lead.evidence.preview;
        eventEl.appendChild(preview);
      }

      timelineStream.appendChild(eventEl);
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
      { title: 'Switch to Attack Surface Graph', action: () => switchTab('tab-graph'), shortcut: 'Graph' },
      { title: 'Switch to Vulnerability Radar', action: () => switchTab('tab-radar'), shortcut: 'Radar' },
      { title: 'Switch to Leads List', action: () => switchTab('tab-leads'), shortcut: 'Leads' },
      { title: 'Switch to Attack Chains', action: () => switchTab('tab-chains'), shortcut: 'Chains' },
      { title: 'Switch to Reconnaissance', action: () => switchTab('tab-recon'), shortcut: 'Recon' },
      { title: 'Switch to Discovery Timeline', action: () => switchTab('tab-timeline'), shortcut: 'Timeline' },
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
  document.addEventListener('keydown', (e) => {
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
    if (currentTabEl?.id !== 'tab-leads') return;

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
