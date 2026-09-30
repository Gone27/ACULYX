/**
 * sidepanel.ts — Attack Surface Graph visualization using d3-force and SVG DOM.
 *
 * Rules:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - Plain SVG and DOM manipulation
 *  - d3-force simulation layout
 */

import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from 'd3-force';
import type { GraphNode, GraphEdge, AttackSurfaceGraph, TabState } from '../shared/types';
import { sendToBackground } from '../shared/messaging';
import { SIDEPANEL_PORT_NAME } from '../shared/constants';
import { registrableDomain } from '../rules/headers/subdomain-trust';

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

document.addEventListener('DOMContentLoaded', () => {
  const tierBadge = getEl<HTMLSpanElement>('tier-badge');
  const refreshBtn = getEl<HTMLButtonElement>('refresh-btn');
  const optionsLink = getEl<HTMLAnchorElement>('options-link');
  const proBanner = getEl<HTMLDivElement>('pro-banner');

  const apexDomainVal = getEl<HTMLSpanElement>('apex-domain-val');
  const nodesCountVal = getEl<HTMLSpanElement>('nodes-count-val');
  const edgesCountVal = getEl<HTMLSpanElement>('edges-count-val');

  const graphLoading = getEl<HTMLDivElement>('graph-loading');
  const graphEmpty = getEl<HTMLDivElement>('graph-empty');
  const edgesGroup = getSvgEl<SVGGElement>('edges-group');
  const nodesGroup = getSvgEl<SVGGElement>('nodes-group');

  const nodeDetails = getEl<HTMLElement>('node-details');
  const nodeHostname = getEl<HTMLHeadingElement>('node-hostname');
  const closeDetailsBtn = getEl<HTMLButtonElement>('close-details-btn');
  const nodeRole = getEl<HTMLSpanElement>('node-role');
  const nodeDiscoveredVia = getEl<HTMLSpanElement>('node-discovered-via');
  const nodeGrade = getEl<HTMLSpanElement>('node-grade');
  const nodeLastSeen = getEl<HTMLSpanElement>('node-last-seen');

  let activeTabId: number | null = null;
  let activeApexDomain: string = '';

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
  });

  closeDetailsBtn.addEventListener('click', () => {
    nodeDetails.hidden = true;
  });

  // Connect port for live updates
  const port = chrome.runtime.connect({ name: SIDEPANEL_PORT_NAME });
  port.onMessage.addListener((msg: unknown) => {
    const message = msg as { type?: string; state?: TabState };
    if (message.type === 'TAB_STATE_UPDATE' && message.state !== undefined) {
      handleTabState(message.state);
    }
  });

  // Query active tab initially or check URL params (e.g. when opened as a full tab in Firefox)
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
        const hostname = new URL(origin).hostname;
        const apex = registrableDomain(hostname) ?? hostname;
        activeApexDomain = apex;
        void fetchAndRenderGraph(apex, tab.id);
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
      const host = new URL(state.origin).hostname;
      const apex = registrableDomain(host) ?? host;
      if (apex !== activeApexDomain) {
        activeApexDomain = apex;
        void fetchAndRenderGraph(apex, state.tabId);
      }
    } catch {
      // Ignore URL parsing errors on special tabs
    }
  }

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

    // Update Pro/Free badges
    if (graph.isPro) {
      tierBadge.textContent = 'PRO';
      tierBadge.className = 'tier-badge pro';
      proBanner.hidden = true;
    } else {
      tierBadge.textContent = 'Free Tier';
      tierBadge.className = 'tier-badge free';
      proBanner.hidden = false;
    }

    nodesCountVal.textContent = graph.nodes.length.toString();
    edgesCountVal.textContent = graph.edges.length.toString();

    // Clear previous SVG contents
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

    // SVG Line Elements
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

    // SVG Node Elements
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

    // Run d3-force layout simulation
    const simulation = forceSimulation<SimNode>(simNodes)
      .force('link', forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(85))
      .force('charge', forceManyBody().strength(-220))
      .force('center', forceCenter(centerX, centerY))
      .force('collide', forceCollide().radius(26));

    simulation.on('tick', () => {
      // Update links
      for (let i = 0; i < simLinks.length; i++) {
        const link = simLinks[i];
        const line = lineElements[i];
        if (link !== undefined && line !== undefined) {
          const s = link.source as SimNode;
          const t = link.target as SimNode;
          line.setAttribute('x1', clamp(s.x ?? centerX, 15, WIDTH - 15).toString());
          line.setAttribute('y1', clamp(s.y ?? centerY, 15, HEIGHT - 15).toString());
          line.setAttribute('x2', clamp(t.x ?? centerX, 15, WIDTH - 15).toString());
          line.setAttribute('y2', clamp(t.y ?? centerY, 15, HEIGHT - 15).toString());
        }
      }

      // Update nodes
      for (let i = 0; i < simNodes.length; i++) {
        const node = simNodes[i];
        const g = nodeGroups[i];
        if (node !== undefined && g !== undefined) {
          const cx = clamp(node.x ?? centerX, 20, WIDTH - 20);
          const cy = clamp(node.y ?? centerY, 20, HEIGHT - 20);
          g.setAttribute('transform', `translate(${cx}, ${cy})`);
        }
      }
    });

    // Auto-select apex node initially
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
    nodeLastSeen.textContent = new Date(node.lastSeen).toLocaleTimeString();
    nodeDetails.hidden = false;
  }

  function clamp(val: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, val));
  }
});
