/**
 * panel.ts - Sensor 4 (S4) DevTools Network Body Analyzer
 *
 * Listens to chrome.devtools.network.onRequestFinished.
 * Analyzes response content in-memory using detector F7 (stack traces, JSON excessive
 * data exposure, banners, GraphQL errors).
 *
 * CRITICAL INVARIANT:
 * Raw response bodies are NEVER stored, cached, or persisted to disk or storage.
 * Only extracted Lead objects with strictly Masked evidence are forwarded and rendered.
 * Pure DOM construction only (zero innerHTML/outerHTML).
 */

import { detectBodyLeads } from '../leads/detectors/f7-body';
import { detectSecrets } from '../leads/detectors/f1-secrets';
import { detectEndpoints } from '../leads/detectors/f2-endpoints';
import { maskLocation } from '../leads/sieve/mask';
import type { Lead } from '../leads/types';

const collectedLeads: Lead[] = [];

// DOM Element references
const tbody = document.getElementById('leads-tbody') as HTMLTableSectionElement;
const btnClear = document.getElementById('btn-clear') as HTMLButtonElement;
const statTotal = document.getElementById('stat-total-count') as HTMLSpanElement;
const statCritical = document.getElementById('stat-critical-count') as HTMLSpanElement;
const statHigh = document.getElementById('stat-high-count') as HTMLSpanElement;
const statMedium = document.getElementById('stat-medium-count') as HTMLSpanElement;
const statLow = document.getElementById('stat-low-count') as HTMLSpanElement;
const statInfo = document.getElementById('stat-info-count') as HTMLSpanElement;

function updateStats(): void {
  let crit = 0;
  let high = 0;
  let med = 0;
  let low = 0;
  let info = 0;

  for (const lead of collectedLeads) {
    switch (lead.potential) {
      case 'critical': crit++; break;
      case 'high': high++; break;
      case 'medium': med++; break;
      case 'low': low++; break;
      case 'info': info++; break;
    }
  }

  if (statTotal) statTotal.textContent = String(collectedLeads.length);
  if (statCritical) statCritical.textContent = String(crit);
  if (statHigh) statHigh.textContent = String(high);
  if (statMedium) statMedium.textContent = String(med);
  if (statLow) statLow.textContent = String(low);
  if (statInfo) statInfo.textContent = String(info);
}

function renderLeadRow(lead: Lead): void {
  const emptyRow = document.getElementById('empty-row');
  if (emptyRow && emptyRow.parentNode === tbody) {
    tbody.removeChild(emptyRow);
  }

  const tr = document.createElement('tr');

  // Potential badge cell
  const tdPotential = document.createElement('td');
  const badge = document.createElement('span');
  badge.className = `potential-badge potential-${lead.potential}`;
  badge.textContent = lead.potential;
  tdPotential.appendChild(badge);
  tr.appendChild(tdPotential);

  // Family cell
  const tdFamily = document.createElement('td');
  tdFamily.textContent = lead.family;
  tr.appendChild(tdFamily);

  // Rule ID cell
  const tdRule = document.createElement('td');
  const ruleChip = document.createElement('span');
  ruleChip.className = 'rule-chip';
  ruleChip.textContent = lead.ruleId;
  tdRule.appendChild(ruleChip);
  tr.appendChild(tdRule);

  // Title cell
  const tdTitle = document.createElement('td');
  tdTitle.textContent = lead.title;
  tr.appendChild(tdTitle);

  // Location cell
  const tdLoc = document.createElement('td');
  tdLoc.className = 'location-cell';
  tdLoc.textContent = lead.evidence.location;
  tr.appendChild(tdLoc);

  // Masked Evidence cell
  const tdEvidence = document.createElement('td');
  const evBox = document.createElement('div');
  evBox.className = 'evidence-cell';
  evBox.textContent = lead.evidence.preview;
  tdEvidence.appendChild(evBox);
  tr.appendChild(tdEvidence);

  // Time cell
  const tdTime = document.createElement('td');
  tdTime.className = 'time-cell';
  const d = new Date(lead.timestamp);
  tdTime.textContent = d.toTimeString().split(' ')[0] ?? '';
  tr.appendChild(tdTime);

  // Prepend to show newest first
  if (tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }
}

if (btnClear) {
  btnClear.addEventListener('click', () => {
    collectedLeads.length = 0;
    while (tbody.firstChild) {
      tbody.removeChild(tbody.firstChild);
    }
    const emptyRow = document.createElement('tr');
    emptyRow.id = 'empty-row';
    emptyRow.className = 'empty-row';
    const td = document.createElement('td');
    td.colSpan = 7;
    td.textContent = 'Listening for network responses... No body leads detected yet.';
    emptyRow.appendChild(td);
    tbody.appendChild(emptyRow);
    updateStats();
  });
}

// ── Network listener ──────────────────────────────────────────────────────────
if (typeof chrome !== 'undefined' && chrome.devtools?.network?.onRequestFinished) {
  chrome.devtools.network.onRequestFinished.addListener((request) => {
    const url = request.request?.url;
    if (!url || url.startsWith('chrome-extension://') || url.startsWith('data:')) {
      return;
    }

    const mimeType = request.response?.content?.mimeType ?? '';

    // Only inspect text, json, xml, html, javascript responses
    const isInspectable =
      mimeType.includes('json') ||
      mimeType.includes('text') ||
      mimeType.includes('javascript') ||
      mimeType.includes('xml') ||
      mimeType.includes('html') ||
      mimeType === '';

    if (!isInspectable) return;

    request.getContent((rawContent) => {
      if (!rawContent || typeof rawContent !== 'string') return;

      // In-memory detector evaluation (F7: Body, F1: Secrets, F2: Endpoints)
      const bodyLeads = detectBodyLeads(rawContent, mimeType, url, 'in-scope');
      const secretLeads = detectSecrets(rawContent, url, 'in-scope');
      const endpointLeads = (mimeType.includes('javascript') || mimeType.includes('json'))
        ? detectEndpoints(rawContent, url, 'in-scope')
        : [];

      // CRITICAL: Explicitly decouple content so raw response is garbage collected immediately
      rawContent = '';

      const allLeads = [...bodyLeads, ...secretLeads, ...endpointLeads];
      if (allLeads.length === 0) return;

      for (const lead of allLeads) {
        lead.sourceSensor = 'S4';
        lead.url = (maskLocation(lead.url) as string) || lead.url;
        lead.evidence.location = maskLocation(lead.evidence.location);
        collectedLeads.push(lead);
        renderLeadRow(lead);
      }

      updateStats();

      // Forward extracted masked leads to background service worker
      try {
        const inspectedTabId = chrome.devtools.inspectedWindow?.tabId;
        void chrome.runtime?.sendMessage?.({
          type: 'DEVTOOLS_LEADS_COLLECTED',
          tabId: inspectedTabId,
          leads: allLeads,
        }).catch(() => undefined);
      } catch {
        // Ignore communication failure
      }
    });
  });
}
