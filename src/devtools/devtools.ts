/**
 * devtools.ts
 *
 * DevTools extension bootstrap script.
 * Registers the "ACULYX Leads" panel in Chrome DevTools.
 */

chrome.devtools.panels.create(
  'ACULYX Leads',
  'icons/icon16.png',
  'src/devtools/panel.html',
  () => {
    // Panel registered successfully
  }
);
