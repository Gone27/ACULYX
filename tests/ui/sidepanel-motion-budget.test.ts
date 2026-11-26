import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../..');

function extractCssBlock(css: string, selector: string): string {
  const idx = css.indexOf(selector);
  if (idx === -1) return '';
  const openBrace = css.indexOf('{', idx);
  if (openBrace === -1) return '';
  const closeBrace = css.indexOf('}', openBrace);
  if (closeBrace === -1) return '';
  return css.slice(openBrace + 1, closeBrace);
}

describe('Sidepanel CSS & Motion Performance Budget', () => {
  const cssPath = path.join(repoRoot, 'src/sidepanel/sidepanel.css');
  const tsPath = path.join(repoRoot, 'src/sidepanel/sidepanel.ts');
  const css = fs.readFileSync(cssPath, 'utf8');
  const ts = fs.readFileSync(tsPath, 'utf8');

  it('promotes rotating radar sweep onto compositor layer without per-frame drop-shadow filter', () => {
    const sweepGroup = extractCssBlock(css, '.radar-sweep-group {');
    expect(sweepGroup).toContain('will-change: transform;');
    expect(sweepGroup).toContain('animation: radarSweepAnim');

    const sweepLine = extractCssBlock(css, '.radar-sweep-line {');
    expect(sweepLine).not.toContain('filter:');
    expect(sweepLine).not.toContain('drop-shadow(');
  });

  it('keeps view and settings transitions restricted to compositor transform and opacity properties', () => {
    const viewActive = extractCssBlock(css, '.panel-view.active {');
    expect(viewActive).toContain('will-change: transform, opacity;');

    const settingsOverlay = extractCssBlock(css, '.settings-panel-overlay {');
    expect(settingsOverlay).toContain('will-change: transform, opacity;');

    const viewFadeKeyframes = extractCssBlock(css, '@keyframes viewFadeIn');
    expect(viewFadeKeyframes).not.toContain('width:');
    expect(viewFadeKeyframes).not.toContain('height:');
    expect(viewFadeKeyframes).not.toContain('top:');
    expect(viewFadeKeyframes).not.toContain('left:');

    const settingsSlideKeyframes = extractCssBlock(css, '@keyframes settingsSlideIn');
    expect(settingsSlideKeyframes).not.toContain('width:');
    expect(settingsSlideKeyframes).not.toContain('height:');
  });

  it('disables animations and transitions under prefers-reduced-motion and data-motion="reduce"', () => {
    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
    expect(css).toContain('[data-motion="reduce"] *');
  });

  it('pauses radar sweep when overview is hidden, settings is open, page is hidden, or motion is reduced', () => {
    const fnStart = ts.indexOf('function updateRadarSweepState()');
    expect(fnStart).toBeGreaterThan(-1);
    const fnSlice = ts.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('!viewOverview.hidden');
    expect(fnSlice).toContain('viewSettings.hidden');
    expect(fnSlice).toContain("document.visibilityState === 'visible'");
    expect(fnSlice).toContain('data-motion');
    expect(fnSlice).toContain('animationPlayState');
  });
});
