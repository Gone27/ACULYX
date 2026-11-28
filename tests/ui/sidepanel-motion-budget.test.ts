import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  MAX_RADAR_PINGS_PER_UPDATE,
  MAX_SMOKE_ENTRANCES,
  recordBoundedSeenId,
  shouldTriggerGradeReveal,
  attachOneShotMotionClass,
  attachSvgPingCleanup,
} from '../../src/shared/motion';

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

describe('Ninja Motion Helpers & Cancellation Lifecycle', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function createFakeElement() {
    const classes = new Set<string>();
    const listeners = new Map<string, Set<(e: Event) => void>>();
    let removed = false;
    const el = {
      classList: {
        add: (c: string) => { classes.add(c); },
        remove: (c: string) => { classes.delete(c); },
        contains: (c: string) => classes.has(c),
      },
      addEventListener: (type: string, fn: (e: Event) => void) => {
        if (!listeners.has(type)) listeners.set(type, new Set());
        listeners.get(type)?.add(fn);
      },
      removeEventListener: (type: string, fn: (e: Event) => void) => {
        listeners.get(type)?.delete(fn);
      },
      dispatch: (type: string, animationName?: string) => {
        const evt = { target: el, animationName } as unknown as Event;
        for (const fn of Array.from(listeners.get(type) ?? [])) {
          fn(evt);
        }
      },
      remove: () => {
        removed = true;
      },
      get listenerCount() {
        return Array.from(listeners.values()).reduce((sum, s) => sum + s.size, 0);
      },
      get isRemoved() {
        return removed;
      },
    };
    return el;
  }

  it('triggers grade reveal only when grade or origin changes', () => {
    const first = shouldTriggerGradeReveal('', 'https://example.com', 'B');
    expect(first).toEqual({ trigger: true, nextKey: 'https://example.com|B' });

    const repeat = shouldTriggerGradeReveal(first.nextKey, 'https://example.com', 'B');
    expect(repeat).toEqual({ trigger: false, nextKey: first.nextKey });

    const upgrade = shouldTriggerGradeReveal(first.nextKey, 'https://example.com', 'A');
    expect(upgrade).toEqual({ trigger: true, nextKey: 'https://example.com|A' });

    const missing = shouldTriggerGradeReveal(first.nextKey, 'https://example.com', null);
    expect(missing).toEqual({ trigger: false, nextKey: first.nextKey });
  });

  it('caps seen ID sets with FIFO eviction so long sessions stay bounded', () => {
    expect(MAX_SMOKE_ENTRANCES).toBe(8);
    expect(MAX_RADAR_PINGS_PER_UPDATE).toBe(6);

    const seen = new Set<string>();
    expect(recordBoundedSeenId(seen, 'a', 2)).toBe(true);
    expect(recordBoundedSeenId(seen, 'a', 2)).toBe(false);
    expect(recordBoundedSeenId(seen, 'b', 2)).toBe(true);
    expect(recordBoundedSeenId(seen, 'c', 2)).toBe(true);
    expect(Array.from(seen)).toEqual(['b', 'c']);
  });

  it('cleans up motion classes and listeners on animationcancel without leaking', () => {
    vi.useFakeTimers();
    const fakeEl = createFakeElement();
    attachOneShotMotionClass(
      fakeEl as unknown as Element,
      'motion-smoke-enter',
      'smokeCardReveal',
      500,
    );
    expect(fakeEl.classList.contains('motion-smoke-enter')).toBe(true);
    expect(fakeEl.listenerCount).toBe(2);

    fakeEl.dispatch('animationcancel');
    expect(fakeEl.classList.contains('motion-smoke-enter')).toBe(false);
    expect(fakeEl.listenerCount).toBe(0);
  });

  it('removes transient radar ping SVG elements on animationcancel', () => {
    vi.useFakeTimers();
    const fakeSvg = createFakeElement();
    attachSvgPingCleanup(fakeSvg as unknown as SVGElement, 800);
    expect(fakeSvg.isRemoved).toBe(false);
    expect(fakeSvg.listenerCount).toBe(2);

    fakeSvg.dispatch('animationcancel');
    expect(fakeSvg.isRemoved).toBe(true);
    expect(fakeSvg.listenerCount).toBe(0);
  });
});
