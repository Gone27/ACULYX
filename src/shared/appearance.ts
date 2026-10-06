/**
 * src/shared/appearance.ts — Unified appearance preferences application
 *
 * Applies theme (system/dark/light), layout density (comfortable/compact),
 * and reduced motion (system/always/never) across all extension surfaces:
 * Options, Popup, and Side Panel.
 */

import { LocalStorage } from './storage';

export function applyAppearance(
  theme?: 'system' | 'dark' | 'light',
  density?: 'comfortable' | 'compact',
  reducedMotion?: 'system' | 'always' | 'never',
  targetDocument: Document = document,
): void {
  const root = targetDocument.documentElement;

  // Theme
  if (theme !== undefined) {
    root.removeAttribute('data-theme');
    if (theme === 'dark' || theme === 'light') {
      root.setAttribute('data-theme', theme);
    }
  }

  // Density
  if (density !== undefined && targetDocument.body as HTMLElement | null !== null) {
    targetDocument.body.classList.toggle('density-compact', density === 'compact');
  }

  // Motion
  if (reducedMotion !== undefined) {
    root.removeAttribute('data-motion');
    if (reducedMotion === 'always') {
      root.setAttribute('data-motion', 'reduce');
    } else if (reducedMotion === 'never') {
      root.setAttribute('data-motion', 'no-reduce');
    }
  }
}

export async function bootstrapAppearance(targetDocument: Document = document): Promise<void> {
  try {
    const settings = await LocalStorage.getSettings();
    applyAppearance(settings.theme, settings.density, settings.reducedMotion, targetDocument);
  } catch {
    // Fail safe on uninitialized storage
  }
}
