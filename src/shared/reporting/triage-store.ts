/**
 * Local Researcher Triage Store for ACULYX.
 *
 * Implements decoupled local storage and retrieval for researcher triage state:
 * - ResearcherReviewState: 'unreviewed' | 'needs-manual-verification' |
 *   'verified-by-researcher' | 'not-reproducible' | 'not-a-finding'.
 * - Notes & timestamps per finding.
 * - Invariant: Triage annotations are stored independently from immutable scanner findings.
 * - Invariant: Private/incognito findings are never written to persistent storage.
 */

import type { ResearcherReviewState, TriageAnnotation } from './types';
import { redactAllSecrets } from './report-builder';

export const TRIAGE_STORAGE_PREFIX = 'triage:';
export const MAX_TRIAGE_NOTE_LENGTH = 5000;

export const VALID_REVIEW_STATES: readonly ResearcherReviewState[] = [
  'unreviewed',
  'needs-manual-verification',
  'verified-by-researcher',
  'not-reproducible',
  'not-a-finding',
] as const;

export function isValidReviewState(state: unknown): state is ResearcherReviewState {
  return typeof state === 'string' && (VALID_REVIEW_STATES as readonly string[]).includes(state);
}

/** In-memory fallback map for test environments and incognito sessions. */
const memoryStore = new Map<string, TriageAnnotation>();
const incognitoStore = new Map<string, TriageAnnotation>();

function getStorageKey(findingId: string): string {
  return `${TRIAGE_STORAGE_PREFIX}${findingId}`;
}

function hasLocalStorage(): boolean {
  return (
    typeof chrome !== 'undefined' &&
    Boolean(chrome.storage) &&
    Boolean(chrome.storage.local)
  );
}

export class TriageStore {
  /**
   * Retrieves the triage annotation for a specific finding.
   * If isIncognito is true, searches the ephemeral incognito store first.
   */
  static async getAnnotation(
    findingId: string,
    options?: { isIncognito?: boolean },
  ): Promise<TriageAnnotation | null> {
    if (!findingId || typeof findingId !== 'string') {
      return null;
    }

    if (options?.isIncognito === true) {
      return incognitoStore.get(findingId) ?? null;
    }

    if (!hasLocalStorage()) {
      return memoryStore.get(findingId) ?? null;
    }

    try {
      const key = getStorageKey(findingId);
      const result = await chrome.storage.local.get(key);
      const raw = result[key] as Record<string, unknown> | undefined;
      if (raw !== undefined && typeof raw === 'object' && raw !== null) {
        const item = raw as unknown as TriageAnnotation;
        if (typeof item.findingId === 'string' && item.findingId.length > 0 && isValidReviewState(item.state)) {
          return item;
        }
      }
      return null;
    } catch {
      return memoryStore.get(findingId) ?? null;
    }
  }

  /**
   * Sets or updates a triage annotation for a finding.
   * Strictly decoupled: does not mutate the scanner finding.
   * If isIncognito is true, stores ONLY in the ephemeral incognito memory store.
   */
  static async setAnnotation(
    findingId: string,
    state: ResearcherReviewState,
    notes?: string,
    options?: { isIncognito?: boolean },
  ): Promise<TriageAnnotation> {
    if (!findingId || typeof findingId !== 'string') {
      throw new Error('Invalid findingId: non-empty string required');
    }
    if (!isValidReviewState(state)) {
      throw new Error(`Invalid ResearcherReviewState: ${String(state)}`);
    }

    let sanitizedNotes: string | undefined;
    if (typeof notes === 'string' && notes.trim().length > 0) {
      const capped = notes.trim().slice(0, MAX_TRIAGE_NOTE_LENGTH);
      sanitizedNotes = redactAllSecrets(capped);
    }

    const annotation: TriageAnnotation = {
      findingId,
      state,
      notes: sanitizedNotes,
      updatedAt: Date.now(),
    };

    if (options?.isIncognito === true) {
      incognitoStore.set(findingId, annotation);
      return annotation;
    }

    if (!hasLocalStorage()) {
      memoryStore.set(findingId, annotation);
      return annotation;
    }

    try {
      const key = getStorageKey(findingId);
      await chrome.storage.local.set({ [key]: annotation });
      // Keep memory mirror in sync
      memoryStore.set(findingId, annotation);
      return annotation;
    } catch {
      memoryStore.set(findingId, annotation);
      return annotation;
    }
  }

  /**
   * Removes a triage annotation for a finding.
   */
  static async deleteAnnotation(
    findingId: string,
    options?: { isIncognito?: boolean },
  ): Promise<boolean> {
    if (!findingId || typeof findingId !== 'string') {
      return false;
    }

    if (options?.isIncognito === true) {
      return incognitoStore.delete(findingId);
    }

    let deleted = false;
    if (memoryStore.has(findingId)) {
      memoryStore.delete(findingId);
      deleted = true;
    }

    if (hasLocalStorage()) {
      try {
        const key = getStorageKey(findingId);
        await chrome.storage.local.remove(key);
        deleted = true;
      } catch {
        // Ignored, fallback memory was updated
      }
    }

    return deleted;
  }

  /**
   * Retrieves all triage annotations for the provided finding IDs or all stored annotations.
   */
  static async getAnnotations(
    findingIds?: string[],
    options?: { isIncognito?: boolean },
  ): Promise<Record<string, TriageAnnotation>> {
    const result: Record<string, TriageAnnotation> = {};

    if (options?.isIncognito === true) {
      if (findingIds && findingIds.length > 0) {
        for (const id of findingIds) {
          const ann = incognitoStore.get(id);
          if (ann) result[id] = ann;
        }
      } else {
        for (const [id, ann] of incognitoStore.entries()) {
          result[id] = ann;
        }
      }
      return result;
    }

    if (!hasLocalStorage()) {
      if (findingIds && findingIds.length > 0) {
        for (const id of findingIds) {
          const ann = memoryStore.get(id);
          if (ann) result[id] = ann;
        }
      } else {
        for (const [id, ann] of memoryStore.entries()) {
          result[id] = ann;
        }
      }
      return result;
    }

    try {
      if (findingIds !== undefined && findingIds.length > 0) {
        const keys = findingIds.map(getStorageKey);
        const data = await chrome.storage.local.get(keys);
        for (const id of findingIds) {
          const key = getStorageKey(id);
          const raw = data[key] as TriageAnnotation | undefined;
          if (raw !== undefined && isValidReviewState(raw.state)) {
            result[id] = raw;
          }
        }
      } else {
        const all = await chrome.storage.local.get(null);
        for (const [key, raw] of Object.entries(all)) {
          if (key.startsWith(TRIAGE_STORAGE_PREFIX)) {
            const id = key.slice(TRIAGE_STORAGE_PREFIX.length);
            const ann = raw as TriageAnnotation | undefined;
            if (ann !== undefined && isValidReviewState(ann.state)) {
              result[id] = ann;
            }
          }
        }
      }
      return result;
    } catch {
      // Return memory fallback
      if (findingIds !== undefined && findingIds.length > 0) {
        for (const id of findingIds) {
          const ann = memoryStore.get(id);
          if (ann !== undefined) result[id] = ann;
        }
      } else {
        for (const [id, ann] of memoryStore.entries()) {
          result[id] = ann;
        }
      }
      return result;
    }
  }

  /**
   * Purges all persistent and in-memory triage annotations.
   */
  static async clearAll(options?: { isIncognitoOnly?: boolean }): Promise<void> {
    if (options?.isIncognitoOnly === true) {
      incognitoStore.clear();
      return;
    }

    incognitoStore.clear();
    memoryStore.clear();

    if (hasLocalStorage()) {
      try {
        const all = await chrome.storage.local.get(null);
        const keysToRemove = Object.keys(all).filter((k) =>
          k.startsWith(TRIAGE_STORAGE_PREFIX),
        );
        if (keysToRemove.length > 0) {
          await chrome.storage.local.remove(keysToRemove);
        }
      } catch {
        // Fallback already cleared
      }
    }
  }

  /**
   * Resets in-memory stores for testing.
   */
  static _resetMemoryStores(): void {
    memoryStore.clear();
    incognitoStore.clear();
  }
}
