/**
 * Shared Ninja Motion lifecycle helpers.
 * Keeps animation state transitions bounded, cancellation-safe, and one-shot.
 */

export const MAX_SMOKE_ENTRANCES = 8;
export const MAX_RADAR_PINGS_PER_UPDATE = 6;
export const MAX_SEEN_IDS = 2000;

/**
 * Records an identifier in a session-bounded Set, evicting the oldest entry
 * (FIFO) if capacity reaches `limit`. Returns `true` if `id` was newly added.
 */
export function recordBoundedSeenId(set: Set<string>, id: string, limit: number = MAX_SEEN_IDS): boolean {
  if (set.has(id)) {
    return false;
  }
  while (set.size >= limit) {
    const oldest = set.values().next();
    if (oldest.done === true) break;
    set.delete(oldest.value);
  }
  set.add(id);
  return true;
}

/**
 * Determines whether a rendered grade genuinely changed and warrants the Katana reveal.
 */
export function shouldTriggerGradeReveal(
  prevKey: string,
  origin: string,
  grade: string | null | undefined,
): { trigger: boolean; nextKey: string } {
  if (grade === null || grade === undefined || grade.length === 0) {
    return { trigger: false, nextKey: prevKey };
  }
  const nextKey = `${origin}|${grade}`;
  return {
    trigger: nextKey !== prevKey,
    nextKey,
  };
}

/**
 * Applies a one-shot CSS animation class and guarantees cleanup on `animationend`,
 * `animationcancel` (e.g. tab/view hide or reduced-motion toggle), or fallback timeout.
 */
export function attachOneShotMotionClass(
  el: Element,
  className: string,
  expectedAnimationName: string,
  fallbackMs: number,
  timerTarget?: { clear: () => void } | null,
): () => void {
  timerTarget?.clear();
  el.classList.add(className);

  let cleaned = false;
  let timerId: ReturnType<typeof setTimeout> | null = null;

  const cleanup = (): void => {
    if (cleaned) return;
    cleaned = true;
    el.classList.remove(className);
    el.removeEventListener('animationend', onEnd);
    el.removeEventListener('animationcancel', onCancel);
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
  };

  const onEnd = (event: Event): void => {
    const animEvent = event as AnimationEvent;
    if (animEvent.target === el && animEvent.animationName === expectedAnimationName) {
      cleanup();
    }
  };

  const onCancel = (event: Event): void => {
    if (event.target === el) {
      cleanup();
    }
  };

  el.addEventListener('animationend', onEnd);
  el.addEventListener('animationcancel', onCancel);
  timerId = setTimeout(cleanup, fallbackMs);

  return cleanup;
}

/**
 * Attaches `animationend`, `animationcancel`, and timeout cleanup to a transient SVG node.
 */
export function attachSvgPingCleanup(svgEl: SVGElement, fallbackMs: number = 800): () => void {
  let removed = false;
  let timerId: ReturnType<typeof setTimeout> | null = null;

  const remove = (): void => {
    if (removed) return;
    removed = true;
    svgEl.removeEventListener('animationend', remove);
    svgEl.removeEventListener('animationcancel', remove);
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
    svgEl.remove();
  };

  svgEl.addEventListener('animationend', remove);
  svgEl.addEventListener('animationcancel', remove);
  timerId = setTimeout(remove, fallbackMs);

  return remove;
}

/**
 * Swaps only the `grade-<x>` class, leaving every other class (notably `motion-grade-reveal`) intact.
 * Assigning `el.className = ...` on every render wiped the running reveal animation.
 */
export function setGradeClass(el: Element, grade: string): void {
  const target = `grade-${grade}`;
  for (const c of Array.from(el.classList)) {
    if (c.startsWith('grade-') && c !== 'grade-badge' && c !== target) {
      el.classList.remove(c);
    }
  }
  if (!el.classList.contains('grade-badge')) el.classList.add('grade-badge');
  if (!el.classList.contains(target)) el.classList.add(target);
}

/**
 * Stable signature of what the findings teaser will render. Re-rendering an identical list
 * rebuilds the DOM and kills in-flight entrance animations, so callers skip when it is unchanged.
 */
export function findingsSignature(
  items: ReadonlyArray<{
    ruleId: string;
    severity: string;
    outcome?: string | undefined;
    evidence?: string | undefined;
  }>,
): string {
  return items.map((f) => `${f.ruleId}:${f.severity}:${f.outcome ?? ''}:${f.evidence ?? ''}`).join('|');
}

/**
 * Stable signature of what the sidepanel leads list will render so identical back-to-back updates
 * do not tear down in-flight card entrance animations.
 */
export function leadsSignature(
  items: ReadonlyArray<{
    id: string;
    potential: string;
    pinned?: boolean | undefined;
    triageState?: string | undefined;
    verdict?:
      | {
          status?: string | undefined;
          evidenceStatus?: string | undefined;
          securityAssessment?: string | undefined;
        }
      | undefined;
  }>,
): string {
  return items
    .map(
      (l) =>
        `${l.id}:${l.potential}:${l.pinned === true ? '1' : '0'}:${l.triageState ?? ''}:${l.verdict?.status ?? ''}:${l.verdict?.evidenceStatus ?? ''}:${l.verdict?.securityAssessment ?? ''}`,
    )
    .join('|');
}
