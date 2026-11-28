/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-return -- minimal DOM stand-in for lifecycle tests */
import { describe, it, expect } from 'vitest';
import { setGradeClass, findingsSignature, leadsSignature, attachOneShotMotionClass } from '../src/shared/motion';

/** Minimal Element stand-in: classList over a Set + event listeners. */
function fakeEl(initial: string[]): Element & { fire(type: string, name?: string): void } {
  const set = new Set(initial);
  const handlers = new Map<string, Array<(e: Event) => void>>();
  const el: any = {
    classList: {
      [Symbol.iterator]: () => set[Symbol.iterator](),
      add: (...c: string[]) => c.forEach((x) => set.add(x)),
      remove: (...c: string[]) => c.forEach((x) => set.delete(x)),
      contains: (c: string) => set.has(c),
    },
    addEventListener: (t: string, h: (e: Event) => void) => handlers.set(t, [...(handlers.get(t) ?? []), h]),
    removeEventListener: (t: string, h: (e: Event) => void) => handlers.set(t, (handlers.get(t) ?? []).filter((x) => x !== h)),
    fire(type: string, name = '') { for (const h of handlers.get(type) ?? []) h({ target: el, animationName: name } as unknown as Event); },
  };
  return el;
}
const has = (el: Element, c: string): boolean => el.classList.contains(c);

describe('setGradeClass keeps the running reveal animation alive', () => {
  it('swaps only the grade-* class and preserves motion-grade-reveal', () => {
    const el = fakeEl(['grade-badge', 'grade-a', 'motion-grade-reveal']);
    setGradeClass(el, 'b');
    expect(has(el, 'grade-b')).toBe(true);
    expect(has(el, 'grade-a')).toBe(false);
    expect(has(el, 'grade-badge')).toBe(true);
    expect(has(el, 'motion-grade-reveal')).toBe(true);
  });
  it('second render with the same grade (popup open renders twice) does not cancel the animation', () => {
    const el = fakeEl(['grade-badge']);
    setGradeClass(el, 'c');
    attachOneShotMotionClass(el, 'motion-grade-reveal', 'katanaSlashSweep', 450);
    setGradeClass(el, 'c'); // second render a few ms later
    expect(has(el, 'motion-grade-reveal')).toBe(true);
    expect(has(el, 'grade-c')).toBe(true);
    el.fire('animationend', 'katanaSlashSweep');
    expect(has(el, 'motion-grade-reveal')).toBe(false); // cleaned only when it finished
  });
});

describe('findingsSignature and leadsSignature skip identical re-renders', () => {
  const f = (ruleId: string, severity: string, evidence = 'e') => ({ ruleId, severity, outcome: 'fail', evidence });
  it('is stable for identical lists and changes when content changes', () => {
    expect(findingsSignature([f('A', 'high')])).toBe(findingsSignature([f('A', 'high')]));
    expect(findingsSignature([f('A', 'high')])).not.toBe(findingsSignature([f('A', 'critical')]));
    expect(findingsSignature([f('A', 'high')])).not.toBe(findingsSignature([f('A', 'high'), f('B', 'low')]));
    expect(findingsSignature([])).toBe('');
  });
  it('tracks lead list changes for triage, pin, and verdict state', () => {
    const l = (id: string, potential: string, triageState = '') => ({ id, potential, pinned: false, triageState });
    expect(leadsSignature([l('1', 'high')])).toBe(leadsSignature([l('1', 'high')]));
    expect(leadsSignature([l('1', 'high')])).not.toBe(leadsSignature([l('1', 'high', 'confirmed')]));
  });
});
