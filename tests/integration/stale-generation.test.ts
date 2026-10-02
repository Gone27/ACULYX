import { describe, it, expect } from 'vitest';

describe('Stale Generation Integration', () => {
  // Simulating state management with generations
  class TabState {
    generation: number = 0;
    data: { apiResponse?: unknown; domSignal?: unknown } = {};
    
    navigate() {
      this.generation++;
      this.data = {}; // reset data on navigation
    }
    
    processApiResponse(generation: number, response: unknown) {
      if (generation !== this.generation) {
        // Discard stale response
        return false;
      }
      this.data.apiResponse = response;
      return true;
    }
    
    processDomSignal(generation: number, signal: unknown) {
      if (generation !== this.generation) {
        // Discard delayed DOM signal
        return false;
      }
      this.data.domSignal = signal;
      return true;
    }
  }

  describe('Stale API response discard', () => {
    it('discards a slow API response from generation 1 when tab is at generation 2', () => {
      const tab = new TabState();
      
      // Tab starts at generation 1
      tab.navigate(); // generation = 1
      const requestGen = tab.generation;
      
      // Request begins, then tab navigates to generation 2
      tab.navigate(); // generation = 2
      
      // Slow API response from generation 1 completes
      const accepted = tab.processApiResponse(requestGen, { status: 200 });
      
      // Verify response is discarded and does not mutate generation 2 state
      expect(accepted).toBe(false);
      expect(tab.data).not.toHaveProperty('apiResponse');
      expect(tab.generation).toBe(2);
    });
  });

  describe('Delayed page signal discard', () => {
    it('safely ignores a delayed DOM signal carrying generation 1 when tab is at generation 2', () => {
      const tab = new TabState();
      
      // Tab starts at generation 1
      tab.navigate(); // generation = 1
      const signalGen = tab.generation;
      
      // Tab navigates to generation 2
      tab.navigate(); // generation = 2
      
      // Delayed DOM signal arrives
      const accepted = tab.processDomSignal(signalGen, { type: 'DOM_READY' });
      
      // Verify signal is ignored
      expect(accepted).toBe(false);
      expect(tab.data).not.toHaveProperty('domSignal');
      expect(tab.generation).toBe(2);
    });
  });
});
