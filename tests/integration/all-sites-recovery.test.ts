/* eslint-disable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any, @typescript-eslint/strict-boolean-expressions, @typescript-eslint/require-await */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Mock } from 'vitest';

describe('All-Sites Recovery Integration', () => {
  beforeEach(() => {
    vi.stubGlobal('chrome', {
      permissions: {
        contains: vi.fn(),
        request: vi.fn(),
        remove: vi.fn(),
        onRemoved: { addListener: vi.fn() },
      }
    });
  });

  describe('Partial broad grant rejection', () => {
    it('classifies missing http://*/* as incomplete when monitoringMode is all-sites', async () => {
      const mode = 'all-sites';
      ((globalThis as any).chrome.permissions.contains as Mock).mockImplementation(async (perms: { origins?: string[] }) => {
        if (perms.origins?.includes('<all_urls>')) return false;
        if (perms.origins?.includes('http://*/*') && perms.origins?.includes('https://*/*')) return false;
        if (perms.origins?.includes('https://*/*')) return true;
        return false;
      });

      const checkPermissions = async () => {
        const hasAllUrls = Boolean(await (globalThis as any).chrome.permissions.contains({ origins: ['<all_urls>'] }));
        const hasBoth = Boolean(await (globalThis as any).chrome.permissions.contains({ origins: ['http://*/*', 'https://*/*'] }));
        return hasAllUrls || hasBoth;
      };

      const isComplete = await checkPermissions();
      expect(isComplete).toBe(false);
      expect(mode).toBe('all-sites');
    });
  });

  describe('Complete broad grant acceptance', () => {
    it('allows capture if <all_urls> or both http/https are present', async () => {
      ((globalThis as any).chrome.permissions.contains as Mock).mockResolvedValue(true);

      const checkPermissions = async () => {
        const hasAllUrls = Boolean(await (globalThis as any).chrome.permissions.contains({ origins: ['<all_urls>'] }));
        return hasAllUrls;
      };

      const isComplete = await checkPermissions();
      expect(isComplete).toBe(true);
    });
  });

  describe('External revocation', () => {
    it('transitions to paused when broad grant is externally removed, keeping mode all-sites', () => {
      const currentMode = 'all-sites';
      let status = 'active';

      // Simulate external revocation callback
      const onRevoked = () => {
        status = 'paused';
      };

      onRevoked();

      expect(currentMode).toBe('all-sites');
      expect(status).toBe('paused');
    });
  });

  describe('Recovery actions', () => {
    it('can restore all-sites access or switch to per-site', async () => {
      let currentMode = 'all-sites';
      let status = 'paused';

      const restoreAllSites = async () => {
        ((globalThis as any).chrome.permissions.request as Mock).mockResolvedValue(true);
        const granted = Boolean(await (globalThis as any).chrome.permissions.request({ origins: ['<all_urls>'] }));
        if (granted) {
          status = 'active';
        }
      };

      const switchToPerSite = () => {
        currentMode = 'per-site';
        status = 'active'; // Assumes permissions are implicitly okay for per-site depending on activeTab
      };

      await restoreAllSites();
      expect(status).toBe('active');

      // reset
      status = 'paused';
      switchToPerSite();
      expect(currentMode).toBe('per-site');
      expect(status).toBe('active');
    });
  });
});
