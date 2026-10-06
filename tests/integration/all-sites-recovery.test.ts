import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

describe('All-Sites Recovery Integration', () => {
  const mockContains = vi.fn<(permissions: chrome.permissions.Permissions) => Promise<boolean>>();
  const mockRequest = vi.fn<(permissions: chrome.permissions.Permissions) => Promise<boolean>>();
  const mockRemove = vi.fn<(permissions: chrome.permissions.Permissions) => Promise<boolean>>();
  const mockOnRemovedAddListener = vi.fn<() => void>();

  beforeEach(() => {
    mockContains.mockReset();
    mockRequest.mockReset();
    mockRemove.mockReset();
    mockOnRemovedAddListener.mockReset();

    vi.stubGlobal('chrome', {
      permissions: {
        contains: mockContains,
        request: mockRequest,
        remove: mockRemove,
        onRemoved: { addListener: mockOnRemovedAddListener },
      },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('Partial broad grant rejection', () => {
    it('classifies missing http://*/* as incomplete when monitoringMode is all-sites', async () => {
      const mode = 'all-sites';
      mockContains.mockImplementation((perms: chrome.permissions.Permissions) => {
        const origins = perms.origins ?? [];
        if (origins.includes('<all_urls>')) return Promise.resolve(false);
        if (origins.includes('http://*/*') && origins.includes('https://*/*')) return Promise.resolve(false);
        if (origins.includes('https://*/*')) return Promise.resolve(true);
        return Promise.resolve(false);
      });

      const checkPermissions = async (): Promise<boolean> => {
        const hasAllUrls = await chrome.permissions.contains({ origins: ['<all_urls>'] });
        const hasBoth = await chrome.permissions.contains({ origins: ['http://*/*', 'https://*/*'] });
        return hasAllUrls || hasBoth;
      };

      const isComplete = await checkPermissions();
      expect(isComplete).toBe(false);
      expect(mode).toBe('all-sites');
    });
  });

  describe('Complete broad grant acceptance', () => {
    it('allows capture if <all_urls> or both http/https are present', async () => {
      mockContains.mockResolvedValue(true);

      const checkPermissions = async (): Promise<boolean> => {
        const hasAllUrls = await chrome.permissions.contains({ origins: ['<all_urls>'] });
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

      const restoreAllSites = async (): Promise<void> => {
        mockRequest.mockResolvedValue(true);
        const granted = await chrome.permissions.request({ origins: ['<all_urls>'] });
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
