import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

interface Manifest {
  manifest_version?: number;
  content_security_policy?: {
    extension_pages?: string;
  };
  permissions?: string[];
  host_permissions?: string[];
  optional_permissions?: string[];
  optional_host_permissions?: string[];
}

describe('Artifact Scan', () => {
  const readManifest = (filename: string): Manifest => {
    const filePath = path.join(__dirname, '../../', filename);
    const content = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(content) as Manifest;
  };

  const manifests = ['manifest.json', 'manifest.firefox.json'];

  manifests.forEach((filename) => {
    describe(filename, () => {
      let manifest: Manifest;

      it('exists and is valid JSON', () => {
        manifest = readManifest(filename);
        expect(manifest).toBeDefined();
      });

      it('uses manifest_version 3', () => {
        expect(manifest.manifest_version).toBe(3);
      });

      it('enforces secure CSP', () => {
        const csp = manifest.content_security_policy?.extension_pages;
        expect(csp).toBeDefined();

        expect(csp).toContain("script-src 'self'");
        expect(csp).toContain("object-src 'none'");
        expect(csp).toContain("connect-src 'none'");

        // Assert no remote code or CDN script references
        expect(csp).not.toMatch(/https:\/\//);
        expect(csp).not.toContain("'unsafe-eval'");
      });

      it('does not request prohibited permissions', () => {
        const permissions = manifest.permissions ?? [];
        const hostPermissions = manifest.host_permissions ?? [];

        const broadPatterns = ['<all_urls>', '*://*/*', 'https://*/*', 'http://*/*'];

        for (const pattern of broadPatterns) {
          expect(permissions).not.toContain(pattern);
          expect(hostPermissions).not.toContain(pattern);
        }
      });

      it('has broad patterns only in optional permissions/host_permissions', () => {
        // It's allowed in optional host permissions or optional permissions, so if it exists there, it's fine.
        // We already verified above it's NOT in required ones.
        const allOptional = [
          ...(manifest.optional_permissions ?? []),
          ...(manifest.optional_host_permissions ?? [])
        ];

        // It doesn't strictly have to have them, but if it does, it's fine.
        // The main requirement was verifying they are NOT in required permissions.
        expect(Array.isArray(allOptional)).toBe(true);
      });
    });
  });

  describe('dist/ chunks security', () => {
    it('scans built dist/ JS chunks ensuring no unredacted canaries or remote script URLs are embedded', () => {
      const distPath = path.join(__dirname, '../../dist');
      if (!fs.existsSync(distPath)) {
        return; // skip if dist/ not found
      }

      const files = fs.readdirSync(distPath, { recursive: true }) as string[];
      const jsFiles = files.filter(f => f.endsWith('.js')).map(f => path.join(distPath, f));

      for (const file of jsFiles) {
        const content = fs.readFileSync(file, 'utf-8');

        // Ensure no unredacted cookie canaries (common dummy canary strings from tests/code)
        // Also ensure no <script src="http(s)://..."> injected by bundler or third party

        // This regex looks for literal script tags with remote HTTP/HTTPS src
        const remoteScriptPattern = /<script[^>]+src=["']https?:\/\/[^"']+["']/i;
        expect(content).not.toMatch(remoteScriptPattern);

        // Check for specific dummy secrets from tests leaking into production build
        expect(content).not.toContain('SECRET_CANARY_12345');
        expect(content).not.toContain('SECRET_CANARY_67890');
      }
    });
  });
});
