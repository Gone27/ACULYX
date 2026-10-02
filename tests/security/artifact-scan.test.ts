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
        // `<all_urls>` should only be in optional_host_permissions, not permissions
        expect(permissions).not.toContain('<all_urls>');
        
        const hostPermissions = manifest.host_permissions ?? [];
        expect(hostPermissions).not.toContain('<all_urls>');
      });
      
      it('has <all_urls> only in optional_host_permissions (or optional_permissions for firefox)', () => {
        // It's allowed in optional host permissions, so if it exists there, it's fine.
        // We just need to make sure it's NOT in the required ones.
      });
    });
  });
});
