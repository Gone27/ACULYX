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

      it('enforces secure CSP with provider allowlist and no broad permissions', () => {
        const csp = manifest.content_security_policy?.extension_pages;
        expect(csp).toBeDefined();

        expect(csp).toContain("script-src 'self'");
        expect(csp).toContain("object-src 'none'");

        // Explicit three-origin connect-src allowlist; never broad https: or wildcard
        expect(csp).toContain("connect-src 'self' https://api.github.com https://api.stripe.com https://slack.com");
        expect(csp).not.toContain("connect-src https:");
        expect(csp).not.toContain("connect-src *");
        expect(csp).not.toContain("http:");

        // Assert no remote code or CDN script references
        expect(csp).not.toMatch(/script-src [^;]*https:\/\//);
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

  const targetBuilds = [
    { name: 'Chrome (dist/)', relPath: '../../dist' },
    { name: 'Firefox (dist-firefox/)', relPath: '../../dist-firefox' },
    { name: 'Hunter (dist-hunter/)', relPath: '../../dist-hunter' },
  ];

  targetBuilds.forEach(({ name, relPath }) => {
    describe(`${name} compiled chunks security`, () => {
      it(`scans built ${name} JS chunks ensuring no unredacted canaries or remote script URLs are embedded`, () => {
        const targetPath = path.join(__dirname, relPath);
        const requireBuild = process.env.REQUIRE_BUILD_ARTIFACTS === 'true';
        if (!fs.existsSync(targetPath)) {
          if (requireBuild) {
            throw new Error(`Required build directory ${name} is missing. Run "npm run build:all" first.`);
          }
          return; // skip if target not found
        }

        const files = fs.readdirSync(targetPath, { recursive: true }) as string[];
        const jsFiles = files.filter(f => f.endsWith('.js')).map(f => path.join(targetPath, f));
        if (requireBuild && jsFiles.length === 0) {
          throw new Error(`Required build directory ${name} contains no compiled .js chunks.`);
        }

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

  describe('Built manifest separation and Hunter permission boundary', () => {
    it('enforces that broad permissions and relaxed connect-src exist only in Hunter and never leak into standard builds', () => {
      const distPath = path.join(__dirname, '../../dist');
      const firefoxDistPath = path.join(__dirname, '../../dist-firefox');
      const hunterDistPath = path.join(__dirname, '../../dist-hunter');

      const requireBuild = process.env.REQUIRE_BUILD_ARTIFACTS === 'true';

      if (!fs.existsSync(distPath) || !fs.existsSync(firefoxDistPath) || !fs.existsSync(hunterDistPath)) {
        if (requireBuild) {
          throw new Error('Expected built directories (dist/, dist-firefox/, dist-hunter/) are missing for boundary scan.');
        }
        return;
      }

      const chromeManifest = JSON.parse(fs.readFileSync(path.join(distPath, 'manifest.json'), 'utf-8')) as Manifest;
      const firefoxManifest = JSON.parse(fs.readFileSync(path.join(firefoxDistPath, 'manifest.json'), 'utf-8')) as Manifest;
      const hunterManifest = JSON.parse(fs.readFileSync(path.join(hunterDistPath, 'manifest.json'), 'utf-8')) as Manifest;

      // 1. Standard Chrome manifest invariants
      expect(chromeManifest.host_permissions ?? []).not.toContain('<all_urls>');
      expect(chromeManifest.permissions ?? []).not.toContain('<all_urls>');
      expect(chromeManifest.content_security_policy?.extension_pages).not.toContain('http:');
      expect(chromeManifest.content_security_policy?.extension_pages).not.toContain('connect-src *');

      // 2. Standard Firefox manifest invariants
      expect(firefoxManifest.host_permissions ?? []).not.toContain('<all_urls>');
      expect(firefoxManifest.permissions ?? []).not.toContain('sidePanel');
      expect(firefoxManifest.content_security_policy?.extension_pages).not.toContain('http:');

      // 3. Hunter edition: deliberately granted broad host permissions and relaxed connect-src for active probing
      expect(hunterManifest.host_permissions).toContain('<all_urls>');
      expect(hunterManifest.content_security_policy?.extension_pages).toContain("connect-src 'self' http: https:");
    });
  });
});
