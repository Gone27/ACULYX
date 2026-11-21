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
  browser_specific_settings?: {
    gecko?: {
      id?: string;
      strict_min_version?: string;
    };
  };
}

const CHROME_REQUIRED_PERMISSIONS = [
  'activeTab',
  'alarms',
  'cookies',
  'scripting',
  'sidePanel',
  'storage',
  'tabs',
  'webNavigation',
  'webRequest',
].sort();

const FIREFOX_REQUIRED_PERMISSIONS = [
  'activeTab',
  'alarms',
  'cookies',
  'scripting',
  'storage',
  'tabs',
  'webNavigation',
  'webRequest',
].sort();

const CHROME_OPTIONAL_HOSTS = [
  '<all_urls>',
  'https://api.github.com/*',
  'https://api.stripe.com/*',
  'https://slack.com/*',
].sort();

const FIREFOX_OPTIONAL_PERMISSIONS = [
  '<all_urls>',
  'https://api.github.com/*',
  'https://api.stripe.com/*',
  'https://slack.com/*',
].sort();

/**
 * Shared rigorous CSP assertion applied identically to source and compiled manifests
 */
function assertStandardCsp(csp: string | undefined): void {
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
        assertStandardCsp(manifest.content_security_policy?.extension_pages);
      });

      it('enforces exact required permission allowlist', () => {
        const permissions = (manifest.permissions ?? []).slice().sort();
        const hostPermissions = manifest.host_permissions ?? [];

        // Required host permissions must be empty in passive store manifests
        expect(hostPermissions).toHaveLength(0);

        if (filename === 'manifest.json') {
          expect(permissions).toEqual(CHROME_REQUIRED_PERMISSIONS);
        } else {
          expect(permissions).toEqual(FIREFOX_REQUIRED_PERMISSIONS);
          expect(permissions).not.toContain('sidePanel');
        }

        // Must never include broad access or dangerous capabilities in required permissions
        const prohibitedPermissions = [
          '<all_urls>',
          '*://*/*',
          'https://*/*',
          'http://*/*',
          'debugger',
          'management',
          'proxy',
          'webRequestBlocking',
          'nativeMessaging',
          'declarativeNetRequest',
        ];

        for (const pattern of prohibitedPermissions) {
          expect(permissions).not.toContain(pattern);
        }
      });

      it('enforces exact optional grants allowlist', () => {
        if (filename === 'manifest.json') {
          const optionalHosts = (manifest.optional_host_permissions ?? []).slice().sort();
          expect(optionalHosts).toEqual(CHROME_OPTIONAL_HOSTS);
          expect(manifest.optional_permissions ?? []).toHaveLength(0);
        } else {
          const optionalPerms = (manifest.optional_permissions ?? []).slice().sort();
          expect(optionalPerms).toEqual(FIREFOX_OPTIONAL_PERMISSIONS);
          expect(manifest.optional_host_permissions ?? []).toHaveLength(0);
        }

        // Required permissions must never contain vendor endpoints
        const permissions = manifest.permissions ?? [];
        expect(permissions).not.toContain('https://api.github.com/*');
        expect(permissions).not.toContain('https://api.stripe.com/*');
        expect(permissions).not.toContain('https://slack.com/*');
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
      it(`scans built ${name} JS chunks ensuring no unredacted canaries, live credentials, or remote scripts`, () => {
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

          // Ensure no <script src="http(s)://..."> injected by bundler or third party
          const remoteScriptPattern = /<script[^>]+src=["']https?:\/\/[^"']+["']/i;
          expect(content).not.toMatch(remoteScriptPattern);

          // Ensure no dynamic remote imports or remote script workers
          const remoteImportPattern = /(?:import\s*\(\s*['"]https?:|importScripts\s*\(\s*['"]https?:)/i;
          expect(content).not.toMatch(remoteImportPattern);

          // Check for specific dummy secrets from tests leaking into production build
          expect(content).not.toContain('SECRET_CANARY_12345');
          expect(content).not.toContain('SECRET_CANARY_67890');
          expect(content).not.toContain('CANARY_SECRET');
          expect(content).not.toContain('TEST_API_TOKEN');

          // Private key pattern check
          expect(content).not.toMatch(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/);

          // Live API credentials patterns
          expect(content).not.toMatch(/\bAKIA[0-9A-Z]{16}\b/);
          expect(content).not.toMatch(/\bsk_live_[0-9a-zA-Z]{24,}\b/);
          expect(content).not.toMatch(/\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b/);
          expect(content).not.toMatch(/\bxox[baprs]-[0-9a-zA-Z]{10,}\b/);
          expect(content).not.toMatch(/\bAIza[0-9A-Za-z-_]{35}\b/);

          // Zero telemetry or analytics client tracking calls
          expect(content).not.toMatch(/\b(?:gtag|ga)\s*\(\s*['"](?:event|send|config)/i);
          expect(content).not.toMatch(/\bSentry\.init\s*\(/);
          expect(content).not.toMatch(/\banalytics\.(?:track|identify|page)\s*\(/);
        }
      });

      it(`scans built ${name} HTML surfaces ensuring all assets and scripts are strictly local`, () => {
        const targetPath = path.join(__dirname, relPath);
        const requireBuild = process.env.REQUIRE_BUILD_ARTIFACTS === 'true';
        if (!fs.existsSync(targetPath)) {
          if (requireBuild) {
            throw new Error(`Required build directory ${name} is missing.`);
          }
          return;
        }

        const files = fs.readdirSync(targetPath, { recursive: true }) as string[];
        const htmlFiles = files.filter(f => f.endsWith('.html')).map(f => path.join(targetPath, f));
        if (requireBuild && htmlFiles.length === 0) {
          throw new Error(`Required build directory ${name} contains no HTML entrypoints.`);
        }

        for (const file of htmlFiles) {
          const content = fs.readFileSync(file, 'utf-8');

          // No remote scripts
          expect(content).not.toMatch(/<script[^>]+src=["']https?:\/\//i);
          // No remote stylesheets
          expect(content).not.toMatch(/<link[^>]+href=["']https?:\/\//i);
          // No remote iframes
          expect(content).not.toMatch(/<iframe[^>]+src=["']https?:\/\//i);
        }
      });
    });
  });

  describe('Built manifest separation and Hunter permission boundary', () => {
    it('enforces exact permission allowlists and Hunter boundary across compiled manifests', () => {
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

      // 1. Standard Chrome manifest exact permissions & rigorous CSP assertions
      expect((chromeManifest.permissions ?? []).slice().sort()).toEqual(CHROME_REQUIRED_PERMISSIONS);
      expect(chromeManifest.host_permissions ?? []).toHaveLength(0);
      expect((chromeManifest.optional_host_permissions ?? []).slice().sort()).toEqual(CHROME_OPTIONAL_HOSTS);
      expect(chromeManifest.optional_permissions ?? []).toHaveLength(0);
      assertStandardCsp(chromeManifest.content_security_policy?.extension_pages);

      // 2. Standard Firefox manifest exact permissions & rigorous CSP assertions
      expect((firefoxManifest.permissions ?? []).slice().sort()).toEqual(FIREFOX_REQUIRED_PERMISSIONS);
      expect(firefoxManifest.host_permissions ?? []).toHaveLength(0);
      expect((firefoxManifest.optional_permissions ?? []).slice().sort()).toEqual(FIREFOX_OPTIONAL_PERMISSIONS);
      expect(firefoxManifest.optional_host_permissions ?? []).toHaveLength(0);
      expect(firefoxManifest.permissions ?? []).not.toContain('sidePanel');
      assertStandardCsp(firefoxManifest.content_security_policy?.extension_pages);
      expect(firefoxManifest.browser_specific_settings?.gecko?.id).toBe('aculyx@dhyanpatel.com');
      expect(firefoxManifest.browser_specific_settings?.gecko?.strict_min_version).toBe('142.0');

      // 3. Hunter edition: broad host permissions and relaxed connect-src for active probing
      expect((hunterManifest.permissions ?? []).slice().sort()).toEqual(CHROME_REQUIRED_PERMISSIONS);
      expect((hunterManifest.host_permissions ?? []).slice().sort()).toEqual(['<all_urls>']);
      expect((hunterManifest.optional_host_permissions ?? []).slice().sort()).toEqual([
        'https://api.github.com/*',
        'https://api.stripe.com/*',
        'https://slack.com/*',
      ]);
      expect(hunterManifest.content_security_policy?.extension_pages).toBe(
        "script-src 'self'; object-src 'none'; connect-src 'self' http: https:"
      );
    });
  });
});
