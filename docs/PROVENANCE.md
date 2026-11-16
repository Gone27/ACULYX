# ACULYX Provenance & Ownership Record

**Author & Copyright Owner**: Dhyan Patel
**Product**: ACULYX — Header & Cookie Security Checker
**Canonical Repository**: `https://github.com/Gone27/ACULYX`
**License**: Apache-2.0 (Code) | Proprietary Trademark & Brand Assets (Dhyan Patel)

---

## 1. Author & Ownership Statement

ACULYX is created and authored by **Dhyan Patel**. All source code, architectural implementations, rule engines, user interface surfaces, and documentation in this repository were created by Dhyan Patel. No other contributors have contributed code to this project.

The software is distributed under the terms of the Apache License, Version 2.0. In accordance with Section 6 of the Apache 2.0 License, the name **ACULYX**, the katana wordmark, and the ACULYX icon designs are proprietary brand assets and trademarks of Dhyan Patel and are not licensed under Apache 2.0.

---

## 2. Brand Asset Provenance & Checksums

The master visual identity assets were created by Dhyan Patel and recorded with the following cryptographic signatures:

| Asset Description | File Path | Format / Dimensions | SHA-256 Checksum |
|---|---|---|---|
| Master Katana Wordmark Lockup | `src/assets/aculyx-wordmark.png` | PNG (1024×395 RGBA) | `d5d2a6311f92623c82cd873e8af632d22ca11758117914d6d5d63be5ed19ebc7` |
| Documentation Lockup | `docs/assets/aculyx-wordmark.png` | PNG (1024×395 RGBA) | `d5d2a6311f92623c82cd873e8af632d22ca11758117914d6d5d63be5ed19ebc7` |
| Extension Store & High-Res Icon | `icons/icon128.png` | PNG (128×128 RGBA) | Derived from Master Silhouette |
| Extension Management Icon | `icons/icon48.png` | PNG (48×48 RGBA) | Derived from Master Silhouette |
| High-DPI Toolbar Action Icon | `icons/icon32.png` | PNG (32×32 RGBA) | Derived from Master Silhouette |
| Standard Toolbar Action Icon | `icons/icon16.png` | PNG (16×16 RGBA) | Derived from Master Silhouette |

---

## 3. Release Verification & Publication Standards

ACULYX enforces a reproducible, verifiable release pipeline to guarantee artifact provenance.

### 3.1 Automated CI & Local Release Verification
Every release package (`source`, `full`, `chrome`, `firefox`) built locally or in CI is verified by [`scripts/verify-release-zip.mjs`](../scripts/verify-release-zip.mjs) against deterministic integrity rules:
- RFC 1951 forward-slash entry naming and CRC-32 validation.
- Clean smoke extraction into isolated temporary workspaces.
- Strict exclusion of sensitive files (`.env*`, `*.local`, `ORIGINAL_REQUEST.md`), development caches, and OS metadata.
- Pre-release passage through all automated quality gates:
  - TypeScript strict compilation (`tsc --noEmit`)
  - Strict ESLint checks (`eslint src tests --max-warnings=0`)
  - Unit, scope, fuzz, and integration suites (`npm test`)
  - Post-build artifact security & syntax validation across all targets (`npm run test:artifacts`)
  - Chromium browser extension end-to-end integration (`npm run test:e2e`)
  - Zero-vulnerability dependency audit (`npm audit --audit-level=low`)
  - Aggregate release package verification across all 4 targets (`npm run verify:pack`)

### 3.2 Public Release Distribution Policy
When official release distributions are published to GitHub Releases (`https://github.com/Gone27/ACULYX/releases`):
1. **Tagged Commits**: Official releases correspond to annotated version tags (e.g. `v2.0.5`) on `main`.
2. **Published Checksums**: Official release packages will be accompanied by a published `SHA256SUMS` manifest allowing researchers and auditors to independently verify package integrity.
3. **Reproducibility**: Binaries are reproducible from the clean source tree using `npm run build:all` and `npm run pack`.
