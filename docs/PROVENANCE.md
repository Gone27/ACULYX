# ACULYX Provenance & Ownership Record

**Author & Copyright Owner**: Dhyan Patel  
**Product**: ACULYX — Header & Cookie Security Checker  
**Canonical Repository**: `https://github.com/Gone27/Cookie-and-header-reader-extention`  
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

## 3. Official Release Verification & Integrity

Official binary builds of ACULYX for Chrome and Firefox are published from tagged commits on GitHub:
- **Repository**: `https://github.com/Gone27/Cookie-and-header-reader-extention`
- **Releases**: `https://github.com/Gone27/Cookie-and-header-reader-extention/releases`

Every official release artifact includes:
1. Git release tag signed by the author.
2. Source tree commit SHA matching the release tag.
3. Published SHA-256 checksums for the compiled `.zip` distribution packages.
4. Clean reproducible build passing all automated quality and security gates:
   - TypeScript compilation (`tsc --noEmit`)
   - Strict ESLint checks (`eslint src tests --max-warnings=0`)
   - Full Vitest suite (454+ tests)
   - Playwright E2E verification
   - Zero vulnerability dependency audit (`npm audit --audit-level=low`)
