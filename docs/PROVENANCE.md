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
  - TypeScript strict compilation (`npm run typecheck`)
  - Strict ESLint checks (`npm run lint` with `--max-warnings=0`)
  - Unit, scope, fuzz, and integration suites (`npm test`)
  - Post-build artifact security & syntax validation across all targets (`npm run test:artifacts`)
  - Official Mozilla Firefox AMO linter (`npm run lint:amo` via `web-ext lint`)
  - Chromium and Firefox browser extension runtime end-to-end integration (`npm run test:e2e`)
  - Zero-vulnerability dependency audit (`npm audit --audit-level=low`)
  - Aggregate release package verification across all 4 targets (`npm run verify:pack`)

### 3.2 Git Tagging & Cryptographic Signature Procedures
- **Historical Git Tags**: Early tags (`v1.0.0`, `v2`, `v2.0.0`) are unsigned annotated milestone tags pointing to pre-v2.0.4 development commits prior to the modular architecture refactor.
- **Current Version Tag**: Release `v2.0.5` corresponds to the validated commit on `main`. It is published as an authoritative annotated Git tag recording tagger metadata and release summary.

#### Method A: Modern SSH Key Signing (Recommended)
Git (>= 2.34) and GitHub natively support signing commits and release tags with standard SSH keys (using `ssh-keygen`), eliminating GPG key-server and daemon configuration:
1. Generate an SSH signing key on your local workstation:
   ```bash
   ssh-keygen -t ed25519 -C "Dhyanpatel884@gmail.com" -f ~/.ssh/aculyx_signing_key
   ```
2. Add the public key (`~/.ssh/aculyx_signing_key.pub`) to GitHub:
   - Go to **GitHub Settings > SSH and GPG keys > New SSH key**.
   - Set **Key type** to **Signing Key**.
   - Paste the public key string and save.
3. Configure Git to automatically sign all commits and tags with this SSH key:
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/aculyx_signing_key.pub
   git config --global commit.gpgsign true
   git config --global tag.gpgSign true
   ```
4. Sign and push the release tag:
   ```bash
   git tag -s -f v2.0.5 -m "Release v2.0.5: hardened security, AMO lint, multi-browser runtime E2E, and verified package integrity"
   git push origin v2.0.5 --force
   ```
   GitHub will verify the SSH cryptographic signature against your account and display the green **Verified** badge.

#### Method B: Traditional GPG Key Signing
If using GPG keys:
1. Generate a GPG key:
   ```bash
   gpg --full-generate-key
   ```
2. Export and add the public key to GitHub under **Settings > SSH and GPG keys > New GPG key**:
   ```bash
   gpg --armor --export <KEY_ID>
   ```
3. Configure Git:
   ```bash
   git config --global user.signingkey <KEY_ID>
   git config --global commit.gpgsign true
   git config --global tag.gpgSign true
   ```
4. Sign and verify the tag:
   ```bash
   git tag -s -f v2.0.5 -m "Release v2.0.5"
   git verify-tag v2.0.5
   git push origin v2.0.5 --force
   ```

---

### 3.3 Cryptographically Verifiable Artifact Attestations (Sigstore / SLSA)

ACULYX integrates **GitHub Artifact Attestations** (`actions/attest-build-provenance`) into the automated CI build pipeline:
1. **Cryptographic Build Provenance**: During automated CI execution on `push` and `v*` tag releases, GitHub generates signed in-toto attestations backed by GitHub's Sigstore OpenID Connect (OIDC) identity provider and public Rekor transparency log.
2. **Immutable Traceability**: The attestation cryptographically binds the exact SHA-256 digests of all 4 release packages (`ACULYX-source.zip`, `ACULYX-full.zip`, `ACULYX-chrome.zip`, `ACULYX-firefox.zip`, `ACULYX.zip`) and `SHA256SUMS` to:
   - The canonical repository: `Gone27/ACULYX`
   - The exact commit SHA and release ref: `refs/tags/v2.0.5`
   - The workflow run ID and builder environment.
3. **Independent Verification**: Researchers, enterprise consumers, and security auditors can verify any release archive against the immutable transparency log using the GitHub CLI:
   ```bash
   # Verify Chromium extension package provenance
   gh attestation verify ACULYX-chrome.zip --repo Gone27/ACULYX

   # Verify Firefox AMO distribution provenance
   gh attestation verify ACULYX-firefox.zip --repo Gone27/ACULYX
   ```
   If the archive was tampered with, rebuilt with different dependencies, or not produced by the authorized GitHub Actions workflow, verification fails closed.

---

### 3.4 Public Release Distribution Policy & Checksum Manifests
When official release distributions are published to GitHub Releases (`https://github.com/Gone27/ACULYX/releases`):
1. **Tagged Commits**: Official releases correspond to version tags (e.g. `v2.0.5`) on `main`.
2. **Release Assets & Checksums**: The official distribution consists of the 4 release archives (`ACULYX-source.zip`, `ACULYX-full.zip`, `ACULYX-chrome.zip`, `ACULYX-firefox.zip`), legacy alias `ACULYX.zip`, and the generated `SHA256SUMS` manifest. Packaging (`npm run pack`) automatically writes and validates this manifest.
3. **Checksum Verification**: In addition to cryptographic artifact attestations, researchers can independently verify packages using:
   ```bash
   sha256sum -c SHA256SUMS
   ```
4. **Reproducibility**: Binaries and distribution ZIPs are reproducible from the clean source tree using `npm run build:all` and `npm run pack`.
