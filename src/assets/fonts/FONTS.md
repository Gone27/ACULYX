# ACULYX Typography Assets

ACULYX bundles modern, clean typography designed for security research operations directly in the extension for full offline privacy. Ordinary builds use only the pinned font binaries checked into `src/assets/fonts/` (no build or CI step downloads fonts over the network).

## Bundled Fonts & Provenance

1. **Space Grotesk** (Display & Headings)
   - Upstream repository: https://github.com/floriankarsten/space-grotesk
   - Upstream copyright notice:
     `Copyright 2020 The Space Grotesk Project Authors (https://github.com/floriankarsten/space-grotesk)`
   - License: SIL Open Font License, Version 1.1 (OFL-1.1) — full text in root [`NOTICE`](../../../NOTICE)
   - Bundled variable font (`wght` axis `300..700`): `SpaceGrotesk-Variable.woff2`
   - Pinned SHA-256: `0640890476fc1198ab4de571fb658de443c4d85b66466ec09534a8737ab1ce9d`

2. **IBM Plex Mono** (Code, Endpoints, Monospace Data)
   - Upstream repository: https://github.com/IBM/plex
   - Upstream copyright notice:
     `Copyright © 2017 IBM Corp. with Reserved Font Name "Plex"`
   - License: SIL Open Font License, Version 1.1 (OFL-1.1) — full text in root [`NOTICE`](../../../NOTICE)
   - Bundled weights:
     - Regular (400): `IBMPlexMono-Regular.woff2`
       Pinned SHA-256: `7ced53420784c93cecccb7c27237594f0e41e5a7990581565f0aef8eda9e9d2f`
     - SemiBold (600): `IBMPlexMono-SemiBold.woff2`
       Pinned SHA-256: `cecb8f0bc58b996a828bc0a23e2814e4acec33f0f531adf565c0248e242061e1`

## Distribution Notice

Both font families are licensed under the SIL Open Font License, Version 1.1. The root `NOTICE` file (containing both upstream copyright attributions and the complete verbatim OFL-1.1 license text) is copied into every compiled extension bundle (`dist/`, `dist-firefox/`, `dist-hunter/`) and included in all release archives (`ACULYX-source.zip`, `ACULYX-full.zip`, `ACULYX-chrome.zip`, `ACULYX-firefox.zip`, and `ACULYX.zip`).
