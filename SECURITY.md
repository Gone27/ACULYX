# Security Policy

## Supported Versions

The latest released version receives active security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0.0 | :x:                |

---

## Reporting a Vulnerability

The ACULYX project takes security and privacy vulnerabilities seriously. If you discover a potential vulnerability in ACULYX, please follow responsible disclosure guidelines.

### Reporting Channel

Please **do not** file public GitHub issues or post public comments for suspected security vulnerabilities.

Instead, submit reports privately through **GitHub Private Vulnerability Reporting**:
👉 [New Security Advisory](https://github.com/Gone27/ACULYX/security/advisories/new)

If private advisory submission is unavailable, contact the author directly via the email listed in repository metadata.

### Report Guidelines

To help us investigate and triage effectively, please include:
1. A clear description of the issue and affected component (service worker, sensors, options, parser, CLI).
2. Step-by-step reproduction instructions or a minimal test case using mocked synthetic inputs.
3. Impact assessment and potential attack vectors.

> [!IMPORTANT]
> **Zero Live Credential Policy**: Never include real API tokens, live credentials, or sensitive private information in any report. Always use synthetic tokens or placeholders (e.g. `sk_test_...` or masked tokens).

### Response Process

- We acknowledge vulnerability reports promptly upon receipt.
- A private investigation will assess the severity and formulate a remediation.
- Fixes will be committed and released with clean regression tests and updated release packages.
