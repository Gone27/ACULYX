# ACULYX CLI

**ACULYX: Header & Cookie Security Checker — Standalone CLI & CI Pipeline**

The ACULYX CLI reuses the extension's pure TypeScript rule engine and fix catalogue. It supports a one-off HTTP(S) scan, offline JSON capture inspection, or offline HAR analysis, and exits with a non-zero code when a configured severity threshold is met.

## Usage

```bash
# Live URL scan
npm run aculyx -- --url https://example.com --format json --fail-on high

# Offline JSON inspection
npm run aculyx -- --input audit.json --format markdown --fail-on medium

# Offline HAR analysis
npm run aculyx -- --har capture.har --url https://example.com/account --format sarif

# Regression diff against baseline
npm run aculyx -- --input current.json --diff baseline.json --format markdown

# Legacy compatibility alias
npm run seccheck -- --url https://example.com
```

`--format` accepts `json`, `markdown`, or `sarif`.
`--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`, or `never`; the default is `high`.

### Output Formats

- **SARIF (Static Analysis Results Interchange Format)**: Outputs SARIF 2.1.0 with driver name `ACULYX`, rule definitions, CWE/OWASP metadata, exact URI locations, confidence metrics, and finding properties. Fully compatible with GitHub Code Scanning.
- **Markdown**: Executive summary, configuration quality score, and actionable remediation snippets from [`fixes.json`](../fixes.json).
- **JSON**: Sanitized machine-readable TabState or CliReport.

### Baseline Regression Diff Mode

You can compare two reports using the `--diff` mode:
```bash
npm run aculyx -- --input current.json --diff baseline.json --format markdown
```
The CLI detects new regressions, resolved findings, and severity changes. If coverage metrics indicate a degraded capture, a prominent warning is surfaced to prevent treating missing findings as resolved vulnerabilities.

### GitHub Actions CI Workflow Example

```yaml
name: Security Header Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci
      - name: Run ACULYX Header Audit
        run: npm run aculyx -- --input audit.json --format sarif --fail-on high > aculyx.sarif
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aculyx.sarif
```

### Exit Codes

- `0`: No finding met or exceeded `--fail-on` threshold.
- `1`: At least one finding met or exceeded `--fail-on`.
- `2`: Invalid CLI arguments, missing parameters, or scan failure.

### Privacy & Input Data Constraints

- **Offline Modes**: JSON and HAR input modes perform zero external network requests.
- **Cookie Value Rejection**: Cookie inputs containing a `value` field are rejected immediately. Only cookie metadata attributes (`name`, `domain`, `secure`, `httpOnly`, `sameSite`, `partitioned`) are evaluated.
- **Redaction**: All `Set-Cookie` header values in HAR/JSON inputs are redacted before evaluation.
- **SSRF Protection & Private IP Blocking**: When auditing live targets via `--url`, direct requests and intermediate redirect hops to private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), IPv6 local addresses (`[::1]`, `fe80::/10`, `fc00::/7`), and cloud metadata IP (`169.254.169.254`) are blocked by default. Pass `--allow-private-ips` for local development servers (`http://localhost:3000`).
