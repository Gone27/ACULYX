# SecCheck CLI

The CLI reuses the extension's rule engine and fix catalogue. It supports a one-off HTTP(S) scan, offline JSON capture, or offline HAR entry, and exits non-zero when a configured severity threshold is met.

## Usage

```bash
npm run seccheck -- --url https://example.com --format json --fail-on high
npm run seccheck -- --input audit.json --format markdown --fail-on medium
npm run seccheck -- --har capture.har --url https://example.com/account --format sarif
```

`--format` accepts `json`, `markdown`, or `sarif`. `--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`, or `never`; the default is `high`.

SARIF output uses version 2.1.0 and includes rule metadata, finding messages, severity levels, evidence properties, and the affected page URL as a location. It can be consumed by GitHub Code Scanning with `github/codeql-action/upload-sarif`. JSON and Markdown reports include both the security score/grade and the separate configuration-quality score/grade.

HAR input is local and does not make a network request. `--url` selects the most recent exact URL match in the HAR; query strings are part of the match and URL fragments are ignored. Response `Set-Cookie` values are redacted before analysis, and HAR cookie objects contribute attributes only. HAR request bodies, response bodies, and TLS details are not analyzed.

Example CI flow:

```yaml
- run: npm run seccheck -- --input audit.json --format sarif --fail-on high > seccheck.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: seccheck.sarif
```

Exit codes: `0` means no finding met the threshold, `1` means at least one finding met or exceeded it, and `2` means invalid arguments, input, or a scan error. Severity ordering is `critical` > `high` > `medium` > `low` > `info`; for example, `--fail-on high` fails on critical and high findings.

URL mode makes one explicit GET request, follows redirects, reads response headers only, and does not send browser cookies. Unlike the extension, this mode contacts the target. JSON input mode performs no network requests:

```json
{
  "url": "https://example.com/",
  "status": 200,
  "headers": {
    "content-security-policy": "default-src 'self'; object-src 'none'"
  },
  "cookies": []
}
```

Offline JSON cookies may include attributes only (`name`, `domain`, `secure`, `httpOnly`, `sameSite`, and related metadata). Inputs containing a cookie `value` are rejected. JSON/HAR `Set-Cookie` header values are redacted before evaluation and never appear in reports.

Each finding includes a matching entry from the root [`fixes.json`](../fixes.json) catalogue when available. Snippets are illustrative and require application-specific review; the CLI never edits files or applies fixes.

## CI

The GitHub Actions workflow runs a CLI smoke scan against a checked-in fixture. For an application pipeline, save the captured response headers as JSON and set `--fail-on` to the severity that should fail the build.