import type { Express, Request, Response } from 'express';

export function registerLeadLabRoutes(app: Express): void {
  // 1. Reflected inputs across 5 contexts (PAR-003)
  app.get('/lead-lab/reflected-input', (req: Request, res: Response) => {
    const q = typeof req.query.q === 'string' ? req.query.q : 'default_query';
    const attr = typeof req.query.attr === 'string' ? req.query.attr : 'attr_value';
    const js = typeof req.query.js === 'string' ? req.query.js : 'js_string';
    const url = typeof req.query.url === 'string' ? req.query.url : '/target_url';
    const comment = typeof req.query.comment === 'string' ? req.query.comment : 'comment_note';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(`<!DOCTYPE html>
<html>
<head><title>Lead Lab: Reflected Input</title></head>
<body>
  <h1>Reflected Parameters Test</h1>
  <!-- HTML context -->
  <div id="html-content"><p>${q}</p></div>
  <!-- Attribute context -->
  <input type="text" id="attr-input" value="${attr}" />
  <!-- URL attribute context -->
  <a id="link-target" href="${url}">Click here</a>
  <!-- Comment context -->
  <!-- ${comment} -->
  <!-- JS String context -->
  <script>
    var reflectedValue = "${js}";
    console.log("Loaded reflected value:", reflectedValue);
  </script>
</body>
</html>`);
  });

  // 2. CORS Reflection with Credentials and missing Vary (COR-001)
  app.get('/lead-lab/cors-reflect', (req: Request, res: Response) => {
    const origin = typeof req.headers.origin === 'string' && req.headers.origin.length > 0
      ? req.headers.origin
      : 'http://attacker-controlled.example';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    // Intentionally omit 'Vary: Origin' to trigger cache poisoning risk lead
    res.status(200).json({ status: 'ok', user: 'authenticated_user_profile' });
  });

  // 3. Inline Source Map Leakage (MAP-001, MAP-002)
  app.get('/lead-lab/inline-sourcemap', (_req: Request, res: Response) => {
    const mockSourceMap = {
      version: 3,
      file: 'bundle.js',
      sources: [
        '/home/dev/acme/src/auth/jwt-service.ts',
        'C:/Users/Admin/workspace/src/secrets/config.ts',
      ],
      sourcesContent: [
        'export const JWT_SECRET = "super_secret_jwt_key_12345";',
        'export const DB_URI = "postgres://dev_user:P@ssword123!@10.0.0.5:5432/acme_db";',
      ],
      mappings: 'AAAA',
    };
    const b64Map = Buffer.from(JSON.stringify(mockSourceMap)).toString('base64');
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.status(200).send(`
function run() { console.log("bundle running"); }
//# sourceMappingURL=data:application/json;base64,${b64Map}
`);
  });

  // 4. Secret-laden JavaScript with public IDs and false-positive controls (SEC-001..004)
  app.get('/lead-lab/secret-js', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    const mockStripe = ['sk', 'live', '51Abcdef1234567890abcdef1234567890'].join('_');
    const mockGithub = ['ghp', '1234567890abcdef1234567890abcdef123456'].join('_');
    const mockSlack = ['https:', '', 'hooks.slack.com', 'services', 'T00000000', 'B00000000', 'XXXXXXXXXXXXXXXXXXXXXXXX'].join('/');
    const mockStripePub = ['pk', 'live', '51Abcdefghijklmnopqrstuvwx1234567890'].join('_');
    res.status(200).send(`
// Public by design (INFO, never secret):
const stripePublishable = "${mockStripePub}";
const sentryDsn = "https://abcdef1234567890@o123456.ingest.sentry.io/123456";

// Real secrets (SEC-001):
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const stripeSecret = "${mockStripe}";
const githubToken = "${mockGithub}";
const slackWebhook = "${mockSlack}";

// Placeholders (must be filtered out):
const fakeKey = "YOUR_API_KEY_HERE";
const dummySecret = "sk_live_xxxxxxxxxxxxxxxxxxxx";

// Database URI (SEC-002):
const mongoUri = "mongodb+srv://admin:Hunter2Password@cluster0.mongodb.net/prod_data";

// Private key PEM block (SEC-002):
const privateKey = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0...\\n-----END RSA PRIVATE KEY-----";
`);
  });

  // 5. Debug Pages and Stack Traces (ERR-001)
  app.get('/lead-lab/debug-page', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(500).send(`<!DOCTYPE html>
<html>
<head><title>Internal Server Error</title></head>
<body>
  <h1>Werkzeug Debugger</h1>
  <div class="traceback">
    <h3>Traceback (most recent call last):</h3>
    <pre>
  File "/app/server/routes.py", line 42, in handle_request
    data = fetch_sensitive_admin_record(account_id)
  File "/app/server/database.py", line 105, in fetch_sensitive_admin_record
    cursor.execute("SELECT * FROM users WHERE id = %s", (account_id,))
DatabaseError: connection to server at "10.0.1.15", port 5432 failed: FATAL: password authentication failed
    </pre>
  </div>
</body>
</html>`);
  });

  // 6. Router tables and hidden webpack chunks (END-002)
  app.get('/lead-lab/hidden-chunks', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.status(200).send(`
// Webpack chunk map leak
!function() {
  window.__webpack_require__ = {};
  window.__webpack_require__.u = function(chunkId) {
    return "" + chunkId + "." + {
      "admin-dashboard": "3a4b5c",
      "billing-export": "7d8e9f",
      "internal-metrics": "0a1b2c"
    }[chunkId] + ".chunk.js";
  };
}();
`);
  });

  // 7. CSP Static Nonce Reuse (CSP-102)
  app.get('/lead-lab/nonce-reuse', (_req: Request, res: Response) => {
    res.setHeader(
      'Content-Security-Policy',
      "script-src 'nonce-STATIC_REUSED_NONCE_VALUE_12345'; object-src 'none'",
    );
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(`<!DOCTYPE html><html><body><h1>Static Nonce Page</h1></body></html>`);
  });

  // 8. Cloud Buckets and Hostnames (CLD-001, HOST-001)
  app.get('/lead-lab/cloud-assets', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(`<!DOCTYPE html>
<html>
<head><title>Cloud Assets</title></head>
<body>
  <img src="https://acme-prod-media.s3.amazonaws.com/logos/header.png" />
  <script src="https://storage.googleapis.com/acme-public-scripts/app.js"></script>
  <a href="https://acme-internal-backups.blob.core.windows.net/archives/2026.zip">Backup</a>
</body>
</html>`);
  });
}
