import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Passkey-X API documentation",
  description: "Production REST API reference and secure encrypted-data push guide for Passkey-X.",
};

const endpoints = [
  ["Vault", "POST /v1/vault-items", "Push a client-encrypted vault envelope"],
  ["Vault", "PATCH /v1/vault-items/{item_id}", "Push a new encrypted revision with If-Match"],
  ["Access", "POST /v1/access-requests", "Create an encrypted access request"],
  ["SaaS & AI", "POST /v1/saas/recommendations/refresh", "Refresh metadata-only proposals"],
  ["Billing", "POST /billing", "Open Stripe sandbox Checkout or Customer Portal"],
  ["Notifications", "POST /tenant-sms", "Manage tenant-scoped Sent notification settings"],
  ["Account", "POST /account-lifecycle", "Preflight or execute guarded account deletion"],
];

const orgEndpoints = [
  ["GET", "/v1/me", "—", "The key's organization, name, scopes and expiry."],
  ["GET", "/v1/audit-events?after=&limit=", "audit:read", "Audit events in sequence order. Cursor pagination: pass the response's next_after as after while has_more is true. limit ≤ 500."],
  ["GET", "/v1/alerts?status=&limit=", "alerts:read", "Security alerts, optionally filtered by status (open, acknowledged, resolved)."],
  ["PATCH", "/v1/alerts/{id}", "alerts:write", "Body {\"status\": \"acknowledged\" | \"resolved\" | \"open\", \"note\": \"…\"} — e.g. close an alert from your ticket system."],
  ["GET", "/v1/members?offset=&limit=", "members:read", "Members with name, email, role, two-step and passkey status and security score."],
  ["GET", "/v1/security/summary", "reports:read", "Current organization security score and adoption metrics."],
  ["GET", "/v1/reports/weekly?limit=", "reports:read", "Stored weekly security reports, newest first."],
];

export default function ApiDocsPage() {
  return <main className="api-docs-page">
    <header className="api-docs-header">
      <Link href="/">← Passkey-X</Link>
      <div><span className="public-kicker">Production API</span><h1>Push encrypted data safely.</h1><p>Use the branded Passkey-X API with a signed-in user’s short-lived access token. Tenant and workspace permissions are enforced by Row Level Security.</p></div>
      <div className="api-docs-actions"><a href="/openapi.yaml" download>Download OpenAPI 3.1</a><a href="https://github.com/raghulsiva63-stack/1accessos/blob/main/docs/api/README.md">Developer guide</a></div>
    </header>
    <section className="api-docs-warning"><strong>Zero-knowledge boundary</strong><p>Encrypt vault content in the trusted client before sending it. Never submit plaintext passwords, recovery keys, private keys, provider tokens, raw page/form content, or raw AI prompts.</p></section>
    <section>
      <h2>Production base URL</h2>
      <pre><code>https://passkey-x.com/api</code></pre>
    </section>
    <section>
      <h2>Authentication headers</h2>
      <pre><code>{`Authorization: Bearer <USER_ACCESS_TOKEN>
apikey: <PUBLISHABLE_KEY>
Content-Type: application/json
Idempotency-Key: <UUID>`}</code></pre>
      <p>Never place Supabase secret/service-role keys, Stripe keys, or Sent keys in browser or integration client code.</p>
    </section>
    <section>
      <h2>Supported write operations</h2>
      <div className="api-docs-grid">{endpoints.map(([area, route, purpose]) => <article key={route}><span>{area}</span><code>{route}</code><p>{purpose}</p></article>)}</div>
    </section>
    <section>
      <h2>Encrypted vault example</h2>
      <pre><code>{`curl --request POST \\
  'https://passkey-x.com/api/v1/vault-items' \\
  --header 'Authorization: Bearer <USER_ACCESS_TOKEN>' \\
  --header 'apikey: <PUBLISHABLE_KEY>' \\
  --header 'Content-Type: application/json' \\
  --header 'Idempotency-Key: <UUID>' \\
  --data '{
    "id": "<ITEM_UUID>",
    "tenant_id": "<TENANT_UUID>",
    "workspace_id": "<WORKSPACE_UUID>",
    "content_type": "login",
    "schema_version": 1,
    "nonce": "<BYTEA_CIPHERTEXT_NONCE>",
    "ciphertext": "<BYTEA_CIPHERTEXT>",
    "aad_hash": "<BYTEA_AAD_HASH>"
  }'`}</code></pre>
    </section>
    <section>
      <h2>Errors and retries</h2>
      <p><code>401</code> refresh the user session once. <code>403</code> means RLS denied the tenant/workspace operation. <code>409</code> means refresh and reconcile state. <code>422</code> means the envelope is invalid or contains prohibited plaintext-shaped fields.</p>
      <p>Record the response <code>x-request-id</code> for support. Retry writes only with a stable idempotency key.</p>
    </section>
    <section id="organization-api">
      <h2>Organization API</h2>
      <p>A read-mostly REST API for SIEMs, ticketing systems, Zapier and Make. It exposes audit events, security alerts, members and reports — vault contents, passwords and encryption keys are never available through it.</p>
      <h3>Authentication</h3>
      <p>Organization owners and admins create scoped keys in <strong>Admin console → Integrations → API keys</strong>. Keys start with <code>pxk_</code>, are shown once, expire after 30–365 days and can be revoked at any time. Send the key as a bearer token:</p>
      <pre><code>{`Authorization: Bearer pxk_…`}</code></pre>
      <h3>Base URL</h3>
      <pre><code>https://&lt;project&gt;.supabase.co/functions/v1/org-api/v1</code></pre>
      <p>Paths in the table include the <code>/v1</code> prefix, so <code>GET /v1/me</code> is <code>&lt;base URL&gt;/me</code>. The exact base URL is shown next to your API keys. Requests are limited to <strong>300 per minute per key</strong>; above that the API returns <code>429</code> with a <code>Retry-After</code> header (seconds).</p>
      <h3>Endpoints</h3>
      <div className="cx-api-table-wrap"><table className="cx-api-table">
        <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Scope</th><th scope="col">Returns</th></tr></thead>
        <tbody>{orgEndpoints.map(([method, path, scope, purpose]) => <tr key={`${method} ${path}`}><td><code>{method}</code></td><td><code>{path}</code></td><td>{scope === "—" ? scope : <code>{scope}</code>}</td><td>{purpose}</td></tr>)}</tbody>
      </table></div>
      <h3>Pulling audit events</h3>
      <pre><code>{`curl -s 'https://<project>.supabase.co/functions/v1/org-api/v1/audit-events?after=0&limit=500' \\
  -H "Authorization: Bearer $PASSKEY_X_API_KEY"

# → { "data": [ … ], "next_after": 18342, "has_more": true }
# Store next_after and pass it as ?after= on the next poll.`}</code></pre>
      <h3>Errors</h3>
      <pre><code>{`{ "error": { "code": "forbidden", "message": "This key needs the alerts:write scope." } }`}</code></pre>
      <p><code>400</code> <code>invalid_parameter</code> / <code>invalid_body</code>. <code>401</code> the key is missing, expired or revoked. <code>403</code> the key lacks the required scope. <code>404</code> the resource is not in your organization. <code>429</code> slow down and retry after <code>Retry-After</code> seconds.</p>
      <p>No-code tools: in Zapier use “Webhooks by Zapier” (or Make’s HTTP module) with the header <code>Authorization: Bearer &lt;key&gt;</code>, and poll <code>/v1/alerts</code> or <code>/v1/audit-events?after=&lt;last sequence&gt;</code>.</p>
      <h3>SCIM groups</h3>
      <p>The SCIM 2.0 endpoint now supports <code>/Groups</code> in addition to <code>/Users</code>. Push groups from Okta, Entra ID or another identity provider, then map each group to a workspace in <strong>Admin console → Identity &amp; SSO</strong> so membership follows your directory.</p>
    </section>
  </main>;
}
