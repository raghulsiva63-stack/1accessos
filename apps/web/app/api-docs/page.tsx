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

export default function ApiDocsPage() {
  return <main className="api-docs-page">
    <header className="api-docs-header">
      <Link href="/">← Passkey-X</Link>
      <div><span className="public-kicker">Production API</span><h1>Push encrypted data safely.</h1><p>Use a signed-in user’s short-lived Supabase access token. Tenant and workspace permissions are enforced by Row Level Security.</p></div>
      <div className="api-docs-actions"><a href="/openapi.yaml" download>Download OpenAPI 3.1</a><a href="https://github.com/raghulsiva63-stack/1accessos/blob/main/docs/api/README.md">Developer guide</a></div>
    </header>
    <section className="api-docs-warning"><strong>Zero-knowledge boundary</strong><p>Encrypt vault content in the trusted client before sending it. Never submit plaintext passwords, recovery keys, private keys, provider tokens, raw page/form content, or raw AI prompts.</p></section>
    <section>
      <h2>Production base URL</h2>
      <pre><code>https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1</code></pre>
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
  'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/v1/vault-items' \\
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
  </main>;
}

