# Passkey-X production REST API

Base URL:

```text
https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1
```

The machine-readable contract is [openapi.yaml](./openapi.yaml). It documents every customer-facing Edge Function and the three provider-managed callback endpoints currently deployed in production.

## Authentication

1. Sign in through Passkey-X/Supabase Auth.
2. Read the short-lived user access token from the authenticated session.
3. Send it as `Authorization: Bearer <USER_ACCESS_TOKEN>`.
4. Send the public Supabase publishable key as `apikey: <PUBLISHABLE_KEY>` when your HTTP client does not add it automatically.

Never use a Supabase secret key, legacy service-role key, Stripe key, Sent key, vault password, or recovery key in client code. The user JWT is tenant-scoped by database RLS. A tenant or workspace UUID never grants access by itself.

## What external systems can push

| Data | Endpoint | Rule |
|---|---|---|
| Encrypted vault item | `POST /v1/vault-items` | Encrypt in the trusted client before sending |
| New encrypted revision | `PATCH /v1/vault-items/{item_id}` | Supply the current `If-Match` revision |
| Encrypted access request | `POST /v1/access-requests` | Purpose must be ciphertext |
| SaaS recommendations refresh | `POST /v1/saas/recommendations/refresh` | Metadata-only; no provider mutation |
| Billing action | `POST /billing` | Owner/manager and entitlement checks apply |
| Tenant SMS configuration | `POST /tenant-sms` | Manager-only; provider key is write-only |
| Account deletion | `POST /account-lifecycle` | Preflight, recent reauthentication, and exact confirmation required |

The current public API does not accept plaintext SaaS-discovery uploads or arbitrary connector payloads. Provider adapters must be separately certified and deployed.

## Create an encrypted vault item

Values below are synthetic ciphertext placeholders. Generate UUIDs and ciphertext in your trusted client.

```bash
curl --request POST \
  'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/v1/vault-items' \
  --header 'Authorization: Bearer <USER_ACCESS_TOKEN>' \
  --header 'apikey: <PUBLISHABLE_KEY>' \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: 7a55a9fc-8b11-4d89-a37e-f0cd369420b8' \
  --data '{
    "id": "a6f82cc7-3b28-4f8d-8af0-9db2fa3330dc",
    "tenant_id": "<TENANT_UUID>",
    "workspace_id": "<WORKSPACE_UUID>",
    "content_type": "login",
    "schema_version": 1,
    "nonce": "\\x00112233445566778899aabb",
    "ciphertext": "\\x7f1a9c00",
    "aad_hash": "\\x54a1c99e"
  }'
```

A successful response is `201`:

```json
{
  "id": "a6f82cc7-3b28-4f8d-8af0-9db2fa3330dc",
  "head_revision": 1
}
```

The API rejects keys such as `password`, `private_key`, `secret_value`, `access_token`, `page_content`, `form_content`, `vault_content`, and `raw_prompt` anywhere in the JSON body.

## JavaScript example

```js
const baseUrl = "https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1";

async function pushEncryptedItem({ accessToken, publishableKey, envelope }) {
  const response = await fetch(`${baseUrl}/v1/vault-items`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      apikey: publishableKey,
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
    },
    body: JSON.stringify(envelope),
  });

  const body = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const requestId = response.headers.get("x-request-id");
    throw new Error(`${body?.error?.code ?? "request_failed"} [${requestId ?? "no-request-id"}]`);
  }
  return body;
}
```

## Update and conflict handling

Read `head_revision`, then send that value in `If-Match`. A concurrent update returns `409`; fetch the latest item, merge locally, re-encrypt, and retry with a new idempotency key.

```bash
curl --request PATCH \
  'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/v1/vault-items/<ITEM_UUID>' \
  --header 'Authorization: Bearer <USER_ACCESS_TOKEN>' \
  --header 'apikey: <PUBLISHABLE_KEY>' \
  --header 'Content-Type: application/json' \
  --header 'If-Match: "1"' \
  --header 'Idempotency-Key: 4cfa7121-347a-4500-b76d-b88bc1f8309d' \
  --data '{"nonce":"\\x00112233445566778899aabc","ciphertext":"\\x03af81","aad_hash":"\\x921dd4"}'
```

## Billing example

Stripe is currently sandbox-only.

```bash
curl --request POST \
  'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/billing' \
  --header 'Authorization: Bearer <USER_ACCESS_TOKEN>' \
  --header 'apikey: <PUBLISHABLE_KEY>' \
  --header 'Content-Type: application/json' \
  --data '{
    "action": "checkout",
    "tenantId": "<TENANT_UUID>",
    "plan": "business",
    "interval": "year",
    "currency": "inr",
    "quantity": 5,
    "requestId": "095225a0-8bf3-4bdd-a34f-d0bf5c39793a"
  }'
```

## Errors and retries

- `401`: missing, invalid, or expired user token. Refresh the session once.
- `403`: the authenticated identity lacks tenant/workspace permission.
- `409`: optimistic-concurrency conflict or unavailable/certification state.
- `422`: invalid or plaintext-bearing request.
- `429`: respect `Retry-After` and use exponential backoff with jitter.
- `5xx`: retry only idempotent requests or writes carrying a stable idempotency key.

Log the `x-request-id`, HTTP status, operation name, and your own correlation ID. Never log request bodies containing ciphertext credentials, tokens, phone numbers, or provider responses.

## Provider callbacks

`/stripe-webhook`, `/sent-webhook`, and `/sent-sms-hook` are provider-managed routes. Do not call them from customer applications. Their configured signatures, replay protection, and idempotency checks are mandatory.

