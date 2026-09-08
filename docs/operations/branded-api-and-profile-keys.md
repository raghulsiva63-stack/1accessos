# Passkey-X branded API and profile-scoped keys

## Target outcome

Keep the web application at:

```text
https://passkey-x.com/
```

Publish the customer REST API through the same trusted domain:

```text
https://passkey-x.com/api
```

Example encrypted vault write:

```text
POST https://passkey-x.com/api/v1/vault-items
```

The Supabase Functions URL remains an internal upstream. Customer documentation,
SDKs, integrations, and generated examples must use the Passkey-X API URL.

Do not point the website root directly at Supabase. The root path serves the web
application. A dedicated `/api/*` namespace prevents route collisions and can later
move unchanged to `https://api.passkey-x.com`.

## Current state

- `public.api_tokens` already stores a token prefix, SHA-256 verifier, scopes,
  expiry, last-used timestamp, and revocation timestamp.
- The current `v1` Edge Function authenticates Supabase user access tokens only.
- API-key creation, one-time display, key authentication, and Settings UI are not
  complete until the implementation and acceptance checks below pass.
- Never document the existing database table as a working customer feature before
  those checks pass.

## Required architecture

### 1. Branded API gateway

Add a Netlify rewrite before any catch-all route:

```toml
[[redirects]]
  from = "/api/*"
  to = "https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/:splat"
  status = 200
  force = true
```

This is a rewrite, not a browser redirect. The caller continues to see the
Passkey-X URL.

Do not embed a Supabase secret or service-role key in `netlify.toml`, frontend
JavaScript, an OpenAPI file, or an SDK. If the Supabase gateway needs a platform
credential, inject only a publishable key at a trusted server boundary or use a
dedicated Edge Function whose own authentication is fully implemented.

### 2. API-key format

Generate at least 256 random bits with a cryptographically secure random-number
generator. Use a recognizable prefix:

```text
pkx_live_<public-prefix>_<secret>
```

Only show the complete key once. Store:

- the visible prefix;
- a versioned password/key derivation verifier (preferred: keyed HMAC-SHA-256
  with a server-held pepper; SHA-256 is acceptable only for a full-entropy key);
- the creating identity;
- the selected organization/profile context;
- approved scopes;
- optional expiry;
- creation, last-used, and revocation timestamps.

Never store or log the raw key.

### 3. Settings workflow

Add **Settings → Developer → API keys** with:

1. Key name.
2. Organization/profile selector limited to memberships held by the signed-in user.
3. Permission checkboxes filtered by the user's live role.
4. Expiry: 30, 90, 180, or 365 days; custom expiry only for owners/admins.
5. A reauthentication/passkey confirmation before creation.
6. A one-time key display with Copy and Download buttons.
7. A list showing prefix, name, scopes, created time, last use, expiry, and state.
8. Immediate revoke and rotate actions.

The browser may receive the raw key only in the successful creation response. It
must not be readable again from the database or API.

### 4. Permission model

An API key can only reduce the creator's access; it can never add access.
Authorization must require all of the following on every request:

```text
key is valid and not expired/revoked
AND identity is active
AND organization membership is active
AND selected scope permits the operation
AND current role permits the operation
AND workspace/resource RLS permits the record
```

Recommended maximum scopes:

| Profile role | Maximum selectable scopes |
|---|---|
| Owner | `vault:read`, `vault:write`, `access:read`, `access:write`, `org:read`, `org:write`, `billing:read`, `billing:write`, `runtime:read`, `runtime:request`, `audit:read` |
| Admin | All owner scopes except ownership transfer and destructive billing/account operations |
| Manager | Workspace vault/access read-write, organization read, runtime request |
| Editor | Workspace vault read-write and access request |
| Viewer | Workspace vault read only |
| Auditor | Audit and organization read only; no vault ciphertext unless explicitly granted by workspace policy |

Do not derive authorization from `user_metadata`. Resolve current membership and
role server-side for every request. A role downgrade must reduce an existing key's
effective permissions immediately without waiting for token expiry.

### 5. Key-authenticated request flow

Use:

```http
Authorization: Bearer pkx_live_...
Content-Type: application/json
Idempotency-Key: <UUID>
```

At the server boundary:

1. Parse and validate the key format and prefix.
2. Find the candidate record by prefix.
3. Verify the secret using constant-time comparison.
4. Reject expired, revoked, disabled-identity, or disabled-membership keys.
5. resolve the current identity, tenant, organization, role, and allowed scopes;
6. map the HTTP operation to a required scope;
7. execute through an authorization-aware service/RPC boundary;
8. update `last_used_at` asynchronously;
9. append a redacted audit event containing key ID/prefix, action, target, result,
   request ID, and timestamp—never the raw key or request secret content.

Do not disable Supabase JWT verification on the existing mixed-auth function and
assume the handler is safe. Either create a dedicated key-authenticated function
with complete custom authentication or put a trusted gateway in front of it.

### 6. Mandatory security controls

- Rate-limit by key, identity, tenant, IP signal, and operation class.
- Reject keys in query strings and request bodies.
- Return `401` for invalid credentials and `403` for insufficient scope or role.
- Preserve the zero-knowledge boundary: clients encrypt vault values before upload.
- Never accept plaintext passwords, recovery material, private keys, provider
  credentials, raw page/form content, or raw AI prompts.
- Require `Idempotency-Key` for mutations and `If-Match` for revision updates.
- Redact authorization headers from Netlify, Supabase, analytics, and application logs.
- Provide owner/admin visibility into organization keys without exposing key values.
- Revoke all keys for a deleted identity, removed membership, or deleted tenant.

## Production configuration checklist

### DNS and Netlify

- [ ] Keep `passkey-x.com` and `www.passkey-x.com` on the current Netlify site.
- [ ] Add the `/api/*` rewrite before any application catch-all.
- [ ] Deploy and verify that the browser address remains on `passkey-x.com/api/...`.
- [ ] Confirm API responses set `Cache-Control: no-store` and security headers.
- [ ] Confirm Netlify logs redact the `Authorization` header.

### Supabase

- [ ] Add a migration that binds each API key to a tenant/profile context and name.
- [ ] Restrict direct browser insert/update of verifier and scope fields.
- [ ] Create authenticated RPCs for create/list/revoke/rotate operations.
- [ ] Make key creation validate current membership and maximum role scopes.
- [ ] Add the dedicated API-key authenticator/gateway.
- [ ] Keep service-role/secret credentials server-side only.
- [ ] Run security and performance advisors after the migration.

### Web application

- [ ] Add Settings → Developer → API keys.
- [ ] Require recent authentication before create, rotate, and revoke.
- [ ] Show the raw key once and clear it from component state after dismissal.
- [ ] Add empty, loading, expiry, revoked, and permission-denied states.
- [ ] Link the Settings screen to the public API documentation.

### Documentation

- [ ] Change the OpenAPI production server to `https://passkey-x.com/api`.
- [ ] Remove the public Supabase hostname and `apikey` header from customer examples.
- [ ] Document `Authorization: Bearer pkx_live_...` and each required scope.
- [ ] Keep Supabase JWT examples in a separate interactive-user-auth section if needed.
- [ ] Publish rotation, revocation, idempotency, conflict, and error examples.

## Acceptance tests

- [ ] A viewer cannot create a write-scoped key.
- [ ] An editor cannot create organization-admin or billing scopes.
- [ ] An owner can select only documented owner scopes.
- [ ] A raw key is returned exactly once and never appears in later responses/logs.
- [ ] A valid read key can read only authorized workspace ciphertext.
- [ ] A read key receives `403` on every write operation.
- [ ] Cross-tenant IDs return no data and cannot reveal resource existence.
- [ ] Revocation takes effect on the next request.
- [ ] Role downgrade takes effect on the next request.
- [ ] Identity or membership disablement takes effect on the next request.
- [ ] Expired keys return `401`.
- [ ] Replayed mutation IDs return the recorded response without duplicate writes.
- [ ] The Passkey-X URL works without revealing or redirecting to the Supabase hostname.
- [ ] Existing web JWT authentication continues to work.
- [ ] OpenAPI validation, application tests, production build, and secret scan pass.

## Rollout order

1. Add the database migration and server-only token management RPCs.
2. Implement and test the dedicated API-key authentication boundary.
3. Add the Settings UI and one-time key ceremony.
4. Add the branded `/api/*` gateway route.
5. Update OpenAPI and examples to the branded URL.
6. Run tenant-isolation, role-downgrade, revocation, replay, and logging tests.
7. Deploy to UAT, create a disposable test key, and verify every scope.
8. Revoke the UAT key, deploy production, and repeat a read/write/revoke smoke test.

Do not mark profile-scoped API keys complete merely because `public.api_tokens`
exists. Completion requires the Settings ceremony, server-side verification,
live-role intersection, audit trail, branded gateway, and all acceptance tests.
