# Passkey-X CLI

This Phase 2 CLI provides a scriptable view of the ciphertext-only `/v1` API. It
lists workspace, membership, item, sync, Mission, request and grant metadata. It
does not accept a vault password, recovery key, plaintext credential, or
Supabase service-role key.

Use a short-lived authenticated user token only through the environment:

```text
PASSKEY_X_ACCESS_TOKEN=<short-lived-user-token> node src/index.mjs workspaces
node src/index.mjs items --workspace <workspace-uuid>
```

Shell history is not a safe place for bearer tokens. Production automation will
use separately scoped personal API tokens after the token broker is deployed.
