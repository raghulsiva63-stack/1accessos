import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";

const page = await readFile("apps/web/app/page.tsx", "utf8");
const itemModel = await readFile("apps/web/lib/vault/items.ts", "utf8");
const crypto = await readFile("apps/web/lib/crypto/vault.ts", "utf8");
const attachments = await readFile("apps/web/lib/vault/attachments.ts", "utf8");
const downloads = await readFile("apps/web/lib/browser/download.ts", "utf8");
const completion = await readFile("supabase/migrations/00000000000004_phase1_completion.sql", "utf8");
const invoker = await readFile("supabase/migrations/00000000000006_invoker_bootstrap_and_recovery.sql", "utf8");
const recoveryPolicy = await readFile("supabase/migrations/00000000000007_recovery_policy_efficiency.sql", "utf8");
const attachmentRpc = await readFile("supabase/migrations/00000000000008_atomic_attachment_rpc.sql", "utf8");
const manifest = JSON.parse(await readFile("apps/extension/public/manifest.json", "utf8"));
const tauri = JSON.parse(await readFile("apps/desktop/src-tauri/tauri.conf.json", "utf8"));
const api = await readFile("supabase/functions/v1/index.ts", "utf8");
const netlify = await readFile("netlify.toml", "utf8");

for (const kind of [
  "login", "passkey", "secure-note", "identity", "payment-card",
  "recovery-codes", "wifi", "software-license", "api-key", "ssh-key",
  "database", "certificate", "custom-secret",
]) assert.match(itemModel, new RegExp(`[\"']${kind}[\"']`), `missing item type ${kind}`);

assert.match(page, /Passkey-X/);
assert.match(page, /vault password must be different from your login password/i);
assert.match(page, /resetPasswordForEmail/);
assert.match(page, /PASSWORD_RECOVERY/);
assert.match(page, /updating the login.*does not reset or decrypt the separate vault password/is);
assert.doesNotMatch(page, /aria-label="1accessos"|Unable to open 1accessos/);
assert.match(crypto, /PX-RK1-/);
assert.match(crypto, /passkey-x-export/);
assert.match(attachments, /vault-attachments/);
assert.match(downloads, /documentObject\.body\.append\(anchor\)/);
assert.match(downloads, /DEFAULT_REVOKE_DELAY_MS/);
assert.doesNotMatch(`${page}\n${attachments}`, /revokeObjectURL\(url\)/, "downloads must not revoke object URLs synchronously");
assert.match(completion, /enable row level security/i);
assert.match(completion, /can_access_attachment_path/);
assert.match(invoker, /security invoker/gi);
assert.doesNotMatch(invoker, /language plpgsql\s+security definer/gi, "public RPC migration must not introduce a PL/pgSQL definer");
assert.equal((recoveryPolicy.match(/create policy crypto_profile_recovery_update/g) ?? []).length, 1);
assert.match(recoveryPolicy, /select current_setting/);
assert.match(attachmentRpc, /security invoker/i);
assert.match(attachmentRpc, /attachment_version_sync_change/);

assert.equal(manifest.manifest_version, 3);
assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
assert.equal(tauri.productName, "Passkey-X");
assert.match(tauri.app.security.csp, /object-src 'none'/);
assert.match(api, /Only ciphertext envelopes are accepted/);
assert.doesNotMatch(api, /SUPABASE_SERVICE_ROLE_KEY/);
assert.match(netlify, /Content-Security-Policy/);
assert.match(netlify, /frame-ancestors 'none'/);
assert.match(netlify, /X-Content-Type-Options = "nosniff"/);

for (const asset of [
  "apps/web/public/brand/passkey-x-horizontal.png",
  "apps/web/public/brand/passkey-x-mark.png",
  "apps/web/public/brand/passkey-x-app-icon.png",
  "apps/web/public/brand/passkey-x-hero.webp",
]) assert.ok((await stat(asset)).size > 10_000, `brand asset ${asset} is missing or invalid`);

console.log("Phase 1 static checks passed for Passkey-X web, extension, desktop, recovery, and attachments.");
