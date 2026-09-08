import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const migration = await readFile("supabase/migrations/00000000000009_phase2_collaboration.sql", "utf8");
const missionRpc = await readFile("supabase/migrations/00000000000010_phase2_mission_rpc.sql", "utf8");
const hardening = await readFile("supabase/migrations/00000000000011_phase2_policy_and_index_hardening.sql", "utf8");
const databaseTest = await readFile("supabase/tests/phase2_collaboration.sql", "utf8");
const client = await readFile("apps/web/lib/collaboration/phase2.ts", "utf8");
const page = await readFile("apps/web/app/page.tsx", "utf8");
const api = await readFile("supabase/functions/v1/index.ts", "utf8");
const openapi = await readFile("docs/api/openapi.yaml", "utf8");
const cli = await readFile("apps/cli/src/index.mjs", "utf8");
const extension = await readFile("apps/extension/src/background.ts", "utf8");

const tables = [
  "workspace_invites", "access_capsules", "access_requests", "approvals",
  "access_grants", "missions", "mission_items", "mission_runs",
];
for (const table of tables) {
  assert.match(migration, new RegExp(`create table public\\.${table}\\b`, "i"), `missing ${table}`);
  assert.match(migration, new RegExp(`alter table public\\.${table} enable row level security`, "i"), `RLS missing for ${table}`);
}
assert.match(migration, /grant select .* on public\.workspace_invites to authenticated/is);
assert.match(migration, /security invoker/gi);
assert.match(missionRpc, /security invoker/i);
assert.doesNotMatch(`${migration}\n${missionRpc}`, /SUPABASE_SERVICE_ROLE_KEY/i);
assert.match(hardening, /wi\.tenant_id = tenant_memberships\.tenant_id/);
assert.match(hardening, /wi\.workspace_id = workspace_memberships\.workspace_id/);
assert.match(hardening, /wi\.role = workspace_memberships\.role/);

for (const evidence of ["wrong token", "outsider", "cross-tenant membership injection", "cross-workspace role injection", "revoke_workspace_member", "anonymous", "consume_access_capsule"]) {
  assert.match(databaseTest, new RegExp(evidence.replaceAll("_", "[ _]"), "i"), `missing adversarial test: ${evidence}`);
}

assert.match(client, /#invite=/);
assert.match(client, /#capsule=/);
assert.match(page, /window\.history\.replaceState/);
assert.match(client, /AES-256-GCM/);
assert.doesNotMatch(client, /service[_. -]?role/i);
for (const surface of ["Encrypted collaboration", "Access Capsule", "Mission Mode", "Access inbox", "Fill-only is not DRM"]) {
  assert.match(page, new RegExp(surface, "i"), `missing Phase 2 surface: ${surface}`);
}

for (const endpoint of ["/workspaces", "/missions", "/access-requests", "/access-grants"]) {
  assert.match(api, new RegExp(endpoint.replaceAll("/", "\\/")), `API handler missing ${endpoint}`);
  assert.match(openapi, new RegExp(`  /v1${endpoint.replaceAll("/", "\\/")}`), `OpenAPI path missing ${endpoint}`);
}
assert.match(api, /Only ciphertext envelopes are accepted/);
assert.doesNotMatch(api, /SUPABASE_SERVICE_ROLE_KEY/);
assert.match(cli, /PASSKEY_X_ACCESS_TOKEN/);
assert.match(cli, /never accepts\s+or prints a vault password/i);
assert.match(extension, /capsule-recipient:v1/);
assert.match(extension, /consume_access_capsule/);

console.log(`Phase 2 static checks passed for ${tables.length} collaboration tables, web surfaces, API, and CLI.`);
