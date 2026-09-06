import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

const [migration, hardening, sms, control, lifecycle, webhook, ai, notifications, runtime, deletion, page, netlify] = await Promise.all([
  read("supabase/migrations/20260906102200_web_v22_runtime_control_plane.sql"),
  read("supabase/migrations/20260906113000_web_v22_integrity_hardening.sql"),
  read("supabase/functions/tenant-sms/index.ts"),
  read("supabase/functions/_shared/control-plane.ts"),
  read("supabase/functions/account-lifecycle/index.ts"),
  read("supabase/functions/sent-webhook/index.ts"),
  read("apps/web/netlify/functions/security-advice.mts"),
  read("apps/web/components/notifications-view.tsx"),
  read("apps/web/components/runtime-access-view.tsx"),
  read("apps/web/components/account-deletion-card.tsx"),
  read("apps/web/app/page.tsx"),
  read("netlify.toml"),
]);

test("v2.2 control-plane tables are RLS protected and credential tables stay backend-only", () => {
  const tables = [
    "account_deletion_requests", "tenant_notification_settings", "tenant_sms_credentials",
    "tenant_sms_subscriptions", "notification_deliveries", "sms_verification_challenges",
    "notification_delivery_events", "ai_assistant_requests", "runtime_activation",
    "privileged_resources", "agent_profiles", "access_simulations", "privilege_requests",
    "privilege_sessions", "credential_leases", "agent_task_capsules",
    "access_graph_snapshots", "session_evidence",
  ];
  for (const table of tables) assert.match(migration, new RegExp(`alter table public\\.${table} enable row level security`, "u"));
  assert.doesNotMatch(migration, /grant select[^;]*tenant_sms_credentials[^;]*authenticated/isu);
  assert.doesNotMatch(migration, /grant select[^;]*tenant_sms_subscriptions[^;]*authenticated/isu);
  assert.doesNotMatch(migration, /grant select[^;]*credential_leases[^;]*authenticated/isu);
  assert.match(migration, /not issuance_enabled or \([\s\S]*review_status = 'accepted'[\s\S]*adapter_status = 'production_certified'/u);
  assert.match(hardening, /private\.valid_runtime_scopes/u);
  assert.match(hardening, /agent_task_capsules_validate/u);
  assert.match(hardening, /revoke insert,update,delete on public\.agent_task_capsules from authenticated/u);
});

test("tenant SMS is credential-isolated, production-only, verified, idempotent, and webhook observed", () => {
  assert.match(control, /TENANT_CREDENTIAL_MASTER_KEY/u);
  assert.match(sms, /https:\/\/api\.sent\.dm\/v3\/me/u);
  assert.match(sms, /"Idempotency-Key"/u);
  assert.match(sms, /sandbox:\s*false/u);
  assert.match(sms, /send_verification/u);
  assert.match(sms, /verify_phone/u);
  assert.match(sms, /credential_status:\s*"verified"/u);
  assert.match(webhook, /apply_sent_notification_event/u);
  assert.doesNotMatch(sms, /console\.(?:log|error)\([^\n]*(?:apiKey|phone|body\.code|challengeId)/u);
  assert.match(notifications, /write-only/iu);
  assert.match(notifications, /accepted by Sent for delivery/iu);
});

test("account deletion requires fresh reauthentication, typed intent, storage cleanup, and Auth deletion", () => {
  assert.match(deletion, /DELETE MY ACCOUNT/u);
  assert.match(deletion, /signInWithPassword/u);
  assert.match(deletion, /TurnstileCheck/u);
  assert.match(lifecycle, /recentlyAuthenticated/u);
  assert.match(lifecycle, /vault-attachments/u);
  assert.match(lifecycle, /complete_account_deletion/u);
  assert.match(lifecycle, /auth\.admin\.deleteUser/u);
  assert.match(lifecycle, /finalize_account_deletion/u);
  assert.match(migration, /ownership_transfer_required/u);
  assert.match(migration, /delete from public\.account_crypto_profiles/u);
  assert.match(hardening, /identities_cleanup_deleted_human_memberships/u);
});

test("Access Twin, agents, privileged approvals, and Flight Recorder stay fail-closed", () => {
  assert.match(migration, /create or replace function public\.simulate_access_impact/u);
  assert.match(migration, /'effect','preview_only'/u);
  assert.match(migration, /create or replace function public\.kill_agent/u);
  assert.match(hardening, /create or replace function public\.create_agent_task_capsule/u);
  assert.match(hardening, /task capsule resource is outside tenant/u);
  assert.match(runtime, /Create one-hour capsule/u);
  assert.match(runtime, /fail-closed state/u);
  assert.match(migration, /private\.runtime_evidence_event/u);
  assert.match(migration, /lower\(event_metadata::text\).*command_output/su);
  assert.match(runtime, /Preview blast radius/u);
  assert.match(runtime, /Credential issuance is fail-closed/u);
  assert.match(runtime, /Flight Recorder/u);
  assert.match(page, /Runtime & Twin/u);
});

test("hosted AI sends only approved aggregate counts through the authenticated Netlify Function", () => {
  assert.match(ai, /model:\s*"gpt-5-mini"/u);
  assert.match(ai, /approved_derived_metrics/u);
  assert.match(ai, /aggregate counts/iu);
  assert.match(ai, /begin_ai_assistant_request/u);
  assert.match(ai, /rateLimit/u);
  assert.doesNotMatch(ai, /vault_items|vault_item_revisions|raw_prompt/u);
});

test("production Turnstile site key is public config while its secret is absent", () => {
  assert.match(netlify, /NEXT_PUBLIC_TURNSTILE_SITE_KEY\s*=\s*"0x[0-9A-Za-z_-]+"/u);
  assert.doesNotMatch(netlify, /TURNSTILE_SECRET|CAPTCHA_SECRET/u);
  assert.match(page, /NotificationsView/u);
  assert.match(page, /action="vault-setup"/u);
  assert.match(page, /Create vault and continue/u);
});
