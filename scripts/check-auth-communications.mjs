import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const [page, client, netlify, config, smsHook, sentWebhook, sentShared, migration, checkpoint] = await Promise.all([
  readFile("apps/web/app/page.tsx", "utf8"),
  readFile("apps/web/lib/supabase/client.ts", "utf8"),
  readFile("netlify.toml", "utf8"),
  readFile("supabase/config.toml", "utf8"),
  readFile("supabase/functions/sent-sms-hook/index.ts", "utf8"),
  readFile("supabase/functions/sent-webhook/index.ts", "utf8"),
  readFile("supabase/functions/_shared/sent.ts", "utf8"),
  readFile("supabase/migrations/20260905080725_auth_sms_delivery_observability.sql", "utf8"),
  readFile("docs/security/auth-communications.md", "utf8"),
]);

for (const call of ["auth.mfa.enroll", "auth.mfa.challenge", "auth.mfa.verify", "auth.mfa.unenroll", "getAuthenticatorAssuranceLevel"]) {
  assert.match(page, new RegExp(call.replaceAll(".", "\\."), "u"));
}
assert.match(page, /factorType:\s*"phone"/u);
assert.match(page, /channel:\s*"sms"/u);
assert.doesNotMatch(page, /signInWithOtp\(\s*\{\s*phone/u, "phone must not become the primary sign-in identifier");
assert.match(page, /cannot reset the vault password, decrypt vault data, or replace the recovery key/u);
assert.match(client, /NEXT_PUBLIC_PHONE_MFA_ENABLED/u);
assert.match(netlify, /NEXT_PUBLIC_PHONE_MFA_ENABLED\s*=\s*"false"/u);
assert.doesNotMatch(netlify, /NEXT_PUBLIC_PHONE_MFA_ENABLED\s*=\s*"true"/u, "phone MFA must stay hidden until live delivery evidence exists");

assert.match(config, /\[functions\.sent-sms-hook\][\s\S]*verify_jwt\s*=\s*false/u);
assert.match(config, /\[functions\.sent-webhook\][\s\S]*verify_jwt\s*=\s*false/u);
assert.match(smsHook, /standardwebhooks@1\.0\.0/u);
assert.match(smsHook, /SEND_SMS_HOOK_SECRET/u);
assert.match(smsHook, /"x-api-key"/u);
assert.match(smsHook, /"Idempotency-Key"/u);
assert.match(smsHook, /channel:\s*\["sms"\]/u);
assert.match(smsHook, /sandbox/u);
assert.doesNotMatch(smsHook, /console\.(?:log|error)\([^\n]*(?:phone|otp)/u, "phone numbers and OTPs must not be logged");

for (const boundary of ["x-webhook-id", "x-webhook-timestamp", "x-webhook-signature", "HMAC", "300"]) {
  assert.match(sentShared, new RegExp(boundary, "u"));
}
assert.match(sentWebhook, /request\.arrayBuffer\(\)/u);
assert.match(sentWebhook, /apply_sent_sms_delivery_event/u);
assert.match(migration, /enable row level security/gu);
assert.match(migration, /auth_sms_deliveries_browser_deny/u);
assert.match(migration, /auth_sms_delivery_events_browser_deny/u);
assert.doesNotMatch(migration, /\b(?:phone|otp|message_body)\s+(?:text|varchar)/iu, "delivery tables must not store phone, OTP, or message content");
assert.match(checkpoint, /Phone number collection/u);
assert.match(checkpoint, /not a runtime credential/u);

console.log("Email/SMS boundary, optional phone MFA, signed hooks, idempotency, RLS, and vault-recovery separation checks passed.");
