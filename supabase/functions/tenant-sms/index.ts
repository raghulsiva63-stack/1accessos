import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import {
  adminSupabase, corsHeaders, decryptCredential, encryptCredential, isUuid, json,
  publicError, requireTenantManager, requireUser, sha256, toBytea,
} from "../_shared/control-plane.ts";

type SmsRequest = {
  action?: "status" | "save_credential" | "enable" | "disable" | "send_verification" | "verify_phone" | "send_test";
  tenantId?: string;
  apiKey?: string;
  senderProfileId?: string;
  phone?: string;
  code?: string;
  challengeId?: string;
  eventTypes?: string[];
};

type SentAccount = {
  type?: string;
  id?: string;
  status?: string;
  channels?: { sms?: { configured?: boolean } | Array<{ status?: string }> };
  profiles?: Array<{ id?: string; status?: string; channels?: { sms?: { configured?: boolean } | Array<{ status?: string }> } }>;
};

type SentEnvelope = {
  success?: boolean;
  data?: SentAccount;
  error?: { code?: string };
  meta?: { request_id?: string };
};

type SentMessageEnvelope = {
  data?: { recipients?: Array<{ message_id?: string }> };
  recipients?: Array<{ message_id?: string }>;
  meta?: { request_id?: string };
};

const EVENTS = new Set(["new_device", "security_alert", "access_requested", "access_approved", "recovery_changed", "billing_notice", "agent_killed"]);

function smsReady(account: SentAccount | undefined): boolean {
  const sms = account?.channels?.sms;
  if (!sms) return false;
  if (!Array.isArray(sms)) return sms.configured === true;
  return sms.some((market) => ["ACTIVE", "APPROVED", "VERIFIED", "READY", "PRODUCTION"].includes(market.status?.toUpperCase() ?? ""));
}

async function validateSentCredential(apiKey: string, requestedProfileId?: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(apiKey)) throw new Error("invalid_credential");
  const response = await fetch("https://api.sent.dm/v3/me", {
    headers: { "Accept": "application/json", "x-api-key": apiKey },
  });
  const payload = await response.json().catch(() => ({})) as SentEnvelope;
  if (!response.ok || !payload.success || !payload.data) throw new Error("invalid_credential");
  const account = payload.data;
  let profile = account;
  if (account.type === "organization" && !requestedProfileId) throw new Error("invalid_profile");
  if (account.type === "organization" && requestedProfileId) {
    profile = account.profiles?.find((entry) => entry.id === requestedProfileId) ?? {};
    if (!profile.id) throw new Error("invalid_profile");
  }
  return {
    profileId: account.type === "organization" ? requestedProfileId ?? null : null,
    hintProfileId: account.type === "profile" ? account.id ?? null : requestedProfileId ?? null,
    ready: smsReady(profile),
    accountStatus: profile.status ?? account.status ?? "unknown",
  };
}

async function credential(admin: ReturnType<typeof adminSupabase>, tenantId: string) {
  const { data, error } = await admin.from("tenant_sms_credentials")
    .select("encrypted_api_key,encryption_nonce,sender_profile_id,revoked_at")
    .eq("tenant_id", tenantId).maybeSingle();
  if (error || !data || data.revoked_at) throw new Error("credential_not_verified");
  const apiKey = await decryptCredential(tenantId, "sent-api-key", data.encrypted_api_key, data.encryption_nonce);
  return { apiKey, profileId: data.sender_profile_id as string | null };
}

async function sendSent(apiKey: string, profileId: string | null, phone: string, text: string, idempotencyKey: string) {
  const response = await fetch("https://api.sent.dm/v3/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
      "x-api-key": apiKey,
      ...(profileId ? { "x-profile-id": profileId } : {}),
    },
    body: JSON.stringify({ to: [phone], channel: ["sms"], text, sandbox: false }),
  });
  const payload = await response.json().catch(() => ({})) as SentMessageEnvelope;
  const messageId = (payload.data?.recipients ?? payload.recipients ?? [])[0]?.message_id ?? null;
  if (!response.ok || !messageId) throw new Error("sms_not_ready");
  return { messageId, requestId: payload.meta?.request_id ?? null };
}

function maskPhone(phone: string): string {
  return `${phone.slice(0, Math.min(3, phone.length - 4))}${"*".repeat(Math.max(4, phone.length - 7))}${phone.slice(-4)}`;
}

async function status(request: Request, tenantId: string) {
  const context = await requireUser(request);
  const { data: membership, error: membershipError } = await context.client.from("tenant_memberships")
    .select("role,status").eq("tenant_id", tenantId).eq("identity_id", context.identityId)
    .eq("status", "active").maybeSingle();
  if (membershipError || !membership) throw new Error("forbidden");
  const admin = adminSupabase();
  const [settingsResult, subscriptionResult, deliveriesResult] = await Promise.all([
    admin.from("tenant_notification_settings").select("sms_enabled,security_email_enabled,event_types,credential_status,sender_profile_hint,last_verified_at,updated_at").eq("tenant_id", tenantId).maybeSingle(),
    admin.from("tenant_sms_subscriptions").select("masked_phone,event_types,enabled,verified_at,updated_at").eq("tenant_id", tenantId).eq("identity_id", context.identityId).maybeSingle(),
    admin.from("notification_deliveries").select("id,event_type,status,error_code,created_at,delivered_at").eq("tenant_id", tenantId).eq("recipient_identity_id", context.identityId).order("created_at", { ascending: false }).limit(10),
  ]);
  const queryError = [settingsResult.error, subscriptionResult.error, deliveriesResult.error].find(Boolean);
  if (queryError) throw queryError;
  return json(request, 200, {
    settings: settingsResult.data ?? { sms_enabled: false, credential_status: "not_configured" },
    subscription: subscriptionResult.data,
    deliveries: deliveriesResult.data ?? [],
    canManage: ["owner", "admin"].includes(membership.role),
  });
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const body = await request.json() as SmsRequest;
    const tenantId = body.tenantId ?? "";
    if (!isUuid(tenantId) || !body.action) throw new Error("invalid_request");
    if (body.action === "status") return await status(request, tenantId);
    const admin = adminSupabase();

    if (body.action === "save_credential") {
      const context = await requireTenantManager(request, tenantId);
      const apiKey = body.apiKey?.trim() ?? "";
      const validation = await validateSentCredential(apiKey, body.senderProfileId?.trim());
      if (!validation.ready) throw new Error("sms_not_ready");
      const encrypted = await encryptCredential(tenantId, "sent-api-key", apiKey);
      const hash = await sha256(apiKey);
      const { error: credentialError } = await admin.from("tenant_sms_credentials").upsert({
        tenant_id: tenantId,
        encrypted_api_key: toBytea(encrypted.ciphertext),
        encryption_nonce: toBytea(encrypted.nonce),
        key_version: 1,
        credential_sha256: toBytea(hash),
        sender_profile_id: validation.profileId,
        created_by: context.identityId,
        rotated_at: new Date().toISOString(),
        revoked_at: null,
      });
      if (credentialError) throw credentialError;
      const { error: settingsError } = await admin.from("tenant_notification_settings").upsert({
        tenant_id: tenantId,
        sms_enabled: false,
        credential_status: "verified",
        sender_profile_hint: validation.hintProfileId ? `…${validation.hintProfileId.slice(-8)}` : "account key",
        last_verified_at: new Date().toISOString(),
        updated_by: context.identityId,
        updated_at: new Date().toISOString(),
      });
      if (settingsError) throw settingsError;
      return json(request, 200, { credentialStatus: "verified", smsReady: true, accountStatus: validation.accountStatus });
    }

    if (body.action === "enable" || body.action === "disable") {
      const context = await requireTenantManager(request, tenantId);
      const { data: settings, error } = await admin.from("tenant_notification_settings")
        .select("credential_status").eq("tenant_id", tenantId).maybeSingle();
      if (error) throw error;
      if (body.action === "enable" && settings?.credential_status !== "verified") throw new Error("credential_not_verified");
      const eventTypes = (body.eventTypes ?? []).filter((event) => EVENTS.has(event));
      const { error: updateError } = await admin.from("tenant_notification_settings").upsert({
        tenant_id: tenantId,
        sms_enabled: body.action === "enable",
        event_types: eventTypes.length ? eventTypes : ["new_device", "security_alert", "access_approved", "recovery_changed"],
        credential_status: settings?.credential_status ?? "not_configured",
        updated_by: context.identityId,
        updated_at: new Date().toISOString(),
      });
      if (updateError) throw updateError;
      return json(request, 200, { enabled: body.action === "enable" });
    }

    const context = await requireUser(request);
    const { data: membership, error: membershipError } = await context.client.from("tenant_memberships")
      .select("status").eq("tenant_id", tenantId).eq("identity_id", context.identityId).eq("status", "active").maybeSingle();
    if (membershipError || !membership) throw new Error("forbidden");
    const providerCredential = await credential(admin, tenantId);

    if (body.action === "send_verification") {
      const phone = body.phone?.trim() ?? "";
      if (!/^\+[1-9]\d{7,14}$/u.test(phone)) throw new Error("invalid_phone");
      const { data: smsSettings, error: smsSettingsError } = await admin.from("tenant_notification_settings")
        .select("sms_enabled").eq("tenant_id", tenantId).maybeSingle();
      if (smsSettingsError) throw smsSettingsError;
      if (!smsSettings?.sms_enabled) throw new Error("sms_not_ready");
      const challengeId = crypto.randomUUID();
      const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
      const phoneHash = await sha256(phone);
      const codeHash = await sha256(`${challengeId}:${code}`);
      const phoneCipher = await encryptCredential(tenantId, `sms-phone:${context.identityId}`, phone);
      // Atomic rate limit (5 per person and 60 per organization per hour) plus insert.
      const { data: allowed, error: challengeError } = await admin.rpc("create_sms_verification_challenge", {
        p_id: challengeId,
        p_tenant_id: tenantId,
        p_identity_id: context.identityId,
        p_code_sha256: toBytea(codeHash),
        p_phone_sha256: toBytea(phoneHash),
      });
      if (challengeError) throw challengeError;
      if (allowed !== true) throw new Error("verification_locked");
      const { error: subscriptionError } = await admin.from("tenant_sms_subscriptions").upsert({
        tenant_id: tenantId,
        identity_id: context.identityId,
        encrypted_phone: toBytea(phoneCipher.ciphertext),
        encryption_nonce: toBytea(phoneCipher.nonce),
        phone_sha256: toBytea(phoneHash),
        masked_phone: maskPhone(phone),
        event_types: (body.eventTypes ?? ["security_alert"]).filter((event) => EVENTS.has(event)),
        enabled: false,
        verified_at: null,
        updated_at: new Date().toISOString(),
      });
      if (subscriptionError) throw subscriptionError;
      const deliveryId = crypto.randomUUID();
      const idempotencyKey = `px_verify_${challengeId}`;
      const { error: deliveryError } = await admin.from("notification_deliveries").insert({
        id: deliveryId,
        tenant_id: tenantId,
        recipient_identity_id: context.identityId,
        channel: "sms",
        event_type: "verification",
        provider: "sent",
        idempotency_key: idempotencyKey,
        status: "queued",
      });
      if (deliveryError) throw deliveryError;
      let sent: Awaited<ReturnType<typeof sendSent>>;
      try {
        sent = await sendSent(providerCredential.apiKey, providerCredential.profileId, phone,
          `${code} is your Passkey-X notification verification code. It expires in 10 minutes.`,
          idempotencyKey);
      } catch (reason) {
        await admin.from("sms_verification_challenges").update({ status: "failed" }).eq("id", challengeId).eq("status", "pending");
        await admin.from("notification_deliveries").update({ status: "failed", error_code: "PROVIDER_SEND_FAILED", updated_at: new Date().toISOString() }).eq("id", deliveryId);
        throw reason;
      }
      const { error: acceptedError } = await admin.from("notification_deliveries").update({
        provider_message_id: sent.messageId,
        status: "accepted",
        accepted_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }).eq("id", deliveryId).eq("status", "queued");
      if (acceptedError) console.error(JSON.stringify({ function: "tenant-sms", code: "delivery_tracking_delayed" }));
      return json(request, 200, { challengeId, maskedPhone: maskPhone(phone), expiresInSeconds: 600 });
    }

    if (body.action === "verify_phone") {
      if (!isUuid(body.challengeId) || !/^\d{6}$/u.test(body.code ?? "")) throw new Error("invalid_code");
      const candidate = toBytea(await sha256(`${body.challengeId}:${body.code}`));
      const { data: checked, error } = await admin.rpc("check_sms_verification_code", {
        p_id: body.challengeId,
        p_tenant_id: tenantId,
        p_identity_id: context.identityId,
        p_candidate_sha256: candidate,
      });
      if (error) throw error;
      const result = (Array.isArray(checked) ? checked[0] : checked) as { outcome?: string; phone_sha256?: string } | null;
      if (result?.outcome === "expired") throw new Error("verification_expired");
      if (result?.outcome === "locked") throw new Error("verification_locked");
      if (result?.outcome !== "verified" || !result.phone_sha256) throw new Error("invalid_code");
      const challenge = { phone_sha256: result.phone_sha256 };
      const now = new Date().toISOString();
      const { error: subscriptionError } = await admin.from("tenant_sms_subscriptions")
        .update({ enabled: true, verified_at: now, updated_at: now })
        .eq("tenant_id", tenantId).eq("identity_id", context.identityId).eq("phone_sha256", challenge.phone_sha256);
      if (subscriptionError) throw subscriptionError;
      return json(request, 200, { verified: true, enabled: true });
    }

    if (body.action === "send_test") {
      const { data: settings, error: settingsError } = await admin.from("tenant_notification_settings").select("sms_enabled").eq("tenant_id", tenantId).maybeSingle();
      if (settingsError) throw settingsError;
      if (!settings?.sms_enabled) throw new Error("sms_not_ready");
      const { data: subscription, error } = await admin.from("tenant_sms_subscriptions")
        .select("encrypted_phone,encryption_nonce,enabled,verified_at")
        .eq("tenant_id", tenantId).eq("identity_id", context.identityId).maybeSingle();
      if (error || !subscription?.enabled || !subscription.verified_at) throw new Error("sms_not_ready");
      const phone = await decryptCredential(tenantId, `sms-phone:${context.identityId}`, subscription.encrypted_phone, subscription.encryption_nonce);
      const deliveryId = crypto.randomUUID();
      const idempotencyKey = `px_test_${deliveryId}`;
      const { error: deliveryError } = await admin.from("notification_deliveries").insert({
        id: deliveryId,tenant_id: tenantId,recipient_identity_id: context.identityId,channel: "sms",
        event_type: "security_alert",provider: "sent",idempotency_key: idempotencyKey,
        status: "queued",
      });
      if (deliveryError) throw deliveryError;
      let sent: Awaited<ReturnType<typeof sendSent>>;
      try {
        sent = await sendSent(providerCredential.apiKey, providerCredential.profileId, phone,
          "Passkey-X security notifications are enabled for this device.", idempotencyKey);
      } catch (reason) {
        await admin.from("notification_deliveries").update({ status: "failed",error_code: "PROVIDER_SEND_FAILED",updated_at: new Date().toISOString() }).eq("id", deliveryId);
        throw reason;
      }
      const { error: acceptedError } = await admin.from("notification_deliveries").update({
        provider_message_id: sent.messageId,status: "accepted",accepted_at: new Date().toISOString(),updated_at: new Date().toISOString(),
      }).eq("id", deliveryId).eq("status", "queued");
      if (acceptedError) console.error(JSON.stringify({ function: "tenant-sms", code: "delivery_tracking_delayed" }));
      return json(request, 200, { accepted: true, deliveryId });
    }
    throw new Error("invalid_request");
  } catch (reason) {
    const error = publicError(reason);
    console.error(JSON.stringify({ function: "tenant-sms", code: error.code }));
    return json(request, error.status, { error: error.code });
  }
});
