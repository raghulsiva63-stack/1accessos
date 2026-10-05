import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, decryptCredential } from "../_shared/control-plane.ts";
import { renderNotification, SMS_EVENTS } from "../_shared/security-templates.ts";
import { sendSent, tenantSmsCredential } from "../_shared/sms-delivery.ts";

/**
 * Security notification worker. pg_cron wakes it every minute (only when there is work) with a
 * one-time token, which it trades for a batch of queued notifications. Email goes out through
 * ZeptoMail (ZEPTOMAIL_TOKEN, optional ZEPTOMAIL_API_HOST such as api.zeptomail.in) or Resend
 * (RESEND_API_KEY), from NOTIFY_FROM_EMAIL; SMS through the organization's own verified Sent.dm
 * credential when the organization and the person turned SMS on for that event.
 * Called without a Supabase JWT (verify_jwt = false); the token is the credential.
 */

type Claimed = {
  id: number; tenant_id: string | null; recipient_identity_id: string; email: string | null;
  event_type: string; template: string; params: Record<string, unknown>; attempts: number;
};

function reply(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

/** "Name <address>" or a bare address. */
export function parseSender(value: string): { name: string; address: string } {
  const match = /^\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/u.exec(value);
  if (match) return { name: match[1].replace(/^"|"$/gu, "").trim(), address: match[2] };
  return { name: "Passkey-X Security", address: value.trim() };
}

// ZeptoMail (Zoho) data centres. The Send Mail token is the same one used as the SMTP password.
const ZEPTO_HOSTS = new Set(["api.zeptomail.com", "api.zeptomail.in", "api.zeptomail.eu", "api.zeptomail.com.au", "api.zeptomail.jp", "api.zeptomail.ca", "api.zeptomail.sa", "api.zeptomail.com.cn"]);

/** Which email service is configured: ZeptoMail (ZEPTOMAIL_TOKEN) first, then Resend (RESEND_API_KEY). */
export function emailProvider(): "zeptomail" | "resend" | null {
  if (Deno.env.get("ZEPTOMAIL_TOKEN")?.trim()) return "zeptomail";
  if (Deno.env.get("RESEND_API_KEY")?.trim()) return "resend";
  return null;
}

async function sendEmail(to: string, subject: string, html: string, text: string, idempotencyKey: string) {
  const from = Deno.env.get("NOTIFY_FROM_EMAIL")?.trim() || "Passkey-X Security <security@passkey-x.com>";
  const provider = emailProvider();
  if (provider === "zeptomail") {
    const token = Deno.env.get("ZEPTOMAIL_TOKEN")!.trim().replace(/^Zoho-enczapikey\s+/iu, "");
    const host = (Deno.env.get("ZEPTOMAIL_API_HOST")?.trim() || "api.zeptomail.com").toLowerCase();
    if (!ZEPTO_HOSTS.has(host)) throw new Error("EMAIL_NOT_CONFIGURED");
    const sender = parseSender(from);
    const response = await fetch(`https://${host}/v1.1/email`, {
      method: "POST",
      headers: { "Authorization": `Zoho-enczapikey ${token}`, "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        from: { address: sender.address, name: sender.name },
        to: [{ email_address: { address: to } }],
        subject, htmlbody: html, textbody: text, client_reference: idempotencyKey,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const payload = await response.json().catch(() => ({})) as { request_id?: string };
    if (!response.ok) throw new Error(response.status === 429 ? "EMAIL_RATE_LIMITED" : "EMAIL_SEND_FAILED");
    return { provider, id: payload.request_id ?? idempotencyKey };
  }
  if (provider === "resend") {
    const key = Deno.env.get("RESEND_API_KEY")!.trim();
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
      body: JSON.stringify({ from, to: [to], subject, html, text }),
      signal: AbortSignal.timeout(8_000),
    });
    const payload = await response.json().catch(() => ({})) as { id?: string };
    if (!response.ok || !payload.id) throw new Error(response.status === 429 ? "EMAIL_RATE_LIMITED" : "EMAIL_SEND_FAILED");
    return { provider, id: payload.id };
  }
  throw new Error("EMAIL_NOT_CONFIGURED");
}

type Admin = ReturnType<typeof adminSupabase>;

async function track(admin: Admin, row: Claimed, channel: "email" | "sms", provider: string, status: "accepted" | "failed", messageId: string | null, errorCode: string | null) {
  if (!row.tenant_id) return;
  await admin.from("notification_deliveries").upsert({
    tenant_id: row.tenant_id,
    recipient_identity_id: row.recipient_identity_id,
    channel,
    event_type: row.event_type,
    provider,
    idempotency_key: `px_${channel}_outbox_${row.id}`,
    provider_message_id: messageId,
    status,
    error_code: errorCode,
    accepted_at: status === "accepted" ? new Date().toISOString() : null,
    updated_at: new Date().toISOString(),
  }, { onConflict: "tenant_id,idempotency_key" });
}

async function smsTarget(admin: Admin, row: Claimed): Promise<string | null> {
  if (!row.tenant_id || !SMS_EVENTS.has(row.event_type)) return null;
  const { data: settings } = await admin.from("tenant_notification_settings")
    .select("sms_enabled,event_types").eq("tenant_id", row.tenant_id).maybeSingle();
  if (!settings?.sms_enabled || !(settings.event_types as string[]).includes(row.event_type)) return null;
  const { data: subscription } = await admin.from("tenant_sms_subscriptions")
    .select("encrypted_phone,encryption_nonce,enabled,verified_at,event_types")
    .eq("tenant_id", row.tenant_id).eq("identity_id", row.recipient_identity_id).maybeSingle();
  if (!subscription?.enabled || !subscription.verified_at || !(subscription.event_types as string[]).includes(row.event_type)) return null;
  return await decryptCredential(row.tenant_id, `sms-phone:${row.recipient_identity_id}`, subscription.encrypted_phone as string, subscription.encryption_nonce as string);
}

async function deliver(admin: Admin, row: Claimed, appUrl: string): Promise<{ status: "sent" | "failed" | "skipped" | "pending"; error: string | null }> {
  const message = renderNotification(row.template, row.params ?? {}, appUrl);
  if (!message) return { status: "skipped", error: "UNKNOWN_TEMPLATE" };
  let delivered = false;
  let lastError: string | null = null;

  if (row.email) {
    try {
      const sent = await sendEmail(row.email, message.subject, message.html, message.text, `px-outbox-${row.id}`);
      await track(admin, row, "email", sent.provider, "accepted", sent.id, null);
      delivered = true;
    } catch (reason) {
      lastError = reason instanceof Error && /^[A-Z_]{3,40}$/u.test(reason.message) ? reason.message : "EMAIL_SEND_FAILED";
      if (lastError !== "EMAIL_NOT_CONFIGURED") await track(admin, row, "email", emailProvider() ?? "resend", "failed", null, lastError);
    }
  }

  if (message.sms) {
    try {
      const phone = await smsTarget(admin, row);
      if (phone && row.tenant_id) {
        const credential = await tenantSmsCredential(admin, row.tenant_id);
        const sent = await sendSent(credential.apiKey, credential.profileId, phone, message.sms, `px_outbox_${row.id}`);
        await track(admin, row, "sms", "sent", "accepted", sent.messageId, null);
        delivered = true;
      }
    } catch {
      lastError = "SMS_SEND_FAILED";
      await track(admin, row, "sms", "sent", "failed", null, lastError);
    }
  }

  if (delivered) return { status: "sent", error: null };
  if (lastError === "EMAIL_NOT_CONFIGURED" || !row.email) return { status: "skipped", error: lastError ?? "NO_EMAIL" };
  // Transient failures are retried by the next run (up to 5 attempts).
  return { status: row.attempts >= 5 ? "failed" : "pending", error: lastError };
}

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return reply(405, { error: "method_not_allowed" });
  let body: { token?: unknown };
  try { body = await request.json(); } catch { return reply(400, { error: "invalid_request" }); }
  if (typeof body.token !== "string" || !/^[0-9a-f]{64}$/u.test(body.token)) return reply(400, { error: "invalid_request" });

  const admin = adminSupabase();
  const { data, error } = await admin.rpc("claim_notification_batch", { p_token: body.token, p_limit: 50 });
  if (error) return reply(403, { error: "invalid_token" });
  const rows = (data ?? []) as Claimed[];
  const appUrl = (Deno.env.get("APP_URL")?.trim() || "https://passkey-x.com").replace(/\/+$/u, "");
  const results = { sent: 0, skipped: 0, retry: 0, failed: 0 };
  for (const row of rows) {
    let outcome: Awaited<ReturnType<typeof deliver>>;
    try { outcome = await deliver(admin, row, appUrl); } catch { outcome = { status: "pending", error: "WORKER_ERROR" }; }
    await admin.rpc("complete_notification", { p_id: row.id, p_status: outcome.status, p_error: outcome.error });
    if (outcome.status === "sent") results.sent += 1;
    else if (outcome.status === "skipped") results.skipped += 1;
    else if (outcome.status === "pending") results.retry += 1;
    else results.failed += 1;
  }
  console.log(JSON.stringify({ function: "security-notify", claimed: rows.length, ...results }));
  return reply(200, { claimed: rows.length, ...results });
});
