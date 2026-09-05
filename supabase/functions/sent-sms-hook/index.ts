import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { Webhook } from "https://esm.sh/standardwebhooks@1.0.0";
import { adminSupabase, bytesToHex, json, optional, required, safeCode, sha256, sha256Text } from "../_shared/sent.ts";

type SmsHook = {
  user?: { id?: string; phone?: string };
  sms?: { otp?: string };
};

type SentResponse = {
  data?: { recipients?: Array<{ message_id?: string }> };
  recipients?: Array<{ message_id?: string }>;
  meta?: { request_id?: string };
};

function verifySupabaseHook(rawBody: string, headers: Headers): SmsHook {
  const configured = required("SEND_SMS_HOOK_SECRET").split("|").map((value) => value.trim()).filter(Boolean);
  for (const candidate of configured) {
    try {
      const secret = candidate.replace(/^v1,whsec_/u, "");
      return new Webhook(secret).verify(rawBody, Object.fromEntries(headers)) as SmsHook;
    } catch { /* try the rotation candidate */ }
  }
  throw new Error("invalid_signature");
}

function sentResult(payload: SentResponse): { messageId: string | null; requestId: string | null } {
  const recipients = payload.data?.recipients ?? payload.recipients ?? [];
  return { messageId: recipients[0]?.message_id ?? null, requestId: payload.meta?.request_id ?? null };
}

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });

  let hookId: string | null = null;
  try {
    const rawBody = await request.text();
    const verified = verifySupabaseHook(rawBody, request.headers);
    hookId = request.headers.get("webhook-id")?.trim() ?? null;
    const userId = verified.user?.id?.trim() ?? "";
    const phone = verified.user?.phone?.trim() ?? "";
    const otp = verified.sms?.otp?.trim() ?? "";
    if (!hookId || hookId.length > 255 || !/^[0-9a-f-]{36}$/iu.test(userId) || !/^\+[1-9]\d{7,14}$/u.test(phone) || !/^\d{6,10}$/u.test(otp)) {
      throw new Error("invalid_payload");
    }

    const rawHash = bytesToHex(await sha256(new TextEncoder().encode(rawBody)));
    const admin = adminSupabase();
    const initial = await admin.from("auth_sms_deliveries").insert({
      auth_hook_id: hookId,
      auth_user_id: userId,
      payload_sha256: `\\x${rawHash}`,
      provider_status: "pending",
    }).select("id,payload_sha256,provider_status").maybeSingle();

    if (initial.error?.code === "23505") {
      const existing = await admin.from("auth_sms_deliveries")
        .select("payload_sha256,provider_status")
        .eq("auth_hook_id", hookId)
        .single();
      if (existing.error) throw existing.error;
      const stored = String(existing.data.payload_sha256).replace(/^\\x/u, "").toLowerCase();
      if (stored !== rawHash) throw new Error("invalid_payload");
      if (!["pending", "failed", "provider_unavailable", "sandbox_validated"].includes(existing.data.provider_status)) return json(200, {});
    } else if (initial.error) throw initial.error;

    const apiKey = required("SENT_DM_API_KEY");
    const sandboxSetting = required("SENT_DM_SMS_SANDBOX");
    if (sandboxSetting !== "true" && sandboxSetting !== "false") throw new Error("sms_not_configured");
    const sandbox = sandboxSetting === "true";
    const idempotencyKey = `px_auth_${(await sha256Text(hookId)).slice(0, 48)}`;
    const providerResponse = await fetch("https://api.sent.dm/v3/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
        "x-api-key": apiKey,
      },
      body: JSON.stringify({
        to: [phone],
        channel: ["sms"],
        text: `${otp} is your Passkey-X security code. It expires soon. Never share this code.`,
        sandbox,
      }),
    });

    const responseBody = await providerResponse.json().catch(() => ({})) as SentResponse;
    const result = sentResult(responseBody);
    if (!providerResponse.ok) {
      await admin.from("auth_sms_deliveries").update({ provider_status: "provider_unavailable", updated_at: new Date().toISOString() }).eq("auth_hook_id", hookId);
      console.error(JSON.stringify({ function: "sent-sms-hook", hookId, providerStatus: providerResponse.status, requestId: result.requestId }));
      return json(providerResponse.status === 429 ? 503 : 502, { error: "provider_unavailable" });
    }
    if (!sandbox && !result.messageId) throw new Error("provider_unavailable");

    const status = sandbox ? "sandbox_validated" : "accepted";
    const update = await admin.from("auth_sms_deliveries").update({
      provider_message_id: result.messageId,
      provider_request_id: result.requestId,
      provider_status: status,
      updated_at: new Date().toISOString(),
    }).eq("auth_hook_id", hookId);
    if (update.error) throw update.error;

    console.log(JSON.stringify({ function: "sent-sms-hook", hookId, providerStatus: providerResponse.status, requestId: result.requestId, sandbox }));
    if (sandbox) return json(503, { error: "sms_sandbox_only" });
    return json(200, {});
  } catch (reason) {
    const code = safeCode(reason);
    console.error(JSON.stringify({ function: "sent-sms-hook", hookId, code }));
    return json(code === "invalid_signature" ? 401 : code === "invalid_payload" ? 400 : 503, { error: code });
  }
});
