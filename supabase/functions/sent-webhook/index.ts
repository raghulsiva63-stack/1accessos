import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, bytesToHex, json, safeCode, sha256, verifySentWebhook } from "../_shared/sent.ts";

type SentEvent = {
  field?: string;
  event?: string;
  value?: {
    message_id?: string;
    message_status?: string;
    channel?: string | null;
    updated_at?: string;
  };
};

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const rawBody = new Uint8Array(await request.arrayBuffer());
    await verifySentWebhook(request.headers, rawBody);
    const event = JSON.parse(new TextDecoder().decode(rawBody)) as SentEvent;

    if (event.field !== "message" || !event.event?.startsWith("message.") || event.event === "message.received") {
      return json(200, { received: true });
    }

    const messageId = event.value?.message_id?.trim() ?? "";
    const status = event.value?.message_status?.trim() ?? "";
    const channel = event.value?.channel?.trim() ?? "";
    const happenedAt = event.value?.updated_at?.trim() ?? "";
    if (messageId.length < 8 || status.length < 2 || !Number.isFinite(Date.parse(happenedAt))) throw new Error("invalid_payload");

    const digest = bytesToHex(await sha256(rawBody));
    const admin = adminSupabase();
    const { data: authMapped, error } = await admin.rpc("apply_sent_sms_delivery_event", {
      p_provider_message_id: messageId,
      p_event_name: event.event,
      p_provider_status: status,
      p_channel: channel,
      p_happened_at: happenedAt,
      p_payload_sha256: `\\x${digest}`,
    });
    if (error) throw error;
    const { data: notificationMapped, error: notificationError } = await admin.rpc("apply_sent_notification_event", {
      p_provider_message_id: messageId,
      p_event_name: event.event,
      p_provider_status: status,
      p_happened_at: happenedAt,
      p_payload_sha256: `\\x${digest}`,
    });
    if (notificationError) throw notificationError;

    console.log(JSON.stringify({ function: "sent-webhook", event: event.event, authMapped: authMapped === true, notificationMapped: notificationMapped === true }));
    return json(200, { received: true });
  } catch (reason) {
    const code = safeCode(reason);
    console.error(JSON.stringify({ function: "sent-webhook", code }));
    return json(code === "invalid_signature" || code === "stale_signature" ? 401 : code === "invalid_payload" ? 400 : 503, { error: code });
  }
});
