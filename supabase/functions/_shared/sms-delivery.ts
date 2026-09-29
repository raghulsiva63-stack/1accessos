import { decryptCredential } from "./control-plane.ts";

type SentMessageEnvelope = {
  data?: { recipients?: Array<{ message_id?: string }> };
  recipients?: Array<{ message_id?: string }>;
  meta?: { request_id?: string };
};

type AdminClient = {
  from: (table: string) => {
    select: (columns: string) => { eq: (column: string, value: string) => { maybeSingle: () => PromiseLike<{ data: Record<string, unknown> | null; error: unknown }> } };
  };
};

/** The organization's verified Sent.dm credential, decrypted in memory only. */
export async function tenantSmsCredential(admin: AdminClient, tenantId: string) {
  const { data, error } = await admin.from("tenant_sms_credentials")
    .select("encrypted_api_key,encryption_nonce,sender_profile_id,revoked_at")
    .eq("tenant_id", tenantId).maybeSingle();
  if (error || !data || data.revoked_at) throw new Error("credential_not_verified");
  const apiKey = await decryptCredential(tenantId, "sent-api-key", data.encrypted_api_key as string, data.encryption_nonce as string);
  return { apiKey, profileId: (data.sender_profile_id as string | null) ?? null };
}

export async function sendSent(apiKey: string, profileId: string | null, phone: string, text: string, idempotencyKey: string) {
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
