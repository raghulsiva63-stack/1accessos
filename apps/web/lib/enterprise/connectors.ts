import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

/**
 * Business connectors: native SIEM destinations for audit streaming, Slack / Microsoft Teams
 * alert channels and organization API keys. Credentials and webhook URLs are write-only:
 * they are sent once and never read back.
 */

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

// ---------------------------------------------------------------------------
// SIEM destinations
// ---------------------------------------------------------------------------
export type DestinationFormat = "generic" | "splunk_hec" | "datadog" | "sentinel" | "elastic";

export type DestinationField = {
  key: string; label: string; placeholder?: string; hint?: string; required?: boolean;
  kind?: "text" | "url" | "select" | "secret"; options?: { value: string; label: string }[]; pattern?: string;
  /** Stored in the destination settings (others: url / credential). */
  target: "url" | "destination" | "credential";
};

export const DATADOG_SITES = [
  { value: "datadoghq.com", label: "US1 (datadoghq.com)" }, { value: "us3.datadoghq.com", label: "US3" },
  { value: "us5.datadoghq.com", label: "US5" }, { value: "datadoghq.eu", label: "EU1 (datadoghq.eu)" },
  { value: "ap1.datadoghq.com", label: "AP1 (Japan)" }, { value: "ap2.datadoghq.com", label: "AP2 (Australia)" },
  { value: "ddog-gov.com", label: "US1-FED (ddog-gov.com)" },
];

export const DESTINATIONS: Record<DestinationFormat, { label: string; description: string; fields: DestinationField[]; docs: string }> = {
  generic: {
    label: "HTTPS webhook",
    description: "Signed JSON batches to any HTTPS endpoint (Splunk with a custom input, Logstash, Sumo Logic, Zapier, your own service).",
    docs: "Verify X-PasskeyX-Signature with the signing secret shown once after creation.",
    fields: [{ key: "url", label: "HTTPS endpoint", placeholder: "https://siem.example.com/passkey-x", kind: "url", required: true, target: "url" }],
  },
  splunk_hec: {
    label: "Splunk (HTTP Event Collector)",
    description: "One Splunk event per audit event, with your index and sourcetype.",
    docs: "Splunk → Settings → Data inputs → HTTP Event Collector → New token. Use your HEC URL (https://…:8088) and the token.",
    fields: [
      { key: "url", label: "HEC URL", placeholder: "https://splunk.example.com:8088", kind: "url", required: true, target: "url" },
      { key: "credential", label: "HEC token", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", kind: "secret", required: true, target: "credential" },
      { key: "index", label: "Index (optional)", placeholder: "security", target: "destination", pattern: "[A-Za-z0-9_\\-]{1,80}" },
      { key: "sourcetype", label: "Sourcetype (optional)", placeholder: "passkeyx:audit", target: "destination", pattern: "[A-Za-z0-9_:.\\-]{1,80}" },
    ],
  },
  datadog: {
    label: "Datadog Logs",
    description: "Logs intake with source:passkey-x, ready for Cloud SIEM detection rules.",
    docs: "Datadog → Organization settings → API keys. Pick the site your account uses.",
    fields: [
      { key: "site", label: "Datadog site", kind: "select", options: DATADOG_SITES, required: true, target: "destination" },
      { key: "credential", label: "API key", placeholder: "32 characters", kind: "secret", required: true, target: "credential" },
      { key: "service", label: "Service (optional)", placeholder: "passkey-x", target: "destination", pattern: "[a-z0-9_.\\-]{1,60}" },
      { key: "tags", label: "Extra tags (optional)", placeholder: "env:prod,team:security", target: "destination", pattern: "[A-Za-z0-9_.:\\/,\\-]{1,200}" },
    ],
  },
  sentinel: {
    label: "Microsoft Sentinel",
    description: "Azure Monitor Logs Ingestion API into a custom table in your Sentinel workspace.",
    docs: "Create a Data Collection Endpoint and Rule with a Custom-… stream (columns: TimeGenerated, Sequence, Action, TargetType, TargetId, ActorIdentityId, Metadata, EventHash, TenantId, Source), register an Entra app, give it the Monitoring Metrics Publisher role on the rule, and paste the values here.",
    fields: [
      { key: "endpoint", label: "Data collection endpoint", placeholder: "https://px-xxxx.westeurope-1.ingest.monitor.azure.com", kind: "url", required: true, target: "destination" },
      { key: "dcr_id", label: "Data collection rule immutable ID", placeholder: "dcr-0123…", required: true, target: "destination", pattern: "dcr-[0-9a-f]{32}" },
      { key: "stream", label: "Stream name", placeholder: "Custom-PasskeyXAudit", required: true, target: "destination", pattern: "Custom-[A-Za-z0-9_]{1,60}" },
      { key: "tenant_id", label: "Entra tenant (directory) ID", placeholder: "00000000-0000-0000-0000-000000000000", required: true, target: "destination", pattern: "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" },
      { key: "client_id", label: "Application (client) ID", placeholder: "00000000-0000-0000-0000-000000000000", required: true, target: "destination", pattern: "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" },
      { key: "credential", label: "Client secret", kind: "secret", required: true, target: "credential" },
    ],
  },
  elastic: {
    label: "Elastic (Elasticsearch)",
    description: "Bulk-indexes events into a data stream or index (ECS-friendly @timestamp).",
    docs: "Kibana → Stack Management → API keys → Create (privileges: create_doc on the index). Paste the encoded key.",
    fields: [
      { key: "url", label: "Elasticsearch URL", placeholder: "https://my-deployment.es.eu-west-1.aws.elastic.cloud", kind: "url", required: true, target: "url" },
      { key: "credential", label: "API key (encoded)", kind: "secret", required: true, target: "credential" },
      { key: "index", label: "Index or data stream", placeholder: "passkey-x-audit", target: "destination", pattern: "[a-z0-9][a-z0-9._\\-]{0,99}" },
    ],
  },
};

export async function createAuditDestination(tenantId: string, name: string, format: DestinationFormat, values: Record<string, string>, prefixes: string[]) {
  const spec = DESTINATIONS[format];
  const destination: Record<string, string> = {};
  let url: string | null = null;
  let credential: string | null = null;
  for (const field of spec.fields) {
    const value = (values[field.key] ?? "").trim();
    if (!value) { if (field.required) throw new Error(`${field.label} is required.`); continue; }
    if (field.target === "url") url = value;
    else if (field.target === "credential") credential = value;
    else destination[field.key] = value;
  }
  const { data, error } = await db().rpc("create_audit_destination", {
    p_tenant_id: tenantId, p_name: name.trim(), p_format: format, p_url: url, p_destination: destination,
    p_credential: credential, p_event_prefixes: prefixes,
  });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as { id: string; secret: string | null } | undefined;
  if (!row) throw new Error("The destination could not be created.");
  return row;
}

export async function replaceDestinationCredential(id: string, credential: string) {
  const { error } = await db().rpc("set_audit_destination_credential", { p_id: id, p_credential: credential.trim() });
  if (error) throw error;
}

// ---------------------------------------------------------------------------
// Slack and Microsoft Teams
// ---------------------------------------------------------------------------
export type ChatKind = "slack" | "teams";
export type ChatEvent = "alerts" | "breach_watch" | "rotation" | "weekly_report";
export type Severity = "critical" | "high" | "medium" | "low";

export type ChatChannel = {
  id: string; tenant_id: string; kind: ChatKind; name: string; url_host: string; events: ChatEvent[]; min_severity: Severity;
  enabled: boolean; created_at: string; failure_count: number; last_status: number | null; last_error: string | null;
  last_attempt_at: string | null; last_success_at: string | null;
};

export const CHAT_EVENTS: { value: ChatEvent; label: string; hint: string }[] = [
  { value: "alerts", label: "Security alerts", hint: "Sign-ins, exports, policy and admin changes, at or above the severity you choose." },
  { value: "breach_watch", label: "Breach watch", hint: "A member's work email appears in a new breach." },
  { value: "rotation", label: "Password rotation", hint: "Overdue rotation campaigns." },
  { value: "weekly_report", label: "Weekly report", hint: "Monday summary: score, two-step and passkey adoption, top risks." },
];

export const CHAT_SETUP: Record<ChatKind, { label: string; steps: string[]; placeholder: string }> = {
  slack: {
    label: "Slack",
    placeholder: "https://hooks.slack.com/services/T…/B…/…",
    steps: ["In Slack, open api.slack.com/apps → Create New App → From scratch.", "Incoming Webhooks → turn on → Add New Webhook to Workspace → pick the channel.", "Copy the webhook URL and paste it here."],
  },
  teams: {
    label: "Microsoft Teams",
    placeholder: "https://prod-00.westeurope.logic.azure.com:443/workflows/…",
    steps: ["In the Teams channel, open ⋯ → Workflows.", "Choose “Post to a channel when a webhook request is received”, pick the team and channel.", "Copy the URL the workflow shows and paste it here."],
  },
};

const CHAT_URL: Record<ChatKind, RegExp> = {
  slack: /^https:\/\/hooks\.slack\.com\/(services|triggers|workflows)\/[A-Za-z0-9/_-]{10,}$/u,
  teams: /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*\.(logic\.azure\.com|webhook\.office\.com|powerplatform\.com|powerautomate\.com)(:443)?\/[A-Za-z0-9/_.%?&=:-]{10,}$/u,
};

export function validChatUrl(kind: ChatKind, url: string) {
  return url.length <= 700 && CHAT_URL[kind].test(url.trim());
}

export async function listChatChannels(tenantId: string): Promise<ChatChannel[]> {
  const { data, error } = await db().from("chat_channels")
    .select("id,tenant_id,kind,name,url_host,events,min_severity,enabled,created_at,failure_count,last_status,last_error,last_attempt_at,last_success_at")
    .eq("tenant_id", tenantId).order("created_at");
  if (error) throw error;
  return (data ?? []) as ChatChannel[];
}

export async function createChatChannel(tenantId: string, kind: ChatKind, name: string, url: string, events: ChatEvent[], minSeverity: Severity) {
  if (!validChatUrl(kind, url)) throw new Error(`Paste the incoming webhook URL from ${CHAT_SETUP[kind].label}.`);
  const { data, error } = await db().rpc("create_chat_channel", {
    p_tenant_id: tenantId, p_kind: kind, p_name: name.trim(), p_url: url.trim(), p_events: events, p_min_severity: minSeverity,
  });
  if (error) throw error;
  return data as string;
}

export async function updateChatChannel(id: string, changes: { name?: string; events?: ChatEvent[]; minSeverity?: Severity; enabled?: boolean; url?: string }) {
  const { error } = await db().rpc("update_chat_channel", {
    p_id: id, p_name: changes.name ?? null, p_events: changes.events ?? null, p_min_severity: changes.minSeverity ?? null,
    p_enabled: changes.enabled ?? null, p_url: changes.url?.trim() || null,
  });
  if (error) throw error;
}

export async function deleteChatChannel(id: string) {
  const { error } = await db().rpc("delete_chat_channel", { p_id: id });
  if (error) throw error;
}

export async function testChatChannel(id: string) {
  const { error } = await db().rpc("test_chat_channel", { p_id: id });
  if (error) throw error;
}

export function channelHealth(channel: ChatChannel): { tone: "good" | "warn" | "bad" | "idle"; label: string } {
  if (!channel.enabled) return channel.failure_count >= 25 ? { tone: "bad", label: "Turned off after repeated failures" } : { tone: "idle", label: "Paused" };
  if (channel.failure_count > 0) return { tone: "warn", label: `${channel.failure_count} failed message${channel.failure_count === 1 ? "" : "s"}` };
  if (channel.last_success_at) return { tone: "good", label: "Posting" };
  return { tone: "idle", label: "Waiting for the first message" };
}

// ---------------------------------------------------------------------------
// Organization API keys
// ---------------------------------------------------------------------------
export type ApiScope = "audit:read" | "alerts:read" | "alerts:write" | "members:read" | "reports:read";
export type OrgApiKey = {
  id: string; name: string; prefix: string; scopes: ApiScope[]; created_at: string; expires_at: string;
  last_used_at: string | null; revoked_at: string | null;
};

export const API_SCOPES: { value: ApiScope; label: string; hint: string }[] = [
  { value: "audit:read", label: "Read audit events", hint: "GET /v1/audit-events — for SIEM pulls and compliance exports." },
  { value: "alerts:read", label: "Read security alerts", hint: "GET /v1/alerts — ticketing, Zapier, Make." },
  { value: "alerts:write", label: "Update alert status", hint: "PATCH /v1/alerts/{id} — close alerts from your ticket system." },
  { value: "members:read", label: "Read members", hint: "GET /v1/members — names, emails, roles, two-step and passkey status, score." },
  { value: "reports:read", label: "Read security reports", hint: "GET /v1/security/summary and /v1/reports/weekly." },
];

export function orgApiBaseUrl() {
  const base = process.env.NEXT_PUBLIC_SUPABASE_URL?.replace(/\/$/u, "") ?? "https://<project>.supabase.co";
  return `${base}/functions/v1/org-api/v1`;
}

export async function listOrgApiKeys(tenantId: string): Promise<OrgApiKey[]> {
  const { data, error } = await db().from("org_api_keys").select("id,name,prefix,scopes,created_at,expires_at,last_used_at,revoked_at")
    .eq("tenant_id", tenantId).order("created_at", { ascending: false });
  if (error) throw error;
  return (data ?? []) as OrgApiKey[];
}

export async function createOrgApiKey(tenantId: string, name: string, scopes: ApiScope[], expiresInDays: number) {
  const { data, error } = await db().rpc("create_org_api_key", { p_tenant_id: tenantId, p_name: name.trim(), p_scopes: scopes, p_expires_in_days: expiresInDays });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as { id: string; token: string } | undefined;
  if (!row?.token) throw new Error("The API key could not be created.");
  return row;
}

export async function revokeOrgApiKey(id: string) {
  const { error } = await db().rpc("revoke_org_api_key", { p_id: id });
  if (error) throw error;
}

export function apiKeyState(key: OrgApiKey, now = Date.now()): "active" | "expired" | "revoked" | "expiring" {
  if (key.revoked_at) return "revoked";
  const expires = Date.parse(key.expires_at);
  if (expires <= now) return "expired";
  return expires - now < 14 * 86_400_000 ? "expiring" : "active";
}

export function curlExample(base = orgApiBaseUrl()) {
  return `curl -s "${base}/audit-events?after=0&limit=100" \\
  -H "Authorization: Bearer $PASSKEY_X_API_KEY"`;
}

export function connectorErrorMessage(reason: unknown, fallback = "The change could not be saved.") {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String((reason as { message: unknown }).message) : String(reason ?? "");
  if (/is required\.$/u.test(detail)) return detail;
  if (/public https address/iu.test(detail)) return "Use a public https:// address. IP addresses, localhost and internal hostnames are not allowed.";
  if (/incoming webhook url|invalid webhook url|Paste the incoming webhook/iu.test(detail)) return detail.startsWith("Paste") ? detail : "Paste the incoming webhook URL from Slack or the Teams Workflows app.";
  if (/unknown Datadog site/iu.test(detail)) return "Choose your Datadog site.";
  if (/Sentinel|data collection|stream name/iu.test(detail)) return detail.charAt(0).toUpperCase() + detail.slice(1) + ".";
  if (/valid destination credential/iu.test(detail)) return "Paste a valid token or key for this destination.";
  if (/Splunk|Elasticsearch|Datadog/iu.test(detail)) return detail.charAt(0).toUpperCase() + detail.slice(1) + ".";
  if (/at most (\d+)/iu.test(detail)) return `You reached the limit (${detail.match(/at most (\d+)/iu)![1]}). Remove one first.`;
  if (/wait a few seconds/iu.test(detail)) return "Wait a few seconds before sending another test.";
  if (/unknown API scope/iu.test(detail)) return "Choose at least one permission.";
  if (/expire after/iu.test(detail)) return "Keys can last from 1 to 365 days.";
  if (/business organization entitlement/iu.test(detail)) return "Integrations need an active Business plan.";
  const code = typeof reason === "object" && reason !== null && "code" in reason ? String((reason as { code: unknown }).code) : "";
  if (code === "42501" || /denied|administrator role/iu.test(detail)) return "Your organization role does not allow this.";
  return fallback;
}
