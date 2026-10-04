/**
 * Shapes outbound deliveries for vendor destinations (used by the audit-relay edge function).
 * Pure functions: no network, no secrets in logs. The relay adds authentication headers here
 * and fetches OAuth tokens (Sentinel) separately.
 */

export type AuditEvent = {
  sequence: number; occurred_at: string; action: string; target_type?: string | null; target_id?: string | null;
  actor_identity_id?: string | null; metadata?: Record<string, unknown> | null; hash_version?: number; event_hash?: string;
};
export type AuditPayload = { source?: string; type?: string; tenant_id?: string; webhook_id?: string; events?: AuditEvent[] };
export type Shaped = { headers: Record<string, string>; body: string };

export const CHAT_FORMATS = new Set(["slack", "teams"]);
export const SIEM_FORMATS = new Set(["splunk_hec", "datadog", "sentinel", "elastic"]);

function events(payload: AuditPayload): AuditEvent[] {
  return Array.isArray(payload.events) ? payload.events.slice(0, 500) : [];
}

function epochSeconds(value: string) {
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? Math.round(ms / 10) / 100 : Math.round(Date.now() / 10) / 100;
}

function flat(event: AuditEvent, tenantId: string | undefined) {
  return {
    sequence: event.sequence, action: event.action, target_type: event.target_type ?? null, target_id: event.target_id ?? null,
    actor_identity_id: event.actor_identity_id ?? null, metadata: event.metadata ?? {}, event_hash: event.event_hash ?? null,
    occurred_at: event.occurred_at, tenant_id: tenantId ?? null,
  };
}

/** SIEM shapes. `credential` is the destination secret (HEC token, API key, bearer token). */
export function shapeSiem(format: string, config: Record<string, unknown>, credential: string, payload: AuditPayload): Shaped {
  const tenant = payload.tenant_id;
  const list = events(payload);
  if (format === "splunk_hec") {
    const body = list.map((event) => JSON.stringify({
      time: epochSeconds(event.occurred_at), host: "passkey-x", source: "passkey-x",
      sourcetype: typeof config.sourcetype === "string" ? config.sourcetype : "passkeyx:audit",
      ...(typeof config.index === "string" ? { index: config.index } : {}),
      event: flat(event, tenant),
    })).join("\n");
    return { headers: { "Content-Type": "application/json", Authorization: `Splunk ${credential}` }, body };
  }
  if (format === "datadog") {
    const tags = ["source:passkey-x", ...(tenant ? [`tenant:${tenant}`] : []), ...(typeof config.tags === "string" && config.tags ? [config.tags] : [])].join(",");
    const body = JSON.stringify(list.map((event) => ({
      ddsource: "passkey-x", service: typeof config.service === "string" ? config.service : "passkey-x", hostname: "passkey-x",
      ddtags: tags, message: event.action, timestamp: Date.parse(event.occurred_at) || Date.now(), ...flat(event, tenant),
    })));
    return { headers: { "Content-Type": "application/json", "DD-API-KEY": credential }, body };
  }
  if (format === "sentinel") {
    const body = JSON.stringify(list.map((event) => ({
      TimeGenerated: event.occurred_at, Sequence: event.sequence, Action: event.action, TargetType: event.target_type ?? "",
      TargetId: event.target_id ?? "", ActorIdentityId: event.actor_identity_id ?? "", Metadata: event.metadata ?? {},
      EventHash: event.event_hash ?? "", TenantId: tenant ?? "", Source: "Passkey-X",
    })));
    return { headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` }, body };
  }
  if (format === "elastic") {
    const index = typeof config.index === "string" ? config.index : "passkey-x-audit";
    const body = list.map((event) => `${JSON.stringify({ create: { _index: index } })}\n${JSON.stringify({ "@timestamp": event.occurred_at, ...flat(event, tenant), event: { dataset: "passkey_x.audit" } })}\n`).join("");
    return { headers: { "Content-Type": "application/x-ndjson", Authorization: `ApiKey ${credential}` }, body };
  }
  throw new Error("unsupported_format");
}

/** Elasticsearch answers 200 for a bulk request even when documents were rejected. */
export function elasticBulkFailed(responseText: string) {
  try { return Boolean((JSON.parse(responseText) as { errors?: boolean }).errors); } catch { return true; }
}

// ---------------------------------------------------------------------------
// Chat messages
// ---------------------------------------------------------------------------
export type ChatPayload = {
  event?: string; app_url?: string; title?: string; severity?: string; kind?: string; channel?: string;
  score?: number | null; score_week_ago?: number | null; members?: number | null; two_step_pct?: number | null;
  passkey_pct?: number | null; alerts_new_7d?: number | null; top_risks?: { key?: string; count?: number }[] | null;
};

const RISK_LABELS: Record<string, string> = {
  critical_alerts: "critical alerts open", breached_passwords: "passwords found in known breaches",
  members_in_breaches: "members whose work email was in a breach", exposed_secrets: "secrets stored in notes",
  members_without_two_step: "members without two-step verification", reused_passwords: "reused passwords",
  high_alerts: "high alerts open", lookalike_sites: "look-alike websites saved", weak_passwords: "weak passwords",
  rotation_overdue: "overdue password rotations", members_not_reporting: "members not reporting yet",
};

const SEVERITY_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

function clip(value: unknown, max: number) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f]/gu, " ").slice(0, max);
}

function appLink(payload: ChatPayload, tab: string) {
  let base = "https://passkey-x.com";
  try {
    const url = new URL(payload.app_url ?? base);
    if (url.protocol === "https:") base = url.origin;
  } catch { /* keep default */ }
  return `${base}/?view=admin&tab=${tab}`;
}

export type ChatMessage = { heading: string; lines: string[]; link: string; linkLabel: string; tone: "attention" | "warning" | "good" | "default" };

export function chatMessage(payload: ChatPayload): ChatMessage {
  const event = payload.event ?? "alerts";
  if (event === "test") {
    return { heading: "Passkey-X is connected", lines: [`Security notifications for this organization will appear here${payload.channel ? ` (${clip(payload.channel, 80)})` : ""}.`],
      link: appLink(payload, "integrations"), linkLabel: "Open integrations", tone: "good" };
  }
  if (event === "weekly_report") {
    const score = typeof payload.score === "number" ? payload.score : null;
    const before = typeof payload.score_week_ago === "number" ? payload.score_week_ago : null;
    const change = score !== null && before !== null ? score - before : null;
    const lines = [
      score === null ? "No security score yet — members appear once they open Passkey-X." : `Security score ${score}/100${change === null ? "" : change === 0 ? " (no change)" : ` (${change > 0 ? "+" : ""}${change} since last week)`}.`,
      ...(typeof payload.two_step_pct === "number" ? [`${payload.two_step_pct}% of members use two-step verification, ${payload.passkey_pct ?? 0}% use passkeys.`] : []),
      ...(typeof payload.alerts_new_7d === "number" ? [`${payload.alerts_new_7d} new alert${payload.alerts_new_7d === 1 ? "" : "s"} this week.`] : []),
      ...(payload.top_risks ?? []).slice(0, 3).filter((risk) => risk.key && RISK_LABELS[risk.key]).map((risk) => `• ${Number(risk.count ?? 0)} ${RISK_LABELS[risk.key!]}`),
    ];
    return { heading: "Weekly security report", lines, link: appLink(payload, "reports"), linkLabel: "Open the report",
      tone: change !== null && change < 0 ? "warning" : "default" };
  }
  const severity = SEVERITY_LABEL[payload.severity ?? ""] ?? "Alert";
  const tab = event === "breach_watch" ? "breach" : event === "rotation" ? "rotation" : "alerts";
  return {
    heading: `${severity}: ${clip(payload.title, 150) || "Security alert"}`,
    lines: [event === "breach_watch" ? "A member's work email appeared in a new data breach." : event === "rotation" ? "A password rotation needs attention."
      : "Review it in the Passkey-X admin console. No passwords or vault data are included in this message."],
    link: appLink(payload, tab), linkLabel: "Review in Passkey-X",
    tone: payload.severity === "critical" || payload.severity === "high" ? "attention" : "warning",
  };
}

function slackEscape(value: string) {
  return value.replace(/&/gu, "&amp;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
}

export function shapeChat(format: string, payload: ChatPayload): Shaped {
  const message = chatMessage(payload);
  if (format === "slack") {
    const body = {
      text: slackEscape(`${message.heading} — ${message.lines[0] ?? ""}`).slice(0, 3000),
      blocks: [
        { type: "header", text: { type: "plain_text", text: message.heading.slice(0, 150), emoji: false } },
        { type: "section", text: { type: "mrkdwn", text: slackEscape(message.lines.join("\n")).slice(0, 2900) || " " } },
        { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: message.linkLabel }, url: message.link }] },
      ],
    };
    return { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  }
  if (format === "teams") {
    const body = {
      type: "message",
      attachments: [{
        contentType: "application/vnd.microsoft.card.adaptive",
        contentUrl: null,
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4",
          body: [
            { type: "TextBlock", text: message.heading, weight: "Bolder", size: "Medium", wrap: true, color: ({ attention: "Attention", warning: "Warning", good: "Good", default: "Default" } as const)[message.tone] },
            ...message.lines.map((line) => ({ type: "TextBlock", text: line, wrap: true, spacing: "Small" })),
          ],
          actions: [{ type: "Action.OpenUrl", title: message.linkLabel, url: message.link }],
        },
      }],
    };
    return { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  }
  throw new Error("unsupported_format");
}

/** Fixed destination hosts per format (defence in depth on top of the database checks). */
export function hostAllowedForFormat(format: string, url: URL) {
  const host = url.hostname.toLowerCase();
  if (format === "slack") return host === "hooks.slack.com";
  if (format === "teams") return /\.(logic\.azure\.com|webhook\.office\.com|powerplatform\.com|powerautomate\.com)$/u.test(host);
  if (format === "datadog") return /^http-intake\.logs\.(datadoghq\.com|us3\.datadoghq\.com|us5\.datadoghq\.com|datadoghq\.eu|ap1\.datadoghq\.com|ap2\.datadoghq\.com|ddog-gov\.com)$/u.test(host);
  if (format === "sentinel") return /\.ingest\.monitor\.azure\.(com|us|cn)$/u.test(host);
  return true;
}

export function sentinelTokenRequest(config: Record<string, unknown>, clientSecret: string) {
  const tenant = String(config.tenant_id ?? "");
  const client = String(config.client_id ?? "");
  if (!/^[0-9a-f-]{36}$/u.test(tenant) || !/^[0-9a-f-]{36}$/u.test(client)) throw new Error("invalid_sentinel_config");
  const authority = String(config.endpoint ?? "").endsWith(".us") ? "https://login.microsoftonline.us" : String(config.endpoint ?? "").endsWith(".cn")
    ? "https://login.chinacloudapi.cn" : "https://login.microsoftonline.com";
  const scope = String(config.endpoint ?? "").endsWith(".us") ? "https://monitor.azure.us//.default" : String(config.endpoint ?? "").endsWith(".cn")
    ? "https://monitor.azure.cn//.default" : "https://monitor.azure.com//.default";
  return {
    url: `${authority}/${tenant}/oauth2/v2.0/token`,
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: client, client_secret: clientSecret, scope }).toString(),
    cacheKey: `${tenant}:${client}`,
  };
}
