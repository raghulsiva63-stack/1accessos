import type { Config } from "@netlify/functions";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import OpenAI from "openai";
import { POLICY_SCHEMA, TRIAGE_SCHEMA, validatePolicyAdvice, validateTriage } from "../../lib/security/ai-output";

const USE_CASES = new Set(["security_posture", "access_review", "spend_review", "incident_summary", "vault_health",
  "alert_triage", "policy_advisor", "weekly_summary"]);
// Organization security use cases: the database builds the context (counts, alert kinds and
// policy settings only) and checks that the caller may see the organization's security posture.
const SECURITY_USE_CASES = new Set(["alert_triage", "policy_advisor", "weekly_summary"]);

const POLICY_CATALOGUE = [
  'passkey_required {"required": boolean} - members must register an account passkey',
  'mfa_required {"required": boolean} - members must use two-step verification',
  'device_approval_required {"required": boolean} - new devices need approval',
  'minimum_vault_password {"min_length": 12-128, "min_strength": 0-4} - vault password strength',
  'session_timeout_minutes {"minutes": 1-480} - automatic vault lock',
  'clipboard_clear_seconds {"seconds": 5-300} - clear copied secrets',
  'breach_monitoring {"mode": "off"|"optional"|"required"} - breached password checks',
  'password_rotation {"days": 30-730} - flag old passwords',
  'sharing_mode {"mode": "open"|"internal_only"|"disabled"} - who items can be shared with',
  'export_policy {"mode": "allowed"|"admins_only"|"blocked"} - who may export vault data',
  'organization_recovery {"enabled": boolean} - admins can help members recover vault access',
].join("\n");

const SYSTEM_PROMPTS: Record<string, string> = {
  alert_triage: "You are the Passkey-X security operations assistant for an organization administrator. You receive only groups of open security alerts: kind, severity, count, age in hours and how many members are involved. No names, emails, secrets or vault content. Rank the alert kinds: priority 1 = act now, 5 = informational. For each kind give why it matters in one plain sentence and the next concrete step (use Passkey-X admin tabs: Alerts, People, Audit log, Policies, Breach watch, Rotation, or contacting the member). Use only kinds present in the input. The summary is at most two sentences.",
  policy_advisor: `You are the Passkey-X policy advisor for an organization administrator. You receive aggregate security posture (counts and percentages) and the policies already enforced. Recommend at most 5 policy changes that would clearly improve security for these numbers, most important first. Only use this catalogue, and put the exact configuration as a JSON object string in configuration_json:\n${POLICY_CATALOGUE}\nDo not recommend a policy that is already enforced with the same value. Each reason is one sentence that refers to the numbers. The summary is at most two sentences.`,
  weekly_summary: "You write the weekly Passkey-X security summary for a company owner who is not a security expert. You receive only counts. In at most 120 words of plain text (no headings, no markdown): say how the security score moved, then the three most important risks with one concrete action each. Never invent numbers.",
};
// Vault-health coaching receives only these on-device totals. Titles, sites, usernames and
// passwords never leave the browser.
const VAULT_HEALTH_KEYS = ["score", "logins", "weak", "reused", "old", "breached", "insecure_sites", "missing_two_step", "passkeys"] as const;

function vaultHealthMetrics(value: unknown): Record<string, number> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !(VAULT_HEALTH_KEYS as readonly string[]).includes(key))) return null;
  const metrics: Record<string, number> = {};
  for (const key of VAULT_HEALTH_KEYS) {
    const entry = input[key];
    // -1 means "not checked yet" (for example, breaches before the user runs a breach check).
    if (!Number.isInteger(entry) || (entry as number) < -1 || (entry as number) > 100_000) return null;
    metrics[key] = entry as number;
  }
  return metrics.score <= 100 ? metrics : null;
}
const ALLOWED_ORIGINS = new Set(["https://passkey-x.com", "https://www.passkey-x.com", "https://passkey-x.netlify.app"]);
// The bundled desktop app runs on its own local origin and calls this endpoint cross-origin
// with the user's bearer token (no cookies).
const DESKTOP_ORIGINS = new Set(["tauri://localhost", "http://tauri.localhost"]);

function response(status: number, body: Record<string, unknown>) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function required(name: string): string {
  const value = Netlify.env.get(name)?.trim();
  if (!value) throw new Error("not_configured");
  return value;
}

function bytea(bytes: Uint8Array): string {
  return `\\x${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

async function hash(value: string): Promise<string> {
  return bytea(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

export default async (request: Request) => {
  const origin = request.headers.get("origin");
  const desktop = Boolean(origin && DESKTOP_ORIGINS.has(origin));
  if (desktop && request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": origin!, "Access-Control-Allow-Methods": "POST", "Access-Control-Allow-Headers": "authorization, content-type", "Access-Control-Max-Age": "86400", "Vary": "Origin" } });
  }
  const result = await handle(request, origin, desktop);
  if (desktop) { result.headers.set("Access-Control-Allow-Origin", origin!); result.headers.set("Vary", "Origin"); }
  return result;
};

async function handle(request: Request, origin: string | null, desktop: boolean): Promise<Response> {
  if (request.method !== "POST") return response(405, { error: "method_not_allowed" });
  if (origin && !desktop && !ALLOWED_ORIGINS.has(origin)) return response(403, { error: "origin_forbidden" });
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return response(401, { error: "authentication_required" });

  let client: SupabaseClient | null = null;
  let requestId: string | null = null;
  try {
    const body = await request.json() as { tenantId?: string; useCase?: string; metrics?: unknown };
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(body.tenantId ?? "") || !USE_CASES.has(body.useCase ?? "")) {
      return response(400, { error: "invalid_request" });
    }
    const tenantId = body.tenantId!;
    const useCase = body.useCase!;
    const supabaseUrl = Netlify.env.get("SUPABASE_URL")?.trim() || required("NEXT_PUBLIC_SUPABASE_URL");
    const publishableKey = Netlify.env.get("SUPABASE_PUBLISHABLE_KEY")?.trim() || required("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY");
    client = createClient(supabaseUrl, publishableKey, {
      global: { headers: { Authorization: authorization } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await client.auth.getUser(authorization.slice(7));
    if (userError || !userData.user?.email_confirmed_at) return response(401, { error: "authentication_required" });

    let metrics: Record<string, unknown>;
    let categories: string[];
    if (SECURITY_USE_CASES.has(useCase)) {
      const { data: context, error: contextError } = await client.rpc("ai_security_context", { p_tenant_id: tenantId, p_use_case: useCase });
      if (contextError?.code === "42501") return response(403, { error: "forbidden" });
      if (contextError || !context || typeof context !== "object") throw new Error("context_unavailable");
      metrics = context as Record<string, unknown>;
      categories = ["security_counts"];
    } else if (useCase === "vault_health") {
      const health = vaultHealthMetrics(body.metrics);
      if (!health) return response(400, { error: "invalid_request" });
      metrics = health;
      categories = ["vault_health_counts"];
    } else {
      const [memberships, applications, unsanctioned, recommendations, pendingAccess, runtime] = await Promise.all([
        client.from("tenant_memberships").select("tenant_id", { count: "exact", head: true }).eq("tenant_id", tenantId).eq("status", "active"),
        client.from("saas_applications").select("id", { count: "exact", head: true }).eq("tenant_id", tenantId),
        client.from("saas_applications").select("id", { count: "exact", head: true }).eq("tenant_id", tenantId).eq("sanctioned_state", "unsanctioned"),
        client.from("saas_recommendations").select("id", { count: "exact", head: true }).eq("tenant_id", tenantId).eq("action_state", "proposed"),
        client.from("privilege_requests").select("id", { count: "exact", head: true }).eq("tenant_id", tenantId).eq("status", "pending"),
        client.rpc("runtime_dashboard", { p_tenant_id: tenantId }),
      ]);
      const queryError = [memberships.error, applications.error, unsanctioned.error, recommendations.error, pendingAccess.error, runtime.error].find(Boolean);
      if (queryError || !runtime.data) throw new Error("context_unavailable");
      metrics = {
        active_members: memberships.count ?? 0,
        discovered_saas_apps: applications.count ?? 0,
        unsanctioned_saas_apps: unsanctioned.count ?? 0,
        open_recommendations: recommendations.count ?? 0,
        pending_privileged_requests: pendingAccess.count ?? 0,
        runtime: runtime.data,
      };
      categories = ["tenant_counts", "spend_totals", "access_risk_counts"];
    }
    const prompt = JSON.stringify({ use_case: useCase, approved_derived_metrics: metrics });
    const { data: started, error: startError } = await client.rpc("begin_ai_assistant_request", {
      p_tenant_id: tenantId,
      p_use_case: useCase,
      p_prompt_sha256: await hash(prompt),
      p_context_categories: categories,
    });
    // 54000: monthly AI credits used up, or the hourly request limit reached. Nothing was charged.
    if (startError?.code === "54000") return response(429, { error: "limit_reached" });
    if (startError || typeof started !== "string") throw new Error("request_blocked");
    requestId = started;

    const openai = new OpenAI({
      apiKey: required("OPENAI_API_KEY"),
      baseURL: required("OPENAI_BASE_URL"),
    });
    const structured = useCase === "alert_triage" ? TRIAGE_SCHEMA : useCase === "policy_advisor" ? POLICY_SCHEMA : null;
    const completion = await openai.responses.create({
      model: "gpt-5-mini",
      reasoning: { effort: "minimal" },
      max_output_tokens: structured ? 1200 : 500,
      input: [
        {
          role: "system",
          content: SYSTEM_PROMPTS[useCase] ?? (useCase === "vault_health"
            ? "You are the Passkey-X AI Security Coach for one person. You receive only counts about their password vault (a -1 value means not checked yet). Write a friendly, plain-language plan: first the single most important fix and why, then up to four short numbered steps in priority order that use Passkey-X screens (Security, Vault, Generator, Account security). Mention turning on two-step verification if relevant. Never ask for or guess passwords, sites or names. Under 180 words."
            : "You are Passkey-X Security Advisor. Analyze only the supplied aggregate counts. Do not infer identities, credentials, secret values, or vault contents. Give concise, non-destructive recommendations and require human approval for access changes."),
        },
        { role: "user", content: prompt },
      ],
      ...(structured ? { text: { format: { type: "json_schema" as const, name: useCase, schema: structured as unknown as Record<string, unknown>, strict: true } } } : {}),
    });
    const output = completion.output_text?.trim();
    if (!output) throw new Error("empty_response");
    let advice = output;
    let result: Record<string, unknown> | null = null;
    if (useCase === "alert_triage") {
      const groups = Array.isArray(metrics.open_alert_groups) ? metrics.open_alert_groups as { kind?: unknown }[] : [];
      const triage = validateTriage(JSON.parse(output), new Set(groups.map((group) => String(group.kind))));
      if (!triage) throw new Error("invalid_response");
      advice = triage.summary; result = triage;
    } else if (useCase === "policy_advisor") {
      const enforced = Array.isArray(metrics.enforced_policies) ? metrics.enforced_policies as { type: string; configuration: unknown }[] : [];
      const policy = validatePolicyAdvice(JSON.parse(output), enforced);
      if (!policy) throw new Error("invalid_response");
      advice = policy.summary; result = policy;
    } else if (useCase === "weekly_summary") {
      advice = output.slice(0, 4000);
    }
    await client.rpc("complete_ai_assistant_request", {
      p_request_id: requestId,
      p_status: "completed",
      p_input_tokens: completion.usage?.input_tokens ?? 0,
      p_output_tokens: completion.usage?.output_tokens ?? 0,
      p_failure_code: null,
    });
    if (useCase === "weekly_summary") {
      // Saved only after the request is completed: the database accepts a summary only from the
      // person who just received one (owners, admins and security admins).
      const now = new Date();
      const monday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - ((now.getUTCDay() + 6) % 7)));
      await client.rpc("save_security_report_summary", { p_tenant_id: tenantId, p_week_start: monday.toISOString().slice(0, 10), p_summary: advice });
    }
    return response(200, {
      requestId,
      model: completion.model,
      advice,
      ...(result ? { result } : {}),
      context: "aggregate_counts_only",
    });
  } catch (error) {
    if (client && requestId) {
      try {
        await client.rpc("complete_ai_assistant_request", {
          p_request_id: requestId,
          p_status: "failed",
          p_input_tokens: 0,
          p_output_tokens: 0,
          p_failure_code: "provider_unavailable",
        });
      } catch { /* the original failure remains the public result */ }
    }
    console.error(JSON.stringify({ function: "security-advice", code: "advisor_unavailable" }));
    return response(503, { error: "advisor_unavailable" });
  }
}

export const config: Config = {
  path: "/api/ai/security-advice",
  method: ["POST", "OPTIONS"],
  rateLimit: { action: "rate_limit", aggregateBy: ["domain", "ip"], windowSize: 60, windowLimit: 12 },
};
