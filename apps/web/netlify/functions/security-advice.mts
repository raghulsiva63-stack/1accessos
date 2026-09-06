import type { Config } from "@netlify/functions";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import OpenAI from "openai";

const USE_CASES = new Set(["security_posture", "access_review", "spend_review", "incident_summary"]);
const ALLOWED_ORIGINS = new Set(["https://passkey-x.com", "https://www.passkey-x.com", "https://passkey-x.netlify.app"]);

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
  if (request.method !== "POST") return response(405, { error: "method_not_allowed" });
  const origin = request.headers.get("origin");
  if (origin && !ALLOWED_ORIGINS.has(origin)) return response(403, { error: "origin_forbidden" });
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return response(401, { error: "authentication_required" });

  let client: SupabaseClient | null = null;
  let requestId: string | null = null;
  try {
    const body = await request.json() as { tenantId?: string; useCase?: string };
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
    const metrics = {
      active_members: memberships.count ?? 0,
      discovered_saas_apps: applications.count ?? 0,
      unsanctioned_saas_apps: unsanctioned.count ?? 0,
      open_recommendations: recommendations.count ?? 0,
      pending_privileged_requests: pendingAccess.count ?? 0,
      runtime: runtime.data,
    };
    const prompt = JSON.stringify({ use_case: useCase, approved_derived_metrics: metrics });
    const { data: started, error: startError } = await client.rpc("begin_ai_assistant_request", {
      p_tenant_id: tenantId,
      p_use_case: useCase,
      p_prompt_sha256: await hash(prompt),
      p_context_categories: ["tenant_counts", "spend_totals", "access_risk_counts"],
    });
    if (startError || typeof started !== "string") throw new Error("request_blocked");
    requestId = started;

    const openai = new OpenAI({
      apiKey: required("OPENAI_API_KEY"),
      baseURL: required("OPENAI_BASE_URL"),
    });
    const completion = await openai.responses.create({
      model: "gpt-5-mini",
      reasoning: { effort: "minimal" },
      max_output_tokens: 500,
      input: [
        {
          role: "system",
          content: "You are Passkey-X Security Advisor. Analyze only the supplied aggregate counts. Do not infer identities, credentials, secret values, or vault contents. Give concise, non-destructive recommendations and require human approval for access changes.",
        },
        { role: "user", content: prompt },
      ],
    });
    const advice = completion.output_text?.trim();
    if (!advice) throw new Error("empty_response");
    await client.rpc("complete_ai_assistant_request", {
      p_request_id: requestId,
      p_status: "completed",
      p_input_tokens: completion.usage?.input_tokens ?? 0,
      p_output_tokens: completion.usage?.output_tokens ?? 0,
      p_failure_code: null,
    });
    return response(200, {
      requestId,
      model: completion.model,
      advice,
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
};

export const config: Config = {
  path: "/api/ai/security-advice",
  method: "POST",
  rateLimit: { action: "rate_limit", aggregateBy: ["domain", "ip"], windowSize: 60, windowLimit: 12 },
};
