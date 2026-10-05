import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, corsHeaders, json, publicError, requireUser } from "../_shared/control-plane.ts";

/**
 * What a protected device needs to check pages on its own (verify_jwt = true):
 * * the version and a short-lived download link of the published prefix list (the device keeps
 *   it and downloads again only when the version changes);
 * * the prefixes of the person's organizations' own confirmed phishing reports;
 * * the Guard policy in effect for the person (strictest of their organizations).
 */
Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const user = await requireUser(request);
    const body = await request.json().catch(() => ({})) as { have?: unknown };
    const admin = adminSupabase();
    const [{ data: state }, { data: organization }, { data: policy }] = await Promise.all([
      admin.rpc("get_threat_intel_state", { p_key: "prefix_set" }),
      user.client.rpc("my_threat_prefixes"),
      user.client.rpc("my_guard_policy"),
    ]);
    const version = Number((state as { version?: number } | null)?.version ?? 0);
    let url: string | null = null;
    if (version && body.have !== version) {
      const signed = await admin.storage.from("threat-intel").createSignedUrl("prefixes.bin", 3600);
      url = signed.data?.signedUrl ?? null;
    }
    return json(request, 200, {
      version,
      url,
      sources: (state as { sources?: string[] } | null)?.sources ?? [],
      organizationPrefixes: organization ?? [],
      policy: policy ?? null,
    });
  } catch (reason) {
    const { code, status } = publicError(reason);
    return json(request, status, { error: code });
  }
});
