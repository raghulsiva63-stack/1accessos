import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, corsHeaders, json, publicError, requireUser } from "../_shared/control-plane.ts";

type DeletionRequest = { action?: "preflight" | "delete"; confirmation?: string };

function recentlyAuthenticated(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/gu, "+").replace(/_/gu, "/"))) as { iat?: number };
    return typeof payload.iat === "number" && Math.floor(Date.now() / 1000) - payload.iat <= 300;
  } catch { return false; }
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const body = await request.json() as DeletionRequest;
    const context = await requireUser(request);
    if (body.action === "preflight") {
      const { data, error } = await context.client.rpc("account_deletion_preflight");
      if (error) throw error;
      return json(request, 200, { preflight: data });
    }
    if (body.action !== "delete" || body.confirmation !== "DELETE MY ACCOUNT") throw new Error("invalid_request");
    if (!recentlyAuthenticated(context.token)) throw new Error("recent_reauthentication_required");

    const admin = adminSupabase();
    const { data: preflight, error: preflightError } = await context.client.rpc("account_deletion_preflight");
    if (preflightError) throw preflightError;
    const result = preflight as { can_delete?: boolean; blocking_tenant_ids?: string[] };
    if (!result.can_delete) throw new Error("ownership_transfer_required");

    const { data: existingDeletion, error: existingError } = await admin.from("account_deletion_requests")
      .select("id").eq("identity_id", context.identityId).in("status", ["requested", "in_progress"])
      .order("requested_at", { ascending: false }).limit(1).maybeSingle();
    if (existingError) throw existingError;
    let deletion = existingDeletion;
    if (!deletion) {
      const { data: createdDeletion, error: requestError } = await admin.from("account_deletion_requests").insert({
        identity_id: context.identityId,
        auth_user_id: context.user.id,
        status: "requested",
      }).select("id").single();
      if (requestError || !createdDeletion) throw requestError ?? new Error("service_unavailable");
      deletion = createdDeletion;
    }

    const { data: paths, error: pathError } = await admin.rpc("account_deletion_storage_paths", { p_auth_user_id: context.user.id });
    if (pathError) throw pathError;
    const storagePaths = ((paths ?? []) as Array<{ storage_path: string }>).map((entry) => entry.storage_path);
    for (let index = 0; index < storagePaths.length; index += 100) {
      const { error } = await admin.storage.from("vault-attachments").remove(storagePaths.slice(index, index + 100));
      if (error) throw new Error("storage_cleanup_failed");
    }

    const { data: cleanup, error: cleanupError } = await admin.rpc("complete_account_deletion", {
      p_auth_user_id: context.user.id,
      p_request_id: deletion.id,
    });
    if (cleanupError) throw cleanupError;
    if (!(cleanup as { cleaned?: boolean })?.cleaned) throw new Error("ownership_transfer_required");
    const { error: authError } = await admin.auth.admin.deleteUser(context.user.id, false);
    if (authError) throw authError;
    const { data: finalized, error: finalizeError } = await admin.rpc("finalize_account_deletion", {
      p_request_id: deletion.id,
    });
    if (finalizeError || finalized !== true) throw finalizeError ?? new Error("service_unavailable");
    return json(request, 200, { deleted: true });
  } catch (reason) {
    const error = publicError(reason);
    console.error(JSON.stringify({ function: "account-lifecycle", code: error.code }));
    return json(request, error.status, { error: error.code });
  }
});

