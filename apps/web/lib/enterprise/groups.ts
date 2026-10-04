import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

/** SCIM groups (pushed by Okta, Entra ID, Google, JumpCloud …) mapped to workspaces. */

export type ScimGroup = { id: string; display_name: string; external_id: string | null; member_count: number; updated_at: string };
export type GroupMapping = { id: string; group_id: string; workspace_id: string; role: "manager" | "editor" | "viewer"; created_at: string };

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

export async function listScimGroups(tenantId: string): Promise<ScimGroup[]> {
  const { data, error } = await db().from("scim_groups")
    .select("id,display_name,external_id,updated_at,scim_group_members(count)")
    .eq("tenant_id", tenantId).order("display_name").limit(500);
  if (error) throw error;
  return ((data ?? []) as (Omit<ScimGroup, "member_count"> & { scim_group_members?: { count: number }[] })[]).map((row) => ({
    id: row.id, display_name: row.display_name, external_id: row.external_id, updated_at: row.updated_at,
    member_count: row.scim_group_members?.[0]?.count ?? 0,
  }));
}

export async function listGroupMappings(tenantId: string): Promise<GroupMapping[]> {
  const { data, error } = await db().from("group_workspace_mappings").select("id,group_id,workspace_id,role,created_at")
    .eq("tenant_id", tenantId).order("created_at");
  if (error) throw error;
  return (data ?? []) as GroupMapping[];
}

export async function setGroupMapping(groupId: string, workspaceId: string, role: GroupMapping["role"]) {
  const { data, error } = await db().rpc("set_group_mapping", { p_group_id: groupId, p_workspace_id: workspaceId, p_role: role });
  if (error) throw error;
  return data as string;
}

export async function deleteGroupMapping(id: string) {
  const { error } = await db().rpc("delete_group_mapping", { p_id: id });
  if (error) throw error;
}
