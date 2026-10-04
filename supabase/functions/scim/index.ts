import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.115.0";

/**
 * SCIM 2.0 (RFC 7643/7644) user provisioning for Passkey-X organizations.
 * Base URL: https://<project>.supabase.co/functions/v1/scim/v2
 * Auth: "Authorization: Bearer pxscim_…" (created in Admin console → Identity & SSO).
 *
 * Provisioning pre-authorizes an email address for the organization. Because vaults
 * are end-to-end encrypted, the person still creates their own vault password when
 * they first sign in, then joins with one click. Deactivating or deleting a user
 * suspends their organization membership, removes workspace access and key envelopes,
 * and flags the affected workspaces for key rotation.
 *
 * Groups (/Groups) can be mapped to workspaces in the admin console. Group membership then
 * adds or removes workspace access; an administrator's device delivers the encrypted
 * workspace key to new members (the server never holds it).
 */

const SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCHEMA_ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";

type ProvisionedGroup = {
  id: string; external_id: string | null; display_name: string; created_at: string; updated_at: string;
  members: { value: string; display: string }[];
};

function toGroupResource(group: ProvisionedGroup, base: string, includeMembers = true) {
  return {
    schemas: [SCHEMA_GROUP],
    id: group.id,
    externalId: group.external_id ?? undefined,
    displayName: group.display_name,
    ...(includeMembers ? { members: group.members.map((member) => ({ value: member.value, display: member.display, $ref: `${base}/Users/${member.value}` })) } : {}),
    meta: { resourceType: "Group", created: group.created_at, lastModified: group.updated_at, location: `${base}/Groups/${group.id}`,
      version: `W/"${Date.parse(group.updated_at)}"` },
  };
}

type PatchOperation = { op?: string; path?: string; value?: unknown };

function memberIds(value: unknown): string[] {
  const list = Array.isArray(value) ? value : value ? [value] : [];
  return list.map((entry) => typeof entry === "string" ? entry : String((entry as { value?: unknown })?.value ?? ""))
    .filter((id) => UUID.test(id));
}

/** Okta and Entra ID PatchOp styles for groups. */
export function parseGroupPatch(operations: PatchOperation[]) {
  const result: { displayName?: string; externalId?: string; add: string[]; remove: string[]; replace?: string[] } = { add: [], remove: [] };
  for (const operation of operations) {
    const op = operation.op?.toLowerCase();
    const path = operation.path?.trim() ?? "";
    const filtered = path.match(/^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$/iu);
    if (op === "remove" && filtered) { if (UUID.test(filtered[1])) result.remove.push(filtered[1]); continue; }
    if (/^members$/iu.test(path)) {
      if (op === "add") result.add.push(...memberIds(operation.value));
      else if (op === "remove") result.remove.push(...memberIds(operation.value));
      else if (op === "replace") result.replace = memberIds(operation.value);
      continue;
    }
    if ((op === "replace" || op === "add") && /^displayName$/iu.test(path)) { result.displayName = String(operation.value ?? ""); continue; }
    if ((op === "replace" || op === "add") && /^externalId$/iu.test(path)) { result.externalId = String(operation.value ?? ""); continue; }
    if ((op === "replace" || op === "add") && !path && operation.value && typeof operation.value === "object") {
      const value = operation.value as Record<string, unknown>;
      if (typeof value.displayName === "string") result.displayName = value.displayName;
      if (typeof value.externalId === "string") result.externalId = value.externalId;
      if ("members" in value) { if (op === "replace") result.replace = memberIds(value.members); else result.add.push(...memberIds(value.members)); }
    }
  }
  return result;
}

function parseGroupFilter(filter: string | null) {
  if (!filter) return { displayName: null as string | null, externalId: null as string | null };
  const match = filter.match(/^\s*(displayName|externalId)\s+eq\s+"([^"]{1,200})"\s*$/iu);
  if (!match) throw new Error("invalid_filter");
  return match[1].toLowerCase() === "externalid" ? { displayName: null, externalId: match[2] } : { displayName: match[2], externalId: null };
}

type ProvisionedUser = {
  id: string; external_id: string | null; user_name: string; display_name: string; job_title: string | null;
  active: boolean; identity_id: string | null; created_at: string; updated_at: string;
};

type ScimUserInput = {
  userName?: string; externalId?: string; displayName?: string; title?: string; active?: boolean | string;
  name?: { formatted?: string; givenName?: string; familyName?: string };
  emails?: { value?: string; primary?: boolean }[];
};

function required(name: string) {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`missing:${name}`);
  return value;
}

function serviceKey() {
  const source = Deno.env.get("SUPABASE_SECRET_KEYS")?.trim();
  if (source) {
    const keys = JSON.parse(source) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  return required("SUPABASE_SERVICE_ROLE_KEY");
}

function scim(status: number, body: unknown) {
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/scim+json" } });
}

function scimError(status: number, detail: string, scimType?: string) {
  return scim(status, { schemas: [SCHEMA_ERROR], status: String(status), detail, ...(scimType ? { scimType } : {}) });
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function toResource(user: ProvisionedUser, base: string) {
  return {
    schemas: [SCHEMA_USER, SCHEMA_ENTERPRISE],
    id: user.id,
    externalId: user.external_id ?? undefined,
    userName: user.user_name,
    name: { formatted: user.display_name },
    displayName: user.display_name,
    title: user.job_title ?? undefined,
    active: user.active,
    emails: [{ value: user.user_name, type: "work", primary: true }],
    meta: {
      resourceType: "User",
      created: user.created_at,
      lastModified: user.updated_at,
      location: `${base}/Users/${user.id}`,
      version: `W/"${Date.parse(user.updated_at)}"`,
    },
  };
}

function parseActive(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.toLowerCase() === "true" ? true : value.toLowerCase() === "false" ? false : undefined;
  return undefined;
}

function fromInput(input: ScimUserInput) {
  const email = input.userName ?? input.emails?.find((entry) => entry.primary)?.value ?? input.emails?.[0]?.value;
  const display = input.displayName ?? input.name?.formatted
    ?? [input.name?.givenName, input.name?.familyName].filter(Boolean).join(" ");
  return {
    userName: email?.trim(),
    externalId: input.externalId?.trim() || null,
    displayName: display?.trim() || null,
    title: input.title?.trim() || null,
    active: parseActive(input.active),
  };
}

/** Applies PatchOp operations (Okta / Entra ID styles) to a flat attribute set. */
function applyPatch(operations: { op?: string; path?: string; value?: unknown }[]) {
  const changes: { displayName?: string; title?: string; active?: boolean; externalId?: string; userName?: string } = {};
  for (const operation of operations) {
    const op = operation.op?.toLowerCase();
    if (op !== "replace" && op !== "add") continue;
    const assign = (path: string, value: unknown) => {
      const key = path.replace(`${SCHEMA_USER}:`, "").toLowerCase();
      if (key === "active") { const active = parseActive(value); if (active !== undefined) changes.active = active; }
      else if (key === "displayname" || key === "name.formatted") changes.displayName = String(value);
      else if (key === "title") changes.title = String(value);
      else if (key === "externalid") changes.externalId = String(value);
      else if (key === "username") changes.userName = String(value);
      else if (key === "name.givenname" || key === "name.familyname") {
        changes.displayName = [changes.displayName, String(value)].filter(Boolean).join(" ");
      }
    };
    if (operation.path) assign(operation.path, operation.value);
    else if (operation.value && typeof operation.value === "object") {
      for (const [key, value] of Object.entries(operation.value as Record<string, unknown>)) {
        if (key === "name" && value && typeof value === "object") {
          const name = value as { formatted?: string; givenName?: string; familyName?: string };
          changes.displayName = name.formatted ?? [name.givenName, name.familyName].filter(Boolean).join(" ");
        } else assign(key, value);
      }
    }
  }
  return changes;
}

function parseFilter(filter: string | null) {
  if (!filter) return { userName: null as string | null, externalId: null as string | null };
  const match = filter.match(/^\s*(userName|externalId|emails(?:\.value)?)\s+eq\s+"([^"]{1,320})"\s*$/iu);
  if (!match) throw new Error("invalid_filter");
  const attribute = match[1].toLowerCase();
  return attribute === "externalid" ? { userName: null, externalId: match[2] } : { userName: match[2], externalId: null };
}

Deno.serve(async (request: Request) => {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^.*?\/scim(?=\/|$)/u, "").replace(/\/+$/u, "") || "/";
  const scimIndex = url.pathname.indexOf("/scim");
  const base = `${url.origin}${scimIndex >= 0 ? url.pathname.slice(0, scimIndex + 5) : ""}/v2`;

  const authorization = request.headers.get("authorization") ?? "";
  const token = authorization.match(/^Bearer\s+(pxscim_[a-f0-9]{64})$/u)?.[1];
  if (!token) return scimError(401, "A valid Passkey-X provisioning token is required.");

  const admin = createClient(required("SUPABASE_URL"), serviceKey(), { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: tenantId, error: authError } = await admin.rpc("scim_tenant_for_token", { p_token: token });
  if (authError) return scimError(503, "Provisioning is temporarily unavailable.");
  if (!tenantId) return scimError(401, "The provisioning token is invalid or revoked.");

  try {
    if (request.method === "GET" && path === "/v2/ServiceProviderConfig") {
      return scim(200, {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
        filter: { supported: true, maxResults: 200 }, changePassword: { supported: false },
        sort: { supported: false }, etag: { supported: false },
        authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "Passkey-X provisioning token", primary: true }],
      });
    }
    if (request.method === "GET" && path === "/v2/ResourceTypes") {
      return scim(200, { schemas: [SCHEMA_LIST], totalResults: 2, Resources: [
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: SCHEMA_USER },
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "Group", name: "Group", endpoint: "/Groups", schema: SCHEMA_GROUP },
      ] });
    }
    if (request.method === "GET" && path === "/v2/Schemas") {
      return scim(200, { schemas: [SCHEMA_LIST], totalResults: 2, Resources: [{ id: SCHEMA_USER, name: "User" }, { id: SCHEMA_GROUP, name: "Group" }] });
    }
    if (path === "/v2/Groups" && request.method === "GET") {
      const { displayName, externalId } = parseGroupFilter(url.searchParams.get("filter"));
      const startIndex = Math.max(1, Number(url.searchParams.get("startIndex") ?? 1) || 1);
      const count = Math.min(200, Math.max(0, Number(url.searchParams.get("count") ?? 100) || 0));
      const { data, error } = await admin.rpc("scim_list_groups", {
        p_tenant_id: tenantId, p_display_name: displayName, p_external_id: externalId, p_offset: startIndex - 1, p_limit: count,
      });
      if (error) throw error;
      const row = (Array.isArray(data) ? data[0] : data) as { total: number; groups: ProvisionedGroup[] };
      const withMembers = !/members/iu.test(url.searchParams.get("excludedAttributes") ?? "");
      return scim(200, { schemas: [SCHEMA_LIST], totalResults: Number(row?.total ?? 0), startIndex, itemsPerPage: row?.groups?.length ?? 0,
        Resources: (row?.groups ?? []).map((group) => toGroupResource(group, base, withMembers)) });
    }
    if (path === "/v2/Groups" && request.method === "POST") {
      const body = await request.json() as { displayName?: string; externalId?: string; members?: unknown };
      if (!body.displayName?.trim()) return scimError(400, "displayName is required.", "invalidValue");
      const { data, error } = await admin.rpc("scim_upsert_group", {
        p_tenant_id: tenantId, p_id: null, p_external_id: body.externalId?.trim() || null, p_display_name: body.displayName.trim(),
        p_members: memberIds(body.members),
      });
      if (error) throw error;
      return scim(201, toGroupResource(data as ProvisionedGroup, base));
    }
    const groupMatch = path.match(/^\/v2\/Groups\/([^/]+)$/u);
    if (groupMatch) {
      const id = groupMatch[1];
      if (!UUID.test(id)) return scimError(404, "Group not found.");
      const loadGroup = async () => {
        const { data, error } = await admin.rpc("scim_get_group", { p_tenant_id: tenantId, p_id: id });
        if (error) throw error;
        return (data ?? null) as ProvisionedGroup | null;
      };
      const current = await loadGroup();
      if (!current) return scimError(404, "Group not found.");
      if (request.method === "GET") return scim(200, toGroupResource(current, base, !/members/iu.test(url.searchParams.get("excludedAttributes") ?? "")));
      if (request.method === "DELETE") {
        const { error } = await admin.rpc("scim_delete_group", { p_tenant_id: tenantId, p_id: id });
        if (error) throw error;
        return scim(204, null);
      }
      if (request.method === "PUT") {
        const body = await request.json() as { displayName?: string; externalId?: string; members?: unknown };
        const { data, error } = await admin.rpc("scim_upsert_group", {
          p_tenant_id: tenantId, p_id: id, p_external_id: body.externalId?.trim() || null, p_display_name: body.displayName?.trim() || null,
          p_members: memberIds(body.members),
        });
        if (error) throw error;
        return scim(200, toGroupResource(data as ProvisionedGroup, base));
      }
      if (request.method === "PATCH") {
        const body = await request.json() as { schemas?: string[]; Operations?: PatchOperation[] };
        if (!body.schemas?.includes(SCHEMA_PATCH)) return scimError(400, "PatchOp schema is required.", "invalidSyntax");
        const patch = parseGroupPatch(Array.isArray(body.Operations) ? body.Operations : []);
        let result: ProvisionedGroup = current;
        if (patch.displayName !== undefined || patch.externalId !== undefined || patch.replace) {
          const members = patch.replace
            ? [...new Set([...patch.replace, ...patch.add])].filter((member) => !patch.remove.includes(member))
            : null;
          const { data, error } = await admin.rpc("scim_upsert_group", {
            p_tenant_id: tenantId, p_id: id, p_external_id: patch.externalId?.trim() || null,
            p_display_name: patch.displayName?.trim() || null, p_members: members,
          });
          if (error) throw error;
          result = data as ProvisionedGroup;
        }
        if (!patch.replace && (patch.add.length || patch.remove.length)) {
          const { data, error } = await admin.rpc("scim_patch_group_members", { p_tenant_id: tenantId, p_id: id, p_add: patch.add, p_remove: patch.remove });
          if (error) throw error;
          result = data as ProvisionedGroup;
        }
        return scim(200, toGroupResource(result, base));
      }
    }

    if (path === "/v2/Users" && request.method === "GET") {
      const { userName, externalId } = parseFilter(url.searchParams.get("filter"));
      const startIndex = Math.max(1, Number(url.searchParams.get("startIndex") ?? 1) || 1);
      const count = Math.min(200, Math.max(0, Number(url.searchParams.get("count") ?? 100) || 0));
      const { data, error } = await admin.rpc("scim_list_users", {
        p_tenant_id: tenantId, p_user_name: userName, p_external_id: externalId, p_offset: startIndex - 1, p_limit: count,
      });
      if (error) throw error;
      const row = (Array.isArray(data) ? data[0] : data) as { total: number; users: ProvisionedUser[] };
      return scim(200, { schemas: [SCHEMA_LIST], totalResults: Number(row?.total ?? 0), startIndex, itemsPerPage: row?.users?.length ?? 0,
        Resources: (row?.users ?? []).map((user) => toResource(user, base)) });
    }

    if (path === "/v2/Users" && request.method === "POST") {
      const input = fromInput(await request.json() as ScimUserInput);
      if (!input.userName) return scimError(400, "userName (an email address) is required.", "invalidValue");
      const existing = await admin.rpc("scim_list_users", { p_tenant_id: tenantId, p_user_name: input.userName, p_external_id: null, p_offset: 0, p_limit: 1 });
      if (existing.error) throw existing.error;
      if (Number((Array.isArray(existing.data) ? existing.data[0] : existing.data)?.total ?? 0) > 0) {
        return scimError(409, "A user with this userName already exists.", "uniqueness");
      }
      const { data, error } = await admin.rpc("scim_upsert_user", {
        p_tenant_id: tenantId, p_id: null, p_external_id: input.externalId, p_user_name: input.userName,
        p_display_name: input.displayName, p_job_title: input.title, p_active: input.active ?? true,
      });
      if (error) throw error;
      return scim(201, toResource(data as ProvisionedUser, base));
    }

    const userMatch = path.match(/^\/v2\/Users\/([^/]+)$/u);
    if (userMatch) {
      const id = userMatch[1];
      if (!UUID.test(id)) return scimError(404, "User not found.");
      const load = async () => {
        const { data, error } = await admin.from("scim_provisioned_users")
          .select("id,external_id,user_name,display_name,job_title,active,identity_id,created_at,updated_at")
          .eq("tenant_id", tenantId).eq("id", id).maybeSingle();
        if (error) throw error;
        return data as ProvisionedUser | null;
      };
      const current = await load();
      if (!current) return scimError(404, "User not found.");

      if (request.method === "GET") return scim(200, toResource(current, base));
      if (request.method === "DELETE") {
        const { error } = await admin.rpc("scim_delete_user", { p_tenant_id: tenantId, p_id: id });
        if (error) throw error;
        return scim(204, null);
      }
      if (request.method === "PUT" || request.method === "PATCH") {
        const body = await request.json() as ScimUserInput & { schemas?: string[]; Operations?: { op?: string; path?: string; value?: unknown }[] };
        const changes = request.method === "PATCH"
          ? applyPatch(Array.isArray(body.Operations) ? body.Operations : [])
          : (() => { const input = fromInput(body); return { displayName: input.displayName ?? undefined, title: input.title ?? undefined, active: input.active, externalId: input.externalId ?? undefined, userName: input.userName }; })();
        if (request.method === "PATCH" && !body.schemas?.includes(SCHEMA_PATCH)) return scimError(400, "PatchOp schema is required.", "invalidSyntax");
        const { data, error } = await admin.rpc("scim_upsert_user", {
          p_tenant_id: tenantId, p_id: id, p_external_id: changes.externalId ?? null,
          p_user_name: changes.userName ?? current.user_name, p_display_name: changes.displayName ?? null,
          p_job_title: changes.title ?? null, p_active: changes.active ?? null,
        });
        if (error) throw error;
        return scim(200, toResource(data as ProvisionedUser, base));
      }
    }
    return scimError(404, "Unsupported SCIM endpoint.");
  } catch (reason) {
    const message = reason instanceof Error ? reason.message : String((reason as { message?: string })?.message ?? "");
    const code = String((reason as { code?: string })?.code ?? "");
    if (message === "invalid_filter") return scimError(400, "Only 'eq' filters on userName, displayName or externalId are supported.", "invalidFilter");
    if (code === "23505") return scimError(409, "A user with this userName or externalId already exists.", "uniqueness");
    if (code === "22023") return scimError(400, "userName must be an email address.", "invalidValue");
    if (code === "42501") return scimError(403, "Organization owners cannot be deprovisioned through SCIM.");
    if (code === "P0002") return scimError(404, "User not found.");
    console.error(JSON.stringify({ function: "scim", code: code || "error" }));
    return scimError(500, "The provisioning request could not be completed.");
  }
});
