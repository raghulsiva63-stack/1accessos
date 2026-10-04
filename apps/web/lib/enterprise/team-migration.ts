import type { SupabaseClient } from "@supabase/supabase-js";
import { fromBase64Url, randomBytes, toPostgresBytea, wrapKey } from "@/lib/crypto/vault";
import { supabase } from "@/lib/supabase/client";
import type { ImportedEntry } from "@/lib/vault/importers";
import { createVaultItem, workspaceNameAad, type WorkspaceVault } from "@/lib/vault/items";
import { grantWorkspaceAccess, requestMemberAccess, type MemberSharingKey } from "@/lib/enterprise/key-sharing";

/**
 * Team migration: an administrator imports a company export (1Password, Bitwarden, LastPass,
 * Keeper, KeePass …) and turns each shared folder / collection into an organization workspace,
 * then gives the right people access. Everything is decrypted and re-encrypted on the
 * administrator's device; the server only sees ciphertext.
 */

const encoder = new TextEncoder();

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

async function sha256(value: string) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

/** Creates an encrypted workspace inside the organization; the caller becomes its owner. */
export async function createOrganizationWorkspace(tenantId: string, identityId: string, rootKey: Uint8Array, name: string,
  source: "admin" | "migration" = "migration"): Promise<WorkspaceVault> {
  const trimmed = name.trim().slice(0, 80);
  if (trimmed.length < 2) throw new Error("Workspace names need at least 2 characters.");
  const workspaceId = crypto.randomUUID();
  const workspaceKey = randomBytes(32);
  try {
    const aad = workspaceNameAad(tenantId, workspaceId);
    const encryptedName = await wrapKey(workspaceKey, encoder.encode(trimmed), aad);
    const rootEnvelope = await wrapKey(rootKey, workspaceKey, "1accessos:workspace:v1");
    const { error } = await db().rpc("create_organization_workspace", {
      p_tenant_id: tenantId, p_workspace_id: workspaceId,
      p_encrypted_name: toPostgresBytea(fromBase64Url(encryptedName.ciphertext)), p_name_nonce: toPostgresBytea(fromBase64Url(encryptedName.nonce)),
      p_name_aad_hash: toPostgresBytea(await sha256(aad)), p_key_nonce: toPostgresBytea(fromBase64Url(rootEnvelope.nonce)),
      p_wrapped_workspace_key: toPostgresBytea(fromBase64Url(rootEnvelope.ciphertext)), p_source: source,
    });
    if (error) throw error;
  } catch (reason) {
    workspaceKey.fill(0);
    throw reason;
  }
  return {
    identityId, tenantId, workspaceId, keyVersion: 1, key: workspaceKey, name: trimmed, suite: "business", kind: "shared",
    role: "owner", keyRotationRequired: false,
  };
}

export type CollectionPlan = {
  /** Source collection name ("" = items without a folder). */
  collection: string;
  /** "new" creates a workspace with `name`; otherwise an existing workspace id; "skip" leaves it out. */
  target: "new" | "skip" | string;
  name: string;
  members: { identityId: string; role: "manager" | "editor" | "viewer" }[];
};

export type MigrationProgress = {
  phase: "workspaces" | "items" | "access" | "done";
  done: number; total: number; current?: string;
};

export type MigrationReport = {
  workspacesCreated: number; itemsImported: number; accessGranted: number;
  /** People given access who have not unlocked Passkey-X yet; their keys are delivered automatically later. */
  waitingForMembers: string[]; failures: { collection: string; remaining: number }[];
  /** Workspaces created by this run, still unlocked (keys in memory) so a retry can reuse them. Call `releaseMigrationKeys` when done. */
  createdWorkspaces: WorkspaceVault[];
};

export function releaseMigrationKeys(report: Pick<MigrationReport, "createdWorkspaces"> | null | undefined) {
  for (const vault of report?.createdWorkspaces ?? []) vault.key.fill(0);
}

/** Groups entries by collection ("" for items without one). */
export function groupByCollection(entries: ImportedEntry[]) {
  const groups = new Map<string, ImportedEntry[]>();
  for (const entry of entries) {
    const key = entry.collection ?? "";
    groups.set(key, [...(groups.get(key) ?? []), entry]);
  }
  return groups;
}

/**
 * A sensible default plan. When the export marks shared folders (1Password business vaults,
 * Bitwarden collections, LastPass Shared-…, Keeper shared folders), only those become
 * workspaces and private folders are skipped — people import personal items themselves. When
 * the export has no sharing information (KeePass, CSV), every named folder becomes a workspace.
 */
export function defaultPlan(entries: ImportedEntry[]): CollectionPlan[] {
  const hasSharing = entries.some((entry) => entry.shared);
  return [...groupByCollection(entries).entries()].sort(([a], [b]) => a.localeCompare(b)).map(([collection, items]) => ({
    collection,
    target: hasSharing ? (items.some((item) => item.shared) ? "new" : "skip") : collection ? "new" : "skip",
    name: (collection || "Imported items").split(" / ").slice(-1)[0].slice(0, 80),
    members: [],
  }));
}

/**
 * Runs a migration plan. Resumable: `skipCounts` tells how many items of each collection were
 * already imported in a previous attempt (returned in `failures`).
 */
export async function runTeamMigration(input: {
  tenantId: string; identityId: string; rootKey: Uint8Array; entries: ImportedEntry[]; plan: CollectionPlan[];
  existing: WorkspaceVault[]; sharingKeys: Map<string, MemberSharingKey>;
  onProgress?: (progress: MigrationProgress) => void; skipCounts?: Record<string, number>;
}): Promise<MigrationReport> {
  const report: MigrationReport = { workspacesCreated: 0, itemsImported: 0, accessGranted: 0, waitingForMembers: [], failures: [], createdWorkspaces: [] };
  const groups = groupByCollection(input.entries);
  const active = input.plan.filter((step) => step.target !== "skip" && groups.has(step.collection));
  const created = report.createdWorkspaces;
  const targets = new Map<string, WorkspaceVault>();

  input.onProgress?.({ phase: "workspaces", done: 0, total: active.length });
  for (const [index, step] of active.entries()) {
    if (step.target === "new") {
      const vault = await createOrganizationWorkspace(input.tenantId, input.identityId, input.rootKey, step.name || step.collection || "Imported items");
      created.push(vault); targets.set(step.collection, vault); report.workspacesCreated += 1;
      step.target = vault.workspaceId; // a retry reuses the workspace
    } else {
      const vault = input.existing.find((entry) => entry.workspaceId === step.target) ?? created.find((entry) => entry.workspaceId === step.target);
      if (!vault) throw new Error(`The workspace chosen for “${step.collection || "Imported items"}” is no longer available.`);
      targets.set(step.collection, vault);
    }
    input.onProgress?.({ phase: "workspaces", done: index + 1, total: active.length, current: step.name });
  }

  const total = active.reduce((sum, step) => sum + Math.max(0, (groups.get(step.collection)?.length ?? 0) - (input.skipCounts?.[step.collection] ?? 0)), 0);
  let done = 0;
  input.onProgress?.({ phase: "items", done, total });
  for (const step of active) {
    const vault = targets.get(step.collection)!;
    const items = (groups.get(step.collection) ?? []).slice(input.skipCounts?.[step.collection] ?? 0);
    let imported = 0;
    try {
      for (const entry of items) {
        await createVaultItem(vault, entry.kind, { version: 1, ...entry.payload, updatedAt: new Date().toISOString() });
        imported += 1; done += 1; report.itemsImported += 1;
        if (done % 5 === 0 || done === total) input.onProgress?.({ phase: "items", done, total, current: vault.name });
      }
    } catch {
      report.failures.push({ collection: step.collection, remaining: items.length - imported });
    }
  }

  const grants = active.flatMap((step) => step.members.map((member) => ({ step, member })));
  input.onProgress?.({ phase: "access", done: 0, total: grants.length });
  for (const [index, { step, member }] of grants.entries()) {
    const vault = targets.get(step.collection)!;
    if (member.identityId === input.identityId) continue;
    const key = input.sharingKeys.get(member.identityId);
    try {
      if (key) { await grantWorkspaceAccess(vault, key, member.role, "migration"); report.accessGranted += 1; }
      else { await requestMemberAccess(vault.workspaceId, member.identityId, member.role, "migration"); report.waitingForMembers.push(member.identityId); }
    } catch {
      report.failures.push({ collection: step.collection, remaining: 0 });
    }
    input.onProgress?.({ phase: "access", done: index + 1, total: grants.length });
  }
  input.onProgress?.({ phase: "done", done: 1, total: 1 });
  report.waitingForMembers = [...new Set(report.waitingForMembers)];
  return report;
}
