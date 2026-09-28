import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

/** Policy types understood by the web client and the database validator. */
export type PolicyType =
  | "passkey_required" | "mfa_required" | "device_approval_required"
  | "minimum_vault_password" | "session_timeout_minutes" | "clipboard_clear_seconds"
  | "sharing_mode" | "export_policy" | "breach_monitoring" | "organization_recovery"
  | "password_rotation";

export type SharingMode = "open" | "internal_only" | "disabled";
export type ExportMode = "allowed" | "admins_only" | "blocked";
export type BreachMode = "off" | "optional" | "required";

export type EnterprisePolicy = {
  passkeyRequired: boolean;
  mfaRequired: boolean;
  deviceApprovalRequired: boolean;
  minVaultPasswordLength: number;
  minVaultPasswordStrength: number;
  sessionTimeoutMinutes: number;
  clipboardClearSeconds: number;
  sharingMode: SharingMode;
  exportMode: ExportMode;
  breachMonitoring: BreachMode;
  organizationRecovery: boolean;
  /** Stored secrets older than this many days are flagged for rotation. */
  passwordRotationDays: number;
  /** Which scope set each enforced value (for "managed by your organization" hints). */
  managed: Partial<Record<PolicyType, string>>;
};

export const DEFAULT_POLICY: EnterprisePolicy = Object.freeze({
  passkeyRequired: false,
  mfaRequired: false,
  deviceApprovalRequired: false,
  minVaultPasswordLength: 12,
  minVaultPasswordStrength: 0,
  sessionTimeoutMinutes: 5,
  clipboardClearSeconds: 30,
  sharingMode: "open",
  exportMode: "allowed",
  breachMonitoring: "optional",
  organizationRecovery: false,
  passwordRotationDays: 365,
  managed: {},
}) as EnterprisePolicy;

/**
 * Used while an organisation's policy is loading or could not be loaded: sensitive
 * actions stay off until the real policy arrives (fail closed).
 */
export const LOADING_POLICY: EnterprisePolicy = Object.freeze({
  ...DEFAULT_POLICY,
  sharingMode: "disabled",
  exportMode: "blocked",
  managed: {},
}) as EnterprisePolicy;

export type PolicyRow = {
  policy_type: string;
  configuration: unknown;
  source_scope_type?: string | null;
};

type Config = Record<string, unknown>;

function asConfig(value: unknown): Config {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Config : {};
}

function clampInteger(value: unknown, min: number, max: number, fallback: number) {
  const number = typeof value === "number" ? value : Number.NaN;
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.round(number)));
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value) ? value as T : fallback;
}

/**
 * Converts effective policy rows into a strongly typed policy. Unknown or malformed
 * values fall back to safe defaults; numbers are clamped to the same ranges the
 * database validator enforces.
 */
export function normalizePolicies(rows: PolicyRow[]): EnterprisePolicy {
  const policy: EnterprisePolicy = { ...DEFAULT_POLICY, managed: {} };
  for (const row of rows) {
    const config = asConfig(row.configuration);
    const scope = row.source_scope_type ?? "tenant";
    switch (row.policy_type) {
      case "passkey_required": policy.passkeyRequired = config.required === true; break;
      case "mfa_required": policy.mfaRequired = config.required === true; break;
      case "device_approval_required": policy.deviceApprovalRequired = config.required === true; break;
      case "organization_recovery": policy.organizationRecovery = config.enabled === true; break;
      case "minimum_vault_password":
        policy.minVaultPasswordLength = clampInteger(config.min_length, 12, 128, 12);
        policy.minVaultPasswordStrength = clampInteger(config.min_strength, 0, 4, 0);
        break;
      case "session_timeout_minutes":
        policy.sessionTimeoutMinutes = clampInteger(config.minutes, 1, 480, DEFAULT_POLICY.sessionTimeoutMinutes);
        break;
      case "clipboard_clear_seconds":
        policy.clipboardClearSeconds = clampInteger(config.seconds, 5, 300, DEFAULT_POLICY.clipboardClearSeconds);
        break;
      case "sharing_mode": policy.sharingMode = oneOf(config.mode, ["open", "internal_only", "disabled"] as const, "open"); break;
      case "export_policy": policy.exportMode = oneOf(config.mode, ["allowed", "admins_only", "blocked"] as const, "allowed"); break;
      case "password_rotation": policy.passwordRotationDays = clampInteger(config.days, 30, 730, 365); break;
      case "breach_monitoring": policy.breachMonitoring = oneOf(config.mode, ["off", "optional", "required"] as const, "optional"); break;
      default: continue;
    }
    policy.managed[row.policy_type as PolicyType] = scope;
  }
  return policy;
}

/** Whether the export action is allowed for someone with this tenant role. */
export function exportAllowed(policy: EnterprisePolicy, tenantRole: string | null) {
  if (policy.exportMode === "allowed") return true;
  if (policy.exportMode === "admins_only") return tenantRole === "owner" || tenantRole === "admin";
  return false;
}

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

export type PolicyState = { policy: EnterprisePolicy; tenantRole: string | null; kind: string | null };

/** Loads the caller's effective organisation policy. Personal vaults get defaults. */
export async function loadMyPolicy(tenantId: string, identityId: string): Promise<PolicyState> {
  const client = db();
  const [membership, tenant] = await Promise.all([
    client.from("tenant_memberships").select("role").eq("tenant_id", tenantId).eq("identity_id", identityId).eq("status", "active").maybeSingle(),
    client.from("tenants").select("kind").eq("id", tenantId).maybeSingle(),
  ]);
  if (membership.error) throw membership.error;
  if (tenant.error) throw tenant.error;
  const tenantRole = (membership.data as { role?: string } | null)?.role ?? null;
  const kind = (tenant.data as { kind?: string } | null)?.kind ?? null;
  if (kind !== "organization") return { policy: { ...DEFAULT_POLICY, managed: {} }, tenantRole, kind };
  const { data, error } = await client.rpc("my_organization_policies", { p_tenant_id: tenantId });
  if (error) {
    // Older databases without the v3 policy RPC keep working with defaults.
    if (error.code === "PGRST202" || error.code === "42883") return { policy: { ...DEFAULT_POLICY, managed: {} }, tenantRole, kind };
    throw error;
  }
  return { policy: normalizePolicies((data ?? []) as PolicyRow[]), tenantRole, kind };
}

// ---------------------------------------------------------------------------
// Editor catalogue used by the admin console
// ---------------------------------------------------------------------------
export type PolicyControl =
  | { kind: "toggle"; key: string }
  | { kind: "number"; key: string; min: number; max: number; step?: number; unit: string }
  | { kind: "choice"; key: string; options: { value: string; label: string }[] };

export type PolicyDefinition = {
  type: PolicyType;
  group: "Authentication" | "Vault protection" | "Data movement" | "Recovery";
  title: string;
  description: string;
  controls: PolicyControl[];
  defaults: Record<string, unknown>;
  enforcement: "server" | "client" | "server+client";
};

export const POLICY_DEFINITIONS: PolicyDefinition[] = [
  {
    type: "passkey_required", group: "Authentication", title: "Require an account passkey",
    description: "Members must register a phishing-resistant passkey before using the vault.",
    controls: [{ kind: "toggle", key: "required" }], defaults: { required: true }, enforcement: "client",
  },
  {
    type: "mfa_required", group: "Authentication", title: "Require two-step verification",
    description: "Members must enroll a second factor for account sign-in.",
    controls: [{ kind: "toggle", key: "required" }], defaults: { required: true }, enforcement: "client",
  },
  {
    type: "device_approval_required", group: "Authentication", title: "Approved devices only",
    description: "New devices need approval and a current posture report before vault access.",
    controls: [{ kind: "toggle", key: "required" }], defaults: { required: true }, enforcement: "server+client",
  },
  {
    type: "minimum_vault_password", group: "Vault protection", title: "Vault password strength",
    description: "Minimum length and estimated strength for members' vault passwords.",
    controls: [
      { kind: "number", key: "min_length", min: 12, max: 128, unit: "characters" },
      { kind: "choice", key: "min_strength", options: [
        { value: "0", label: "Any" }, { value: "2", label: "Fair" }, { value: "3", label: "Strong" }, { value: "4", label: "Very strong" },
      ] },
    ],
    defaults: { min_length: 14, min_strength: 3 }, enforcement: "client",
  },
  {
    type: "session_timeout_minutes", group: "Vault protection", title: "Automatic vault lock",
    description: "Lock the vault after this many minutes without activity.",
    controls: [{ kind: "number", key: "minutes", min: 1, max: 480, unit: "minutes" }],
    defaults: { minutes: 5 }, enforcement: "client",
  },
  {
    type: "clipboard_clear_seconds", group: "Vault protection", title: "Clear copied secrets",
    description: "Remove copied passwords from the clipboard after this many seconds.",
    controls: [{ kind: "number", key: "seconds", min: 5, max: 300, unit: "seconds" }],
    defaults: { seconds: 20 }, enforcement: "client",
  },
  {
    type: "breach_monitoring", group: "Vault protection", title: "Breached password checks",
    description: "Check passwords against known breaches using k-anonymity (only a 5-character hash prefix leaves the device).",
    controls: [{ kind: "choice", key: "mode", options: [
      { value: "off", label: "Off" }, { value: "optional", label: "Member choice" }, { value: "required", label: "Always on" },
    ] }],
    defaults: { mode: "required" }, enforcement: "client",
  },
  {
    type: "password_rotation", group: "Vault protection", title: "Password rotation",
    description: "Flag stored passwords and secrets that have not changed in this many days, with a one-click rotate action.",
    controls: [{ kind: "number", key: "days", min: 30, max: 730, unit: "days" }],
    defaults: { days: 180 }, enforcement: "client",
  },
  {
    type: "sharing_mode", group: "Data movement", title: "Sharing boundary",
    description: "Control whether members can share items and invite people outside the organization.",
    controls: [{ kind: "choice", key: "mode", options: [
      { value: "open", label: "Anyone" }, { value: "internal_only", label: "Organization members only" }, { value: "disabled", label: "Admins only" },
    ] }],
    defaults: { mode: "internal_only" }, enforcement: "server",
  },
  {
    type: "export_policy", group: "Data movement", title: "Vault export",
    description: "Decide who may download an encrypted export of vault data.",
    controls: [{ kind: "choice", key: "mode", options: [
      { value: "allowed", label: "Everyone" }, { value: "admins_only", label: "Owners and admins" }, { value: "blocked", label: "Nobody" },
    ] }],
    defaults: { mode: "admins_only" }, enforcement: "client",
  },
  {
    type: "organization_recovery", group: "Recovery", title: "Organization account recovery",
    description: "Allow designated admins to help members regain vault access. Members are told when this is on. Vlightsoft can never decrypt vaults.",
    controls: [{ kind: "toggle", key: "enabled" }], defaults: { enabled: false }, enforcement: "client",
  },
];

/** Human summary of a stored configuration, e.g. "14 characters · Strong". */
export function describePolicy(type: PolicyType, configuration: unknown) {
  const definition = POLICY_DEFINITIONS.find((entry) => entry.type === type);
  const config = asConfig(configuration);
  if (!definition) return "Custom";
  return definition.controls.map((control) => {
    const value = config[control.key];
    if (control.kind === "toggle") return value === true ? "On" : "Off";
    if (control.kind === "number") return `${String(value ?? "—")} ${control.unit}`;
    return control.options.find((option) => option.value === String(value))?.label ?? String(value ?? "—");
  }).join(" · ");
}

/** Converts editor values into the JSON configuration stored in the database. */
export function serializePolicy(type: PolicyType, values: Record<string, string | boolean>) {
  const definition = POLICY_DEFINITIONS.find((entry) => entry.type === type);
  if (!definition) throw new Error("Unknown policy.");
  const configuration: Record<string, unknown> = {};
  for (const control of definition.controls) {
    const value = values[control.key];
    if (control.kind === "toggle") configuration[control.key] = value === true;
    else if (control.kind === "number") {
      const number = Number(value);
      if (!Number.isInteger(number) || number < control.min || number > control.max) {
        throw new Error(`${definition.title}: enter a whole number between ${control.min} and ${control.max}.`);
      }
      configuration[control.key] = number;
    } else {
      const option = control.options.find((entry) => entry.value === String(value));
      if (!option) throw new Error(`${definition.title}: choose a supported option.`);
      configuration[control.key] = /^\d+$/u.test(option.value) ? Number(option.value) : option.value;
    }
  }
  return configuration;
}

// ---------------------------------------------------------------------------
// Admin persistence helpers
// ---------------------------------------------------------------------------
export type StoredPolicy = {
  id: string;
  policy_type: PolicyType;
  configuration: Record<string, unknown>;
  scope_type: "tenant" | "department" | "team";
  scope_id: string | null;
  enforced: boolean;
  version: number;
  updated_at: string | null;
};

export async function loadTenantPolicies(tenantId: string) {
  const { data, error } = await db().from("organization_policies")
    .select("id,policy_type,configuration,scope_type,scope_id,enforced,version,updated_at")
    .eq("tenant_id", tenantId).order("scope_type").order("policy_type");
  if (error) throw error;
  return (data ?? []) as StoredPolicy[];
}

/** Creates or replaces the tenant-wide value of a policy and enforces it. */
export async function saveTenantPolicy(
  tenantId: string, identityId: string, type: PolicyType, configuration: Record<string, unknown>,
) {
  const client = db();
  const existing = await client.from("organization_policies").select("id,version")
    .eq("tenant_id", tenantId).eq("scope_type", "tenant").is("scope_id", null)
    .eq("policy_type", type).maybeSingle();
  if (existing.error) throw existing.error;
  const current = existing.data as { id: string; version: number } | null;
  if (current) {
    const { error } = await client.from("organization_policies")
      .update({ configuration, enforced: true, version: current.version + 1, updated_at: new Date().toISOString() })
      .eq("id", current.id).eq("version", current.version);
    if (error) throw error;
    return;
  }
  const { error } = await client.from("organization_policies").insert({
    tenant_id: tenantId, scope_type: "tenant", scope_id: null, policy_type: type,
    configuration, created_by: identityId, version: 1, enforced: true,
  });
  if (error) throw error;
}

export async function setPolicyEnforced(policy: StoredPolicy, enforced: boolean) {
  const { error } = await db().from("organization_policies")
    .update({ enforced, version: policy.version + 1, updated_at: new Date().toISOString() })
    .eq("id", policy.id).eq("version", policy.version);
  if (error) throw error;
}

/** A defensible starting point for most organizations (SOC 2 / ISO 27001 friendly). */
export const RECOMMENDED_BASELINE: { type: PolicyType; configuration: Record<string, unknown> }[] = [
  { type: "passkey_required", configuration: { required: true } },
  { type: "mfa_required", configuration: { required: true } },
  { type: "minimum_vault_password", configuration: { min_length: 14, min_strength: 3 } },
  { type: "session_timeout_minutes", configuration: { minutes: 10 } },
  { type: "clipboard_clear_seconds", configuration: { seconds: 20 } },
  { type: "breach_monitoring", configuration: { mode: "required" } },
  { type: "password_rotation", configuration: { days: 180 } },
  { type: "sharing_mode", configuration: { mode: "internal_only" } },
  { type: "export_policy", configuration: { mode: "admins_only" } },
];

/** Percentage of the recommended baseline currently enforced tenant-wide. */
export function baselineCoverage(policies: StoredPolicy[]) {
  const enforced = new Map(policies.filter((policy) => policy.enforced && policy.scope_type === "tenant")
    .map((policy) => [policy.policy_type, policy.configuration]));
  const met = RECOMMENDED_BASELINE.filter((entry) => enforced.has(entry.type)).length;
  return { met, total: RECOMMENDED_BASELINE.length, percent: Math.round((met / RECOMMENDED_BASELINE.length) * 100) };
}
