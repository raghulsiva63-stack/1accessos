// Passkey-X Guard: calls to the database (as the signed-in person; the database decides what they
// may see or change).

import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";
import type { Severity } from "@/lib/security/endpoint-guard";

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

async function rpc<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
  const { data, error } = await db().rpc(name, args);
  if (error) throw error;
  return data as T;
}

export async function hasSession(): Promise<boolean> {
  if (!supabase) return false;
  const { data } = await supabase.auth.getSession();
  return Boolean(data.session);
}

export type GuardPolicyRecord = {
  webMode: "off" | "warn" | "block";
  blockSuspicious: boolean;
  requireExtension: boolean;
  requireDesktop: boolean;
  allowDomains: string[];
  blockDomains: string[];
  protectedDomains: string[];
  softwareBlock: string[];
  softwareAllow: string[];
  communityIntel: boolean;
  organizationName: string | null;
  managed?: boolean;
};

export const EMPTY_GUARD_POLICY: GuardPolicyRecord = {
  webMode: "warn", blockSuspicious: false, requireExtension: false, requireDesktop: false, allowDomains: [], blockDomains: [],
  protectedDomains: [], softwareBlock: [], softwareAllow: [], communityIntel: true, organizationName: null,
};

const strings = (value: unknown) => Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];

export function parseGuardPolicy(value: unknown): GuardPolicyRecord {
  const raw = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  const pick = (camel: string, snake: string) => raw[camel] ?? raw[snake];
  const mode = pick("webMode", "web_mode");
  return {
    webMode: mode === "off" || mode === "block" ? mode : "warn",
    blockSuspicious: pick("blockSuspicious", "block_suspicious") === true,
    requireExtension: pick("requireExtension", "require_extension") === true,
    requireDesktop: pick("requireDesktop", "require_desktop") === true,
    allowDomains: strings(pick("allowDomains", "allow_domains")),
    blockDomains: strings(pick("blockDomains", "block_domains")),
    protectedDomains: strings(pick("protectedDomains", "protected_domains")),
    softwareBlock: strings(pick("softwareBlock", "software_block")),
    softwareAllow: strings(pick("softwareAllow", "software_allow")),
    communityIntel: pick("communityIntel", "community_intel") !== false,
    organizationName: typeof pick("organizationName", "organization_name") === "string" ? pick("organizationName", "organization_name") as string : null,
    managed: raw.managed === true,
  };
}

export const myGuardPolicy = () => rpc<unknown>("my_guard_policy").then(parseGuardPolicy);
export const setGuardPolicy = (tenantId: string, policy: GuardPolicyRecord) => rpc<void>("set_guard_policy", { p_tenant_id: tenantId, p_policy: policy });

export type GuardFindingInput = {
  source: "extension" | "desktop" | "mobile" | "web";
  category: "web" | "software" | "device" | "account";
  kind: string;
  severity: Severity;
  subject: string;
  detail: Record<string, unknown>;
  action: "warned" | "blocked" | "proceeded" | "reported" | "detected";
  key?: string;
};

export const reportGuardEndpoint = (args: {
  installId: string; kind: "desktop" | "extension" | "mobile"; platform: string; label: string; osVersion: string | null;
  appVersion: string | null; posture: Record<string, boolean | number>; softwareTotal?: number | null; softwareRisky?: number | null;
}) => rpc<string>("report_guard_endpoint", {
  p_install_id: args.installId, p_kind: args.kind, p_platform: args.platform, p_label: args.label.slice(0, 80),
  p_os_version: args.osVersion?.slice(0, 60) ?? null, p_app_version: args.appVersion?.slice(0, 30) ?? null, p_posture: args.posture,
  p_software_total: args.softwareTotal ?? null, p_software_risky: args.softwareRisky ?? null, p_protection_on: true,
});

export async function reportGuardFindings(installId: string, findings: GuardFindingInput[]) {
  for (let index = 0; index < findings.length; index += 50) {
    await rpc<number>("report_guard_findings", { p_install_id: installId, p_findings: findings.slice(index, index + 50) });
  }
}

export const resolveGuardFindings = (installId: string, keys: string[]) =>
  keys.length ? rpc<number>("resolve_guard_findings", { p_install_id: installId, p_keys: keys }) : Promise.resolve(0);

// ---------------------------------------------------------------------------
// The person's own devices and warnings
// ---------------------------------------------------------------------------

export type GuardEndpoint = {
  id: string; kind: "desktop" | "extension" | "mobile"; platform: string; label: string; os_version: string | null; app_version: string | null;
  posture: Record<string, boolean | number>; software_total: number | null; software_risky: number | null; protection_on: boolean; last_seen_at: string;
};
export type GuardFinding = {
  id: number; source: string; category: string; kind: string; severity: Severity; subject: string; detail: Record<string, unknown>;
  action: string; status: "open" | "resolved" | "dismissed"; occurrences: number; first_seen_at: string; last_seen_at: string;
};

export async function myGuardOverview(): Promise<{ endpoints: GuardEndpoint[]; findings: GuardFinding[] }> {
  const [endpoints, findings] = await Promise.all([
    db().from("guard_endpoints").select("id,kind,platform,label,os_version,app_version,posture,software_total,software_risky,protection_on,last_seen_at")
      .eq("identity_id", (await currentIdentity()) ?? "").order("last_seen_at", { ascending: false }).limit(50),
    db().from("guard_findings").select("id,source,category,kind,severity,subject,detail,action,status,occurrences,first_seen_at,last_seen_at")
      .eq("identity_id", (await currentIdentity()) ?? "").order("last_seen_at", { ascending: false }).limit(100),
  ]);
  if (endpoints.error) throw endpoints.error;
  if (findings.error) throw findings.error;
  return { endpoints: (endpoints.data ?? []) as GuardEndpoint[], findings: (findings.data ?? []) as GuardFinding[] };
}

let identityRequest: Promise<string | null> | null = null;
function currentIdentity(): Promise<string | null> {
  identityRequest ??= (async () => {
    const { data: user } = await db().auth.getUser();
    if (!user.user) return null;
    const { data } = await db().from("identities").select("id").eq("auth_user_id", user.user.id).maybeSingle();
    return (data as { id?: string } | null)?.id ?? null;
  })().finally(() => { setTimeout(() => { identityRequest = null; }, 60_000); });
  return identityRequest;
}

// ---------------------------------------------------------------------------
// Organization Threat Center
// ---------------------------------------------------------------------------

export type GuardOverview = {
  members: number;
  open: Record<Severity, number>;
  last7Days: { blocked: number; warned: number; proceeded: number; reported: number };
  coverage: { desktop: number; extension: number; mobile: number; any: number };
  devices: { total: number; atRisk: number };
  pendingReports: number;
  policy: Record<string, unknown>;
};
export type OrganizationFinding = GuardFinding & { identity_id: string; member_email: string | null; member_name: string; endpoint_label: string | null; platform: string | null };
export type OrganizationEndpoint = GuardEndpoint & { identity_id: string; member_email: string | null; member_name: string; open_findings: number };
export type ThreatReport = { id: number; member_email: string | null; expression: string; host: string; note: string | null; status: string; created_at: string; confirmed_elsewhere: number };

export const organizationGuardOverview = (tenantId: string) => rpc<GuardOverview>("organization_guard_overview", { p_tenant_id: tenantId });
export const organizationGuardFindings = (tenantId: string, status: "open" | "resolved" | "dismissed" | null = "open", category: string | null = null) =>
  rpc<OrganizationFinding[]>("organization_guard_findings", { p_tenant_id: tenantId, p_status: status, p_category: category, p_limit: 300 }).then((rows) => rows ?? []);
export const organizationGuardEndpoints = (tenantId: string) =>
  rpc<OrganizationEndpoint[]>("organization_guard_endpoints", { p_tenant_id: tenantId }).then((rows) => rows ?? []);
export const setGuardFindingStatus = (tenantId: string, findingId: number, status: "open" | "resolved" | "dismissed") =>
  rpc<void>("set_guard_finding_status", { p_tenant_id: tenantId, p_finding_id: findingId, p_status: status });
export const organizationThreatReports = (tenantId: string, status: "pending" | "confirmed" | "rejected" | null = "pending") =>
  rpc<ThreatReport[]>("organization_threat_reports", { p_tenant_id: tenantId, p_status: status }).then((rows) => rows ?? []);
export const reviewThreatReport = (tenantId: string, reportId: number, confirm: boolean) =>
  rpc<void>("review_threat_report", { p_tenant_id: tenantId, p_report_id: reportId, p_confirm: confirm });

// ---------------------------------------------------------------------------
// Wording for findings (admin console, member view, desktop and mobile)
// ---------------------------------------------------------------------------

export const FINDING_LABELS: Record<string, string> = {
  phishing_site: "Phishing site", malware_site: "Malware site", unwanted_site: "Harmful downloads site", blocked_site: "Blocked by policy",
  lookalike_site: "Look-alike site", insecure_login: "Login without encryption", ip_login: "Login on an IP address", data_url: "Login form in the address bar",
  unusual_ending: "Suspicious login page", password_reuse: "Password reused on another site", reported_site: "Reported as phishing",
  disputed_warning: "Warning disputed", compromised_software: "Compromised software", piracy_tool: "Piracy tool", unsupported_software: "Unsupported software",
  remote_access_tool: "Remote-control software", unwanted_software: "Unwanted software", crypto_miner: "Crypto miner", p2p_software: "File-sharing software",
  blocked_software: "Blocked software", os_unsupported: "Unsupported OS", os_support_ending: "OS support ending", disk_not_encrypted: "Disk not encrypted",
  firewall_off: "Firewall off", antivirus_off: "Antivirus off", auto_updates_off: "Updates off", gatekeeper_off: "Gatekeeper off",
  no_screen_lock: "No screen lock", rooted_device: "Rooted device", usb_debugging_on: "USB debugging on", unknown_sources_allowed: "Unknown app sources",
  browser_unprotected: "Browser not protected",
};

export const findingLabel = (kind: string) => FINDING_LABELS[kind] ?? kind.replace(/_/gu, " ");
