// Browser-side calls for the security intelligence features. Every call runs as the signed-in
// person; the database decides what they may see or change.

import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";
import { webUrl } from "@/lib/desktop/bridge";
import type { SiteDirectory } from "@/lib/security/site-directory";
import type { PolicyRecommendation, TriageItem } from "@/lib/security/ai-output";

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

async function rpc<T>(name: string, args: Record<string, unknown>): Promise<T> {
  const { data, error } = await db().rpc(name, args);
  if (error) throw error;
  return data as T;
}

// ---------------------------------------------------------------------------
// Sign-in activity
// ---------------------------------------------------------------------------
export type AccountSession = {
  session_id: string; created_at: string; last_active_at: string; device_label: string;
  network_label: string | null; country: string | null; two_step: boolean; is_current: boolean;
};
export type SignInRecord = {
  id: string; auth_session_id: string; device_label: string; network_label: string | null; country: string | null;
  new_device: boolean; new_network: boolean; new_country: boolean; created_at: string;
};
export type NotificationPreferences = { new_sign_in_email: boolean; breach_email: boolean; weekly_report_email: boolean };

export const listMySessions = () => rpc<AccountSession[]>("my_sessions", {}).then((rows) => rows ?? []);
export const revokeMySession = (sessionId: string) => rpc<boolean>("revoke_my_session", { p_session_id: sessionId });

export async function signOutOtherSessions() {
  const { error } = await db().auth.signOut({ scope: "others" });
  if (error) throw error;
}

export async function listMySignIns(limit = 25): Promise<SignInRecord[]> {
  const { data, error } = await db().from("account_sign_ins")
    .select("id,auth_session_id,device_label,network_label,country,new_device,new_network,new_country,created_at")
    .order("created_at", { ascending: false }).limit(limit);
  if (error) throw error;
  return (data ?? []) as SignInRecord[];
}

export async function loadNotificationPreferences(): Promise<NotificationPreferences> {
  const { data, error } = await db().from("account_notification_preferences")
    .select("new_sign_in_email,breach_email,weekly_report_email").maybeSingle();
  if (error) throw error;
  return (data as NotificationPreferences | null) ?? { new_sign_in_email: true, breach_email: true, weekly_report_email: true };
}

export const saveNotificationPreferences = (value: NotificationPreferences) =>
  rpc<void>("set_my_notification_preferences", { p_new_sign_in: value.new_sign_in_email, p_breach: value.breach_email, p_weekly_report: value.weekly_report_email });

/** Once per session: lets the server attach the sign-in country (see sign-in-context function). */
export async function reportSignInContext() {
  const { data } = await db().auth.getSession();
  const session = data.session;
  if (!session?.access_token) return;
  const marker = `px-signin-context:${session.access_token.split(".")[1]?.slice(-16) ?? ""}`;
  try { if (sessionStorage.getItem(marker)) return; sessionStorage.setItem(marker, "1"); } catch { /* storage may be unavailable */ }
  await fetch(webUrl("/api/security/sign-in-context"), {
    method: "POST", headers: { Authorization: `Bearer ${session.access_token}` }, credentials: "omit", cache: "no-store",
  }).catch(() => undefined);
}

// ---------------------------------------------------------------------------
// 2FA / passkey site directory (downloaded whole, matched on the device)
// ---------------------------------------------------------------------------
const DIRECTORY_CACHE = "px-site-directory-v1";
let directoryPromise: Promise<SiteDirectory | null> | null = null;

export function loadSiteDirectory(): Promise<SiteDirectory | null> {
  if (directoryPromise) return directoryPromise;
  directoryPromise = (async () => {
    try {
      const cached = JSON.parse(localStorage.getItem(DIRECTORY_CACHE) ?? "null") as { savedAt: number; directory: SiteDirectory } | null;
      if (cached && Date.now() - cached.savedAt < 3 * 86_400_000 && cached.directory?.sites) return cached.directory;
    } catch { /* ignore a damaged cache */ }
    try {
      const response = await fetch(webUrl("/api/security/site-directory"), { credentials: "omit" });
      if (!response.ok) return null;
      const directory = await response.json() as SiteDirectory;
      if (!directory || typeof directory.sites !== "object") return null;
      try { localStorage.setItem(DIRECTORY_CACHE, JSON.stringify({ savedAt: Date.now(), directory })); } catch { /* quota */ }
      return directory;
    } catch {
      return null;
    }
  })();
  return directoryPromise;
}

// ---------------------------------------------------------------------------
// Rotation tasks and breach exposures (member view)
// ---------------------------------------------------------------------------
export type RotationTask = {
  id: string; campaign_id: string; item_id: string; workspace_id: string; status: "pending" | "done" | "skipped" | "cancelled";
  created_at: string; campaign: { title: string; reason: string | null; due_at: string; status: string } | null;
};

export async function listMyRotationTasks(identityId: string): Promise<RotationTask[]> {
  const { data, error } = await db().from("rotation_tasks")
    .select("id,campaign_id,item_id,workspace_id,status,created_at,campaign:rotation_campaigns(title,reason,due_at,status)")
    .eq("assignee_identity_id", identityId).eq("status", "pending").order("created_at", { ascending: true }).limit(500);
  if (error) throw error;
  return ((data ?? []) as unknown as RotationTask[]).filter((task) => task.campaign?.status === "open");
}

export const updateRotationTask = (taskId: string, status: "skipped" | "pending", note?: string) =>
  rpc<void>("update_rotation_task", { p_task_id: taskId, p_status: status, p_note: note ?? null });

export type BreachExposure = {
  tenant_id: string; identity_id: string; breach_name: string; breach_title: string; breach_domain: string | null;
  breach_date: string | null; data_classes: string[]; includes_passwords: boolean; first_seen_at: string; acknowledged_at: string | null;
  member_acknowledged_at: string | null;
};

export async function listBreachExposures(tenantId: string, identityId?: string): Promise<BreachExposure[]> {
  let query = db().from("member_breach_exposures")
    .select("tenant_id,identity_id,breach_name,breach_title,breach_domain,breach_date,data_classes,includes_passwords,first_seen_at,acknowledged_at,member_acknowledged_at")
    .eq("tenant_id", tenantId);
  if (identityId) query = query.eq("identity_id", identityId);
  const { data, error } = await query.order("breach_date", { ascending: false, nullsFirst: false }).limit(500);
  if (error) throw error;
  return (data ?? []) as BreachExposure[];
}

export const acknowledgeBreachExposure = (tenantId: string, identityId: string, breachName: string) =>
  rpc<boolean>("acknowledge_breach_exposure", { p_tenant_id: tenantId, p_identity_id: identityId, p_breach_name: breachName });

// ---------------------------------------------------------------------------
// Organization (admin) views
// ---------------------------------------------------------------------------
export type TrendPoint = { day: string; average_score: number | null; members_reporting: number; weak: number; reused: number; breached: number; exposed_secrets: number };
export type TeamHealth = { department_id: string | null; department_name: string; members: number; members_reporting: number; average_score: number | null; weak: number; reused: number; breached: number; exposed_secrets: number };
export type MemberBreachSummary = { identity_id: string; email: string | null; display_name: string; exposures: number; password_exposures: number; unacknowledged: number; latest_breach_date: string | null; last_checked_at: string | null };
export type PasskeyAdoptionRow = { identity_id: string; email: string | null; display_name: string; account_passkeys: number; two_step_methods: number; vault_passkeys: number; passkey_ready_sites: number; last_nudged_at: string | null };
export type RotationCampaign = { id: string; title: string; reason: string | null; due_at: string; status: "open" | "closed"; created_at: string; total: number; done: number; skipped: number; pending: number; cancelled: number; overdue: boolean };
export type SecurityReport = {
  generated_at: string; members: number; members_reporting: number; score: number | null; score_week_ago: number | null;
  weak: number; reused: number; breached: number; exposed_secrets: number; old: number; lookalike_sites: number;
  two_step_pct: number; passkey_pct: number; alerts_open: Record<"critical" | "high" | "medium" | "low", number>; alerts_new_7d: number;
  members_in_breaches: number; breach_exposures_new_7d: number; rotation_pending: number; rotation_overdue: number;
  unfamiliar_sign_ins_7d: number; policies_enforced: number; top_risks: { key: string; count: number }[]; all_risks?: { key: string; count: number }[];
};
export type StoredReport = { week_start: string; report: SecurityReport; ai_summary: string | null; ai_generated_at: string | null; created_at: string };

export const organizationHealthTrend = (tenantId: string, days = 30) => rpc<TrendPoint[]>("organization_health_trend", { p_tenant_id: tenantId, p_days: days }).then((rows) => rows ?? []);
export const organizationHealthByTeam = (tenantId: string) => rpc<TeamHealth[]>("organization_health_by_team", { p_tenant_id: tenantId }).then((rows) => rows ?? []);
export const organizationBreachWatch = (tenantId: string) => rpc<MemberBreachSummary[]>("organization_breach_watch", { p_tenant_id: tenantId }).then((rows) => rows ?? []);
export const setBreachWatch = (tenantId: string, enabled: boolean) => rpc<void>("set_breach_watch", { p_tenant_id: tenantId, p_enabled: enabled });
export const organizationPasskeyAdoption = (tenantId: string) => rpc<PasskeyAdoptionRow[]>("organization_passkey_adoption", { p_tenant_id: tenantId }).then((rows) => rows ?? []);
export const sendPasskeyNudges = (tenantId: string, identityIds: string[]) => rpc<number>("send_passkey_nudges", { p_tenant_id: tenantId, p_identity_ids: identityIds });
export const rotationCampaignSummary = (tenantId: string) => rpc<RotationCampaign[]>("rotation_campaign_summary", { p_tenant_id: tenantId }).then((rows) => rows ?? []);
export const closeRotationCampaign = (campaignId: string) => rpc<void>("close_rotation_campaign", { p_campaign_id: campaignId });
export const generateSecurityReportNow = (tenantId: string) => rpc<SecurityReport>("generate_security_report_now", { p_tenant_id: tenantId });

export function createRotationCampaign(tenantId: string, title: string, reason: string, dueAt: Date, tasks: { itemId: string; assigneeIdentityId: string }[]) {
  return rpc<string>("create_rotation_campaign", {
    p_tenant_id: tenantId, p_title: title, p_reason: reason || null, p_due_at: dueAt.toISOString(),
    p_tasks: tasks.map((task) => ({ item_id: task.itemId, assignee_identity_id: task.assigneeIdentityId })),
  });
}

export async function breachWatchEnabled(tenantId: string): Promise<boolean> {
  const { data, error } = await db().from("breach_watch_settings").select("enabled").eq("tenant_id", tenantId).maybeSingle();
  if (error) throw error;
  return Boolean((data as { enabled?: boolean } | null)?.enabled);
}

export async function listWeeklyReports(tenantId: string, limit = 12): Promise<StoredReport[]> {
  const { data, error } = await db().from("weekly_security_reports")
    .select("week_start,report,ai_summary,ai_generated_at,created_at").eq("tenant_id", tenantId)
    .order("week_start", { ascending: false }).limit(limit);
  if (error) throw error;
  return (data ?? []) as StoredReport[];
}

export async function workspaceEditors(tenantId: string, workspaceId: string): Promise<string[]> {
  const { data, error } = await db().from("workspace_memberships").select("identity_id,role,status")
    .eq("tenant_id", tenantId).eq("workspace_id", workspaceId).eq("status", "active").in("role", ["owner", "manager", "editor"]);
  if (error) throw error;
  return ((data ?? []) as { identity_id: string }[]).map((row) => row.identity_id);
}

// ---------------------------------------------------------------------------
// Organization AI (Business plan credits; counts only)
// ---------------------------------------------------------------------------
export type SecurityAiResult =
  | { useCase: "alert_triage"; summary: string; items: TriageItem[] }
  | { useCase: "policy_advisor"; summary: string; recommendations: PolicyRecommendation[] }
  | { useCase: "weekly_summary"; summary: string };

export class SecurityAiError extends Error {
  constructor(public code: "limit_reached" | "forbidden" | "unavailable") { super(code); }
}

export async function askSecurityAi(tenantId: string, useCase: SecurityAiResult["useCase"]): Promise<SecurityAiResult> {
  const { data } = await db().auth.getSession();
  if (!data.session?.access_token) throw new SecurityAiError("forbidden");
  const response = await fetch(webUrl("/api/ai/security-advice"), {
    method: "POST",
    headers: { Authorization: `Bearer ${data.session.access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ tenantId, useCase }),
  });
  const payload = await response.json().catch(() => ({})) as { advice?: string; result?: { summary?: string; items?: TriageItem[]; recommendations?: PolicyRecommendation[] }; error?: string };
  if (response.status === 429) throw new SecurityAiError("limit_reached");
  if (response.status === 403 || response.status === 401) throw new SecurityAiError("forbidden");
  if (!response.ok || typeof payload.advice !== "string") throw new SecurityAiError("unavailable");
  if (useCase === "alert_triage") return { useCase, summary: payload.result?.summary ?? payload.advice, items: payload.result?.items ?? [] };
  if (useCase === "policy_advisor") return { useCase, summary: payload.result?.summary ?? payload.advice, recommendations: payload.result?.recommendations ?? [] };
  return { useCase, summary: payload.advice };
}

export function aiErrorMessage(reason: unknown) {
  if (reason instanceof SecurityAiError && reason.code === "limit_reached") return "Your organization has used its AI credits for now (they refill monthly), or the hourly limit was reached.";
  if (reason instanceof SecurityAiError && reason.code === "forbidden") return "Only owners, admins, security admins and auditors on the Business plan can use this.";
  return "The AI assistant is unavailable right now. Nothing was changed and no vault data was sent.";
}
