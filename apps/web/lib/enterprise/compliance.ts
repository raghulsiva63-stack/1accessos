import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type ComplianceSnapshot = {
  generated_at: string;
  members: { active: number; suspended: number; owners_admins: number; with_mfa: number };
  vault_health: { reporters: number; avg_score: number | null; weak: number | null; reused: number | null; old: number | null; breached: number | null; passkeys: number | null; logins: number | null } | null;
  policies: { type: string; scope: string; configuration: Record<string, unknown> }[];
  activity_30d: { secret_access: number; exports: number; policy_changes: number; emergency_events: number; total: number } | null;
  alerts: { open: number; open_high: number; last_30d: number } | null;
  temporary_access_members: number;
  audit_streaming: { enabled: number; last_success: string | null } | null;
  emergency_access: { active_grants: number; break_glass: number } | null;
};

export type ControlResult = { id: string; title: string; frameworks: string; status: "pass" | "partial" | "fail"; evidence: string };

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

export async function loadComplianceSnapshot(tenantId: string): Promise<ComplianceSnapshot> {
  const { data, error } = await db().rpc("organization_compliance_snapshot", { p_tenant_id: tenantId });
  if (error) throw error;
  return data as ComplianceSnapshot;
}

export async function listComplianceHistory(tenantId: string): Promise<{ period: string; snapshot: ComplianceSnapshot }[]> {
  const { data, error } = await db().from("compliance_snapshots").select("period,snapshot").eq("tenant_id", tenantId)
    .order("period", { ascending: false }).limit(12);
  if (error) throw error;
  return (data ?? []) as { period: string; snapshot: ComplianceSnapshot }[];
}

function enforced(snapshot: ComplianceSnapshot, type: string) {
  return snapshot.policies.find((policy) => policy.type === type && policy.scope === "tenant");
}

function percent(part: number, whole: number) {
  return whole ? Math.round((part / whole) * 100) : 0;
}

/**
 * Maps the metadata-only snapshot to common control objectives. This is evidence to
 * support an audit (SOC 2, ISO 27001), not a certification.
 */
export function evaluateControls(snapshot: ComplianceSnapshot, chainVerified: boolean | null): ControlResult[] {
  const active = snapshot.members.active;
  const mfaCoverage = percent(snapshot.members.with_mfa, active);
  const mfaPolicy = enforced(snapshot, "mfa_required") ?? enforced(snapshot, "passkey_required");
  const passwordPolicy = enforced(snapshot, "minimum_vault_password");
  const timeout = enforced(snapshot, "session_timeout_minutes");
  const exportPolicy = enforced(snapshot, "export_policy");
  const sharing = enforced(snapshot, "sharing_mode");
  const breach = enforced(snapshot, "breach_monitoring");
  const rotation = enforced(snapshot, "password_rotation");
  const health = snapshot.vault_health;
  const streaming = snapshot.audit_streaming;
  const alerts = snapshot.alerts;
  const minutes = Number(timeout?.configuration.minutes ?? 0);
  return [
    { id: "mfa", title: "Multi-factor authentication for all members", frameworks: "SOC 2 CC6.1 · ISO 27001 A.8.5",
      status: mfaPolicy && mfaCoverage === 100 ? "pass" : mfaPolicy || mfaCoverage >= 80 ? "partial" : "fail",
      evidence: `${mfaCoverage}% of ${active} active members have a verified second factor; ${mfaPolicy ? "required by policy" : "not required by policy"}.` },
    { id: "password", title: "Strong vault passwords", frameworks: "SOC 2 CC6.1 · ISO 27001 A.5.17",
      status: passwordPolicy ? "pass" : "fail",
      evidence: passwordPolicy ? `Minimum ${String(passwordPolicy.configuration.min_length)} characters enforced.` : "No minimum vault password policy." },
    { id: "session", title: "Automatic session lock", frameworks: "SOC 2 CC6.1 · ISO 27001 A.8.5",
      status: timeout && minutes <= 15 ? "pass" : timeout ? "partial" : "fail",
      evidence: timeout ? `Vaults lock after ${minutes} minutes of inactivity.` : "Default 5-minute lock; not enforced by policy." },
    { id: "dlp", title: "Data export and sharing controls", frameworks: "SOC 2 CC6.7 · ISO 27001 A.5.14",
      status: exportPolicy && sharing ? "pass" : exportPolicy || sharing ? "partial" : "fail",
      evidence: `Export: ${String(exportPolicy?.configuration.mode ?? "not restricted")}; sharing: ${String(sharing?.configuration.mode ?? "not restricted")}. ${snapshot.activity_30d?.exports ?? 0} exports in 30 days.` },
    { id: "credential-hygiene", title: "Credential hygiene monitoring", frameworks: "SOC 2 CC7.1 · ISO 27001 A.5.17",
      status: breach && rotation ? "pass" : breach || rotation ? "partial" : "fail",
      evidence: health ? `${health.reporters} members reporting; average score ${health.avg_score ?? "—"}; ${health.weak ?? 0} weak, ${health.reused ?? 0} reused, ${health.breached ?? 0} breached, ${health.old ?? 0} due for rotation.` : "No vault health reports yet." },
    { id: "privileged", title: "Least privilege for administrators", frameworks: "SOC 2 CC6.3 · ISO 27001 A.8.2",
      status: snapshot.members.owners_admins <= Math.max(2, Math.ceil(active * 0.2)) ? "pass" : "partial",
      evidence: `${snapshot.members.owners_admins} owners/admins out of ${active} active members; ${snapshot.temporary_access_members} time-limited workspace grants.` },
    { id: "audit", title: "Tamper-evident audit logging", frameworks: "SOC 2 CC7.2 · ISO 27001 A.8.15",
      status: chainVerified === false ? "fail" : streaming && streaming.enabled > 0 && chainVerified ? "pass" : "partial",
      evidence: `${snapshot.activity_30d?.total ?? 0} events in 30 days; hash chain ${chainVerified === null ? "not verified in this report" : chainVerified ? "verified intact" : "FAILED verification"}; ${streaming?.enabled ?? 0} SIEM stream(s) active.` },
    { id: "monitoring", title: "Security event monitoring and response", frameworks: "SOC 2 CC7.3 · ISO 27001 A.5.25",
      status: (alerts?.open_high ?? 0) === 0 ? "pass" : "partial",
      evidence: `${alerts?.last_30d ?? 0} alerts in 30 days; ${alerts?.open ?? 0} open (${alerts?.open_high ?? 0} critical/high).` },
    { id: "continuity", title: "Emergency and break-glass access", frameworks: "SOC 2 A1.2 · ISO 27001 A.5.29",
      status: (snapshot.emergency_access?.break_glass ?? 0) > 0 ? "pass" : "partial",
      evidence: `${snapshot.emergency_access?.break_glass ?? 0} break-glass grants and ${snapshot.emergency_access?.active_grants ?? 0} emergency grants configured.` },
  ];
}

export function complianceCsv(controls: ControlResult[], snapshot: ComplianceSnapshot) {
  const cell = (value: string) => {
    const safe = /^[=+\-@\t\r]/u.test(value) ? `'${value}` : value;
    return /[",\n\r]/u.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
  };
  return [
    ["control", "frameworks", "status", "evidence"].join(","),
    ...controls.map((control) => [control.title, control.frameworks, control.status, control.evidence].map(cell).join(",")),
    "",
    `generated_at,${cell(snapshot.generated_at)}`,
  ].join("\r\n");
}
