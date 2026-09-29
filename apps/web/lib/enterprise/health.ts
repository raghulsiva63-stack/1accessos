import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";
import type { VaultItem } from "@/lib/vault/items";

export {
  analyzeVaultHealth, estimateStrength, healthMetrics, STRENGTH_LABELS, summarizeHealth,
  type HealthIssue, type ItemHealth, type StrengthScore, type VaultHealthReport,
} from "@/lib/security/score";
import type { VaultHealthReport } from "@/lib/security/score";
import { healthMetrics } from "@/lib/security/score";

async function sha1Hex(value: string) {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/**
 * Breach lookup with k-anonymity: only the first 5 hex characters of each SHA-1
 * hash are sent (padded responses), and matching happens on the device.
 */
export async function checkBreachedPasswords(
  items: VaultItem[],
  fetcher: typeof fetch = fetch,
  endpoint = "https://api.pwnedpasswords.com/range/",
): Promise<Map<string, number>> {
  const logins = items.filter((item) => !item.deletedAt && item.contentType === "login" && item.payload.secret);
  const hashes = new Map<string, string[]>();
  for (const item of logins) {
    const hash = await sha1Hex(item.payload.secret!);
    hashes.set(hash, [...(hashes.get(hash) ?? []), item.id]);
  }
  const prefixes = new Map<string, string[]>();
  for (const hash of hashes.keys()) prefixes.set(hash.slice(0, 5), [...(prefixes.get(hash.slice(0, 5)) ?? []), hash]);
  const result = new Map<string, number>();
  const queue = [...prefixes.entries()];
  async function worker() {
    for (let entry = queue.shift(); entry; entry = queue.shift()) {
      const [prefix, fullHashes] = entry;
      const response = await fetcher(`${endpoint}${prefix}`, { headers: { "Add-Padding": "true" }, cache: "no-store", referrerPolicy: "no-referrer", credentials: "omit" });
      if (!response.ok) throw new Error("The breach check service is unavailable. Try again later.");
      const counts = new Map<string, number>();
      for (const line of (await response.text()).split(/\r?\n/u)) {
        const [suffix, count] = line.trim().split(":");
        if (suffix && count) counts.set(suffix.toUpperCase(), Number.parseInt(count, 10) || 0);
      }
      for (const hash of fullHashes) {
        const count = counts.get(hash.slice(5)) ?? 0;
        for (const id of hashes.get(hash) ?? []) result.set(id, count);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
  hashes.clear();
  return result;
}

/**
 * Sends aggregate counts (no secrets, titles or URLs) to the organisation dashboard. Uses the v2
 * report (which also carries exposed-secret, look-alike and passkey-readiness counts) and falls
 * back to the original report while the database is being upgraded.
 */
export async function reportVaultHealth(
  tenantId: string, report: VaultHealthReport, clientKind = "web",
  readiness?: { passkeyReady: number; twoFactorReady: number },
) {
  if (!supabase) return;
  const client = supabase as unknown as SupabaseClient;
  const v2 = await client.rpc("report_security_health_v2", {
    p_tenant_id: tenantId, p_metrics: healthMetrics(report, readiness), p_client_kind: clientKind,
  });
  if (!v2.error) return;
  if (v2.error.code !== "PGRST202") throw v2.error;
  const { error } = await client.rpc("report_security_health", {
    p_tenant_id: tenantId,
    p_score: report.score,
    p_item_count: report.itemCount,
    p_login_count: report.loginCount,
    p_weak_count: report.weak.length,
    p_reused_count: new Set(report.reused.flat()).size,
    p_old_count: report.old.length,
    p_breached_count: report.breachChecked ? report.breached.length : null,
    p_missing_totp_count: report.missingTotp.length,
    p_passkey_count: report.passkeyCount,
    p_client_kind: clientKind,
  });
  if (error && error.code !== "PGRST202") throw error;
}
