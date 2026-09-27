import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";
import type { VaultItem } from "@/lib/vault/items";

/** 0 = very weak … 4 = very strong. Local estimate; nothing leaves the device. */
export type StrengthScore = 0 | 1 | 2 | 3 | 4;

const COMMON = new Set([
  "password", "passw0rd", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey",
  "dragon", "football", "baseball", "master", "sunshine", "princess", "login", "abc123",
  "123456", "12345678", "123456789", "1234567890", "111111", "000000", "trustno1",
]);

const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm", "01234567890"];

function hasSequence(value: string, length = 4) {
  const lower = value.toLowerCase();
  for (const sequence of SEQUENCES) {
    for (let index = 0; index + length <= sequence.length; index += 1) {
      const run = sequence.slice(index, index + length);
      if (lower.includes(run) || lower.includes([...run].reverse().join(""))) return true;
    }
  }
  return false;
}

/**
 * Conservative entropy estimate with penalties for common words, repeats and
 * keyboard/alphabet sequences. Returns estimated bits and a 0–4 score.
 */
export function estimateStrength(password: string): { bits: number; score: StrengthScore } {
  if (!password) return { bits: 0, score: 0 };
  let pool = 0;
  if (/[a-z]/u.test(password)) pool += 26;
  if (/[A-Z]/u.test(password)) pool += 26;
  if (/\d/u.test(password)) pool += 10;
  if (/[^A-Za-z0-9\s]/u.test(password)) pool += 33;
  if (/\s/u.test(password)) pool += 1;
  if ([...password].some((character) => (character.codePointAt(0) ?? 0) > 127)) pool += 64;
  const unique = new Set(password).size;
  let bits = password.length * Math.log2(Math.max(pool, 2));
  // Low character variety dominates length (e.g. "aaaaaaaaaaaa").
  bits = Math.min(bits, unique * Math.log2(Math.max(pool, 2)) * 1.6 + password.length);
  const normalized = password.toLowerCase().replace(/[@4]/gu, "a").replace(/[3]/gu, "e").replace(/[1!|]/gu, "i").replace(/[0]/gu, "o").replace(/[$5]/gu, "s");
  for (const word of COMMON) {
    if (normalized.includes(word)) bits -= word.length * 3.5;
  }
  if (/(.)\1{2,}/u.test(password)) bits -= 10;
  if (hasSequence(password)) bits -= 12;
  if (/^(19|20)\d{2}$|(19|20)\d{2}$/u.test(password)) bits -= 6;
  bits = Math.max(0, Math.round(bits));
  const score: StrengthScore = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { bits, score };
}

export const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"] as const;

export type HealthIssue = "weak" | "reused" | "old" | "breached" | "missing_totp" | "insecure_url";

export type ItemHealth = {
  itemId: string;
  title: string;
  issues: HealthIssue[];
  strength: StrengthScore;
  breachCount?: number;
};

export type VaultHealthReport = {
  score: number;
  itemCount: number;
  loginCount: number;
  passkeyCount: number;
  weak: string[];
  reused: string[][];
  old: string[];
  breached: string[];
  missingTotp: string[];
  insecureUrl: string[];
  items: ItemHealth[];
  breachChecked: boolean;
};

const DAY = 86_400_000;

function totpPresent(item: VaultItem) {
  const fields = item.payload.fields ?? {};
  return Object.entries(fields).some(([key, value]) => /totp|otp|2fa|mfa|authenticator/iu.test(key) && Boolean(value?.trim()));
}

/**
 * Analyses decrypted items in memory. `breaches` maps item id → breach count from a
 * k-anonymity lookup (omit when the check has not run).
 */
export function analyzeVaultHealth(items: VaultItem[], breaches?: Map<string, number>, now = Date.now()): VaultHealthReport {
  const active = items.filter((item) => !item.deletedAt && !item.payload.archived);
  const logins = active.filter((item) => item.contentType === "login" && item.payload.secret);
  const bySecret = new Map<string, string[]>();
  for (const item of logins) bySecret.set(item.payload.secret!, [...(bySecret.get(item.payload.secret!) ?? []), item.id]);
  const reused = [...bySecret.values()].filter((group) => group.length > 1);
  const reusedIds = new Set(reused.flat());
  const perItem: ItemHealth[] = [];
  const weak: string[] = []; const old: string[] = []; const breached: string[] = [];
  const missingTotp: string[] = []; const insecureUrl: string[] = [];
  for (const item of logins) {
    const issues: HealthIssue[] = [];
    const strength = estimateStrength(item.payload.secret!).score;
    if (strength <= 1) { issues.push("weak"); weak.push(item.id); }
    if (reusedIds.has(item.id)) issues.push("reused");
    const updated = Date.parse(item.payload.updatedAt);
    if (Number.isFinite(updated) && now - updated > 365 * DAY) { issues.push("old"); old.push(item.id); }
    const breachCount = breaches?.get(item.id);
    if (breachCount && breachCount > 0) { issues.push("breached"); breached.push(item.id); }
    if (item.payload.url && !totpPresent(item)) { missingTotp.push(item.id); }
    if (item.payload.url?.startsWith("http://")) { issues.push("insecure_url"); insecureUrl.push(item.id); }
    if (issues.length) perItem.push({ itemId: item.id, title: item.payload.title, issues, strength, breachCount });
  }
  const loginCount = logins.length;
  const penalty = loginCount === 0 ? 0 : Math.min(100,
    (breached.length * 25 + reusedIds.size * 10 + weak.length * 8 + old.length * 2 + insecureUrl.length * 3) * (20 / Math.max(20, loginCount)));
  return {
    score: Math.max(0, Math.round(100 - penalty)),
    itemCount: active.length,
    loginCount,
    passkeyCount: active.filter((item) => item.contentType === "passkey").length,
    weak, reused, old, breached, missingTotp, insecureUrl,
    items: perItem.sort((a, b) => b.issues.length - a.issues.length),
    breachChecked: Boolean(breaches),
  };
}

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

/** Sends aggregate counts (no secrets, titles or URLs) to the organisation dashboard. */
export async function reportVaultHealth(tenantId: string, report: VaultHealthReport, clientKind = "web") {
  if (!supabase) return;
  const { error } = await (supabase as unknown as SupabaseClient).rpc("report_security_health", {
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
