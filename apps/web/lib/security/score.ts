// The single Passkey-X security score. Home, Security, reminders and the organization dashboard
// all use this analysis. Runs in memory on the device; nothing here touches the network.

import type { VaultItem } from "@/lib/vault/items";
import { needsRotation } from "../vault/rotation";
import { lookalikePairs } from "./phishing";
import { scanForExposedSecrets, type SecretFinding } from "./secret-scan";

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

export type HealthIssue = "weak" | "reused" | "old" | "breached" | "missing_totp" | "insecure_url" | "exposed_secret" | "lookalike";

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
  /** Secrets (API keys, private keys, card numbers) found in notes or custom fields. */
  exposedSecrets: SecretFinding[];
  /** Saved logins whose website looks like another saved website. */
  lookalikes: ReturnType<typeof lookalikePairs>;
  items: ItemHealth[];
  breachChecked: boolean;
};

function totpPresent(item: VaultItem) {
  const fields = item.payload.fields ?? {};
  return Object.entries(fields).some(([key, value]) => /totp|otp|2fa|mfa|authenticator/iu.test(key) && Boolean(value?.trim()));
}

/**
 * Analyses decrypted items in memory. `breaches` maps item id → breach count from a
 * k-anonymity lookup (omit when the check has not run).
 */
export function analyzeVaultHealth(items: VaultItem[], breaches?: Map<string, number>, now = Date.now(), rotationDays = 365): VaultHealthReport {
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
    if (needsRotation(item.payload, now, rotationDays)) { issues.push("old"); old.push(item.id); }
    const breachCount = breaches?.get(item.id);
    if (breachCount && breachCount > 0) { issues.push("breached"); breached.push(item.id); }
    if (item.payload.url && !totpPresent(item)) { missingTotp.push(item.id); }
    if (item.payload.url?.startsWith("http://")) { issues.push("insecure_url"); insecureUrl.push(item.id); }
    if (issues.length) perItem.push({ itemId: item.id, title: item.payload.title, issues, strength, breachCount });
  }
  const exposedSecrets = scanForExposedSecrets(active);
  const lookalikes = lookalikePairs(logins.map((item) => ({ id: item.id, url: item.payload.url })));
  const byItem = new Map(perItem.map((entry) => [entry.itemId, entry]));
  const flag = (id: string, issue: HealthIssue) => {
    const item = active.find((candidate) => candidate.id === id);
    if (!item) return;
    const entry = byItem.get(id) ?? { itemId: id, title: item.payload.title, issues: [], strength: item.payload.secret ? estimateStrength(item.payload.secret).score : 4 };
    if (!entry.issues.includes(issue)) entry.issues.push(issue);
    if (!byItem.has(id)) { byItem.set(id, entry); perItem.push(entry); }
  };
  for (const finding of exposedSecrets) flag(finding.itemId, "exposed_secret");
  for (const pair of lookalikes) { flag(pair.itemId, "lookalike"); flag(pair.otherId, "lookalike"); }
  const exposedItems = new Set(exposedSecrets.map((finding) => finding.itemId)).size;
  const loginCount = logins.length;
  const scale = 20 / Math.max(20, loginCount + exposedItems);
  const penalty = loginCount === 0 && exposedItems === 0 ? 0 : Math.min(100,
    (breached.length * 25 + lookalikes.length * 15 + reusedIds.size * 10 + weak.length * 8 + exposedItems * 6
      + old.length * 2 + insecureUrl.length * 3) * scale);
  return {
    score: Math.max(0, Math.round(100 - penalty)),
    itemCount: active.length,
    loginCount,
    passkeyCount: active.filter((item) => item.contentType === "passkey").length,
    weak, reused, old, breached, missingTotp, insecureUrl, exposedSecrets, lookalikes,
    items: perItem.sort((a, b) => b.issues.length - a.issues.length),
    breachChecked: Boolean(breaches),
  };
}

/** Counts sent to the organization dashboard (report_security_health_v2). Never titles, sites or secrets. */
export function healthMetrics(report: VaultHealthReport, readiness?: { passkeyReady: number; twoFactorReady: number }) {
  return {
    score: report.score,
    items: report.itemCount,
    logins: report.loginCount,
    weak: report.weak.length,
    reused: new Set(report.reused.flat()).size,
    old: report.old.length,
    breached: report.breachChecked ? report.breached.length : null,
    missing_totp: report.missingTotp.length,
    passkeys: report.passkeyCount,
    exposed_secrets: new Set(report.exposedSecrets.map((finding) => finding.itemId)).size,
    lookalikes: report.lookalikes.length,
    passkey_ready: readiness?.passkeyReady ?? 0,
    two_factor_ready: readiness?.twoFactorReady ?? 0,
  };
}

export type HealthFinding = {
  id: string;
  severity: "critical" | "warning" | "good";
  title: string;
  detail: string;
  itemIds: string[];
};

/** The summary used on Home and by local reminders. Same analysis as the Security page. */
export function summarizeHealth(report: VaultHealthReport) {
  const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
  const findings: HealthFinding[] = [
    ...(report.breached.length ? [{ id: "breached", severity: "critical" as const, title: "Passwords found in breaches",
      detail: `${plural(report.breached.length, "login")} use a password that appears in known data breaches. Change them first.`, itemIds: report.breached }] : []),
    ...(report.lookalikes.length ? [{ id: "lookalike", severity: "critical" as const, title: "Look-alike websites saved",
      detail: `${plural(report.lookalikes.length, "pair")} of saved sites look alike. One may be a phishing copy.`, itemIds: [...new Set(report.lookalikes.flatMap((pair) => [pair.itemId, pair.otherId]))] }] : []),
    ...report.reused.map((group, index) => ({ id: `reused-${index}`, severity: "critical" as const, title: "Reused password",
      detail: `${group.length} logins share the same password. Change each to a unique value.`, itemIds: group })),
    ...(report.weak.length ? [{ id: "weak", severity: "warning" as const, title: "Weak passwords",
      detail: `${plural(report.weak.length, "login")} should use a longer, more varied password.`, itemIds: report.weak }] : []),
    ...(report.exposedSecrets.length ? [{ id: "exposed", severity: "warning" as const, title: "Secrets stored in notes",
      detail: `${plural(new Set(report.exposedSecrets.map((finding) => finding.itemId)).size, "item")} keep API keys, private keys or card numbers in plain-view notes.`,
      itemIds: [...new Set(report.exposedSecrets.map((finding) => finding.itemId))] }] : []),
    ...(report.old.length ? [{ id: "old", severity: "warning" as const, title: "Passwords due for rotation",
      detail: `${plural(report.old.length, "login")} have not changed in a long time.`, itemIds: report.old }] : []),
  ];
  return {
    score: report.score,
    findings: findings.length ? findings : [{ id: "healthy", severity: "good" as const, title: "No obvious password risks",
      detail: "Passkey-X found no breached, reused, weak or stale passwords in this vault.", itemIds: [] }],
    loginCount: report.loginCount,
  };
}
