import type { VaultItem } from "../vault/items";
import { passwordHealth } from "../vault/tools";

const DAY = 86_400_000;
export const RECIPES = [
  { id: "weekly-health", title: "Weekly vault health review", detail: "Review weak and reused login passwords.", interval: 7 * DAY, destination: "security" },
  { id: "stale-passwords", title: "Older login review", detail: "Review login records not updated for a year. Record age does not establish password age.", interval: 7 * DAY, destination: "security" },
  { id: "device-review", title: "Monthly device review", detail: "Review trusted devices and revoke those you no longer use.", interval: 30 * DAY, destination: "devices" },
] as const;
export type RecipeId = typeof RECIPES[number]["id"];
export type Preferences = Record<RecipeId, { enabled: boolean; reviewedAt: number }>;
export type Reminder = { id: RecipeId; title: string; detail: string; itemIds: string[]; destination: "security" | "devices" };

export function preferenceKey(identityId: string, tenantId: string, workspaceId: string) {
  return `passkey-x:local-routines:v1:${encodeURIComponent(identityId)}:${encodeURIComponent(tenantId)}:${encodeURIComponent(workspaceId)}`;
}

export function parsePreferences(raw: string | null, now: number): Preferences {
  const result = Object.fromEntries(RECIPES.map(({ id }) => [id, { enabled: false, reviewedAt: 0 }])) as Preferences;
  if (!raw || raw.length > 4096) return result;
  try {
    const value = JSON.parse(raw);
    if (!value || value.version !== 1 || !value.recipes || typeof value.recipes !== "object") return result;
    for (const { id } of RECIPES) {
      const entry = value.recipes[id];
      if (!entry || typeof entry !== "object") continue;
      const reviewedAt = Number.isSafeInteger(entry.reviewedAt) && entry.reviewedAt >= 0 && entry.reviewedAt <= now ? entry.reviewedAt : 0;
      result[id] = { enabled: entry.enabled === true, reviewedAt };
    }
  } catch { /* A damaged preference must not prevent opening the vault. */ }
  return result;
}

export function serializePreferences(preferences: Preferences, now: number) {
  // Whitelist again at the persistence boundary; never serialize findings or vault data.
  return JSON.stringify({ version: 1, recipes: parsePreferences(JSON.stringify({ version: 1, recipes: preferences }), now) });
}

export function dueReminders(items: VaultItem[], preferences: Preferences, now: number): Reminder[] {
  const active = items.filter((item) => !item.deletedAt && !item.payload.archived);
  const health = passwordHealth(active, now);
  return RECIPES.filter(({ id, interval }) => preferences[id].enabled &&
    (preferences[id].reviewedAt === 0 || now < preferences[id].reviewedAt || now - preferences[id].reviewedAt >= interval))
    .map(({ id, title, destination }) => {
      if (id === "device-review") return { id, title, destination, detail: "Check your device list. Revocation requires your explicit action.", itemIds: [] };
      const findings = health.findings.filter((finding) => id === "stale-passwords" ? finding.id === "old" : finding.id === "weak" || finding.id.startsWith("reused-"));
      const itemIds = [...new Set(findings.flatMap((finding) => finding.itemIds))];
      return { id, title, destination, itemIds, detail: itemIds.length ? `${itemIds.length} login record${itemIds.length === 1 ? "" : "s"} to review.` : "No matching issues found in active login records. You can mark this review complete." };
    });
}
