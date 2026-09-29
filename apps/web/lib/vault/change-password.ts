import type { VaultItem } from "@/lib/vault/items";

/**
 * The standard "/.well-known/change-password" address (W3C). Sites that support it redirect to
 * their own change-password page; others show their normal page, where the person can find it.
 * Only https sites (and plain http on localhost for testing) get a link.
 */
export function changePasswordUrl(siteUrl: string | undefined | null): string | null {
  if (!siteUrl) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/iu.test(siteUrl.trim()) ? siteUrl.trim() : `https://${siteUrl.trim()}`;
  let parsed: URL;
  try { parsed = new URL(candidate); } catch { return null; }
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) return null;
  if (!parsed.hostname.includes(".") && !loopback) return null;
  return `${parsed.origin}/.well-known/change-password`;
}

export type FixReason = "breached" | "reused" | "weak";

export type FixTask = { itemId: string; title: string; reasons: FixReason[]; changeUrl: string | null };

/**
 * The order to fix passwords in: breached first, then reused, then weak. Each item appears once
 * with every reason that applies. Items without a password are skipped.
 */
export function buildFixQueue(items: VaultItem[], report: { breached: string[]; reused: string[][]; weak: string[] }): FixTask[] {
  const byId = new Map(items.map((item) => [item.id, item]));
  const reasons = new Map<string, FixReason[]>();
  const add = (id: string, reason: FixReason) => {
    if (!byId.get(id)?.payload.secret) return;
    const list = reasons.get(id) ?? [];
    if (!list.includes(reason)) list.push(reason);
    reasons.set(id, list);
  };
  for (const id of report.breached) add(id, "breached");
  for (const id of report.reused.flat()) add(id, "reused");
  for (const id of report.weak) add(id, "weak");
  const rank = (list: FixReason[]) => (list.includes("breached") ? 0 : list.includes("reused") ? 1 : 2);
  return [...reasons.entries()]
    .map(([itemId, list]) => ({ itemId, title: byId.get(itemId)!.payload.title, reasons: list, changeUrl: changePasswordUrl(byId.get(itemId)!.payload.url) }))
    .sort((a, b) => rank(a.reasons) - rank(b.reasons) || a.title.localeCompare(b.title));
}
