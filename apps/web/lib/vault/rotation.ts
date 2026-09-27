import type { VaultPayload } from "@/lib/vault/items";

const DAY = 86_400_000;

/** Default age (days) after which a stored secret is flagged for rotation. */
export const ROTATION_WARNING_DAYS = 180;

/** Days since the item's secret last changed (falls back to the last edit for older items). */
export function passwordAgeDays(payload: Pick<VaultPayload, "passwordChangedAt" | "updatedAt">, now: number): number | null {
  const changed = Date.parse(payload.passwordChangedAt ?? payload.updatedAt);
  if (!Number.isFinite(changed)) return null;
  return Math.max(0, Math.floor((now - changed) / DAY));
}

export function needsRotation(payload: Pick<VaultPayload, "passwordChangedAt" | "updatedAt" | "secret">, now: number, maxAgeDays = ROTATION_WARNING_DAYS) {
  if (!payload.secret) return false;
  const age = passwordAgeDays(payload, now);
  return age !== null && age >= maxAgeDays;
}
