/**
 * Breach Watch: a weekly, on-device re-check of saved passwords against Have I Been Pwned
 * (k-anonymity, see checkBreachedPasswords). Only item ids and timestamps are remembered, in
 * this browser; passwords, hashes, titles and sites are never stored or sent to Passkey-X.
 * It is off until the person turns it on (or their organisation requires breach monitoring).
 */

export const BREACH_WATCH_INTERVAL_DAYS = 7;
const DAY = 86_400_000;

export type BreachWatchState = {
  enabled: boolean;
  /** ISO time of the last completed check, or null if it has never run on this device. */
  lastCheckedAt: string | null;
  /** Item ids that were breached at the last check. */
  known: string[];
  /** Item ids first seen as breached at the last check and not yet reviewed. */
  fresh: string[];
};

export const EMPTY_BREACH_WATCH: BreachWatchState = { enabled: false, lastCheckedAt: null, known: [], fresh: [] };

export function breachWatchKey(identityId: string, tenantId: string) {
  return `px-breach-watch:${identityId}:${tenantId}`;
}

function ids(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string" && entry.length <= 64).slice(0, 5_000) : [];
}

export function parseBreachWatch(raw: string | null): BreachWatchState {
  try {
    const parsed = JSON.parse(raw ?? "null") as Partial<BreachWatchState> | null;
    if (!parsed || typeof parsed !== "object") return { ...EMPTY_BREACH_WATCH };
    const checked = typeof parsed.lastCheckedAt === "string" && Number.isFinite(Date.parse(parsed.lastCheckedAt)) ? parsed.lastCheckedAt : null;
    return { enabled: parsed.enabled === true, lastCheckedAt: checked, known: ids(parsed.known), fresh: ids(parsed.fresh) };
  } catch {
    return { ...EMPTY_BREACH_WATCH };
  }
}

/** True when a watch is on and the last check is older than the interval (or never ran). */
export function breachCheckDue(state: BreachWatchState, now = Date.now(), intervalDays = BREACH_WATCH_INTERVAL_DAYS) {
  if (!state.enabled) return false;
  if (!state.lastCheckedAt) return true;
  return now - Date.parse(state.lastCheckedAt) >= intervalDays * DAY;
}

/**
 * Folds a fresh check into the stored state. Items breached now but not at the previous check
 * are "fresh" (a new alert). The very first check sets a baseline: everything breached is
 * reported once so the person sees it, then only changes alert.
 */
export function applyBreachResults(state: BreachWatchState, results: Map<string, number>, liveItemIds: Iterable<string>, now = Date.now()): BreachWatchState {
  const live = new Set(liveItemIds);
  const breached = [...results.entries()].filter(([id, count]) => count > 0 && live.has(id)).map(([id]) => id).sort();
  const previous = new Set(state.known);
  const newlyBreached = breached.filter((id) => !previous.has(id));
  const stillFresh = state.fresh.filter((id) => breached.includes(id));
  return {
    enabled: state.enabled,
    lastCheckedAt: new Date(now).toISOString(),
    known: breached,
    fresh: [...new Set([...stillFresh, ...newlyBreached])].sort(),
  };
}

/** Marks the current alerts as reviewed. */
export function acknowledgeBreaches(state: BreachWatchState): BreachWatchState {
  return { ...state, fresh: [] };
}

export function nextCheckLabel(state: BreachWatchState, now = Date.now(), intervalDays = BREACH_WATCH_INTERVAL_DAYS) {
  if (!state.enabled) return "Breach Watch is off";
  if (!state.lastCheckedAt) return "First check runs now";
  const days = Math.ceil((Date.parse(state.lastCheckedAt) + intervalDays * DAY - now) / DAY);
  return days <= 0 ? "Checking now" : days === 1 ? "Next check tomorrow" : `Next check in ${days} days`;
}

// Results of the latest check in this tab, kept in memory only, so the Security screen can show
// them without checking again. Cleared when the page reloads or the vault locks.
const recent = new Map<string, Map<string, number>>();

export function rememberBreachResults(tenantId: string, results: Map<string, number>) {
  recent.set(tenantId, new Map(results));
}

export function recallBreachResults(tenantId: string | null): Map<string, number> | undefined {
  const results = tenantId ? recent.get(tenantId) : undefined;
  return results ? new Map(results) : undefined;
}

export function forgetBreachResults() {
  recent.clear();
}
