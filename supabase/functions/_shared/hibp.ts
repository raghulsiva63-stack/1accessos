// Have I Been Pwned "breachedaccount" parsing. Pure (no Deno or network) for unit tests.

export type BreachRecord = { name: string; title: string; domain: string | null; date: string | null; data_classes: string[] };

type RawBreach = {
  Name?: unknown; Title?: unknown; Domain?: unknown; BreachDate?: unknown; DataClasses?: unknown;
  IsFabricated?: unknown; IsSpamList?: unknown; IsRetired?: unknown;
};

/** Keeps real breaches only (no fabricated, spam-list or retired entries) and only safe fields. */
export function parseBreaches(payload: unknown): BreachRecord[] {
  if (!Array.isArray(payload)) throw new Error("invalid_hibp_response");
  const result: BreachRecord[] = [];
  for (const entry of payload.slice(0, 1000) as RawBreach[]) {
    if (!entry || typeof entry !== "object") continue;
    if (entry.IsFabricated === true || entry.IsSpamList === true || entry.IsRetired === true) continue;
    const name = typeof entry.Name === "string" ? entry.Name.trim() : "";
    if (!/^[A-Za-z0-9 _.()-]{1,100}$/u.test(name)) continue;
    const title = typeof entry.Title === "string" && entry.Title.trim() ? entry.Title.trim().slice(0, 160) : name;
    const domain = typeof entry.Domain === "string" && /^[a-z0-9.-]{1,253}$/iu.test(entry.Domain) ? entry.Domain.toLowerCase() : null;
    const date = typeof entry.BreachDate === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(entry.BreachDate) ? entry.BreachDate : null;
    const classes = Array.isArray(entry.DataClasses)
      ? entry.DataClasses.filter((value): value is string => typeof value === "string").map((value) => value.slice(0, 60)).slice(0, 60)
      : [];
    result.push({ name, title, domain, date, data_classes: classes });
  }
  return result;
}

export function breachedAccountUrl(email: string): string {
  return `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email.trim())}?truncateResponse=false`;
}

/** Milliseconds to wait between requests for a plan's requests-per-minute limit. */
export function spacingMs(requestsPerMinute: number): number {
  const rpm = Number.isFinite(requestsPerMinute) && requestsPerMinute > 0 ? Math.min(requestsPerMinute, 1000) : 10;
  return Math.ceil(60_000 / rpm) + 100;
}
