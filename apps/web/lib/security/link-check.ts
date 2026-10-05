// "Check a link": someone pastes or shares a suspicious link and Passkey-X says whether it is safe.
// The look-alike and policy checks run on the device. Because the person asked about this link,
// its 4-byte hash prefixes (never the address) are sent to the threat-check service, which
// answers with full hashes that are compared here.

import { supabase } from "@/lib/supabase/client";
import {
  assessPageLocally, DEFAULT_GUARD_POLICY, describeReason, verdictTitle, withThreat,
  type GuardPolicy, type GuardVerdict, type ThreatMatch,
} from "@/lib/security/web-guard";
import { canonicalExpression, hashedExpressions, prefixBytes, sha256Bytes, toBase64 } from "@/lib/security/url-hash";
import { hasSession, myGuardPolicy } from "@/lib/security/guard-client";

export type LinkCheckResult = { url: string; host: string; verdict: GuardVerdict; title: string; reasons: string[]; checkedLists: boolean };

/** Accepts "example.com/x" as well as full http(s) links. */
export function normalizeLink(input: string): string | null {
  const value = input.trim();
  if (!value || value.length > 2048) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:/iu.test(value) ? value : `https://${value}`);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname.includes(".") && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

async function remoteMatches(url: string): Promise<ThreatMatch[] | null> {
  if (!supabase || !(await hasSession())) return null;
  const expressions = await hashedExpressions(url);
  const prefixes = [...new Set(expressions.map((entry) => toBase64(prefixBytes(entry.prefix))))].slice(0, 32);
  if (!prefixes.length) return [];
  const { data, error } = await supabase.functions.invoke<{ matches?: ThreatMatch[] }>("threat-check", { body: { prefixes } });
  if (error) return null;
  const full = new Set(expressions.map((entry) => toBase64(entry.hash)));
  return (data?.matches ?? []).filter((match) => full.has(match.hash));
}

export async function checkLink(input: string, savedUrls: string[] = []): Promise<LinkCheckResult | null> {
  const url = normalizeLink(input);
  if (!url) return null;
  let policy: GuardPolicy = DEFAULT_GUARD_POLICY;
  if (await hasSession().catch(() => false)) {
    try { const record = await myGuardPolicy(); policy = { ...DEFAULT_GUARD_POLICY, ...record, webMode: record.webMode === "off" ? "warn" : record.webMode }; } catch { /* defaults */ }
  }
  // A link someone asks about is checked as if it asked for a password: weak hints count too.
  let verdict = assessPageLocally(url, policy, { savedUrls, hasPasswordField: true });
  const matches = await remoteMatches(url).catch(() => null);
  if (matches?.length) {
    const order: Record<string, number> = { malware: 0, phishing: 1, blocked: 2, unwanted: 3 };
    verdict = withThreat(verdict, [...matches].sort((a, b) => order[a.threat] - order[b.threat])[0]);
  }
  return {
    url, host: new URL(url).hostname, verdict, title: verdict.level === "safe" ? "No known threats found" : verdictTitle(verdict),
    reasons: verdict.reasons.map(describeReason), checkedLists: matches !== null,
  };
}

/** Reports a page as phishing for the organization to review. */
export async function reportPhishingLink(url: string, note?: string): Promise<boolean> {
  if (!supabase) return false;
  const canonical = canonicalExpression(url);
  if (!canonical) return false;
  const expression = `${canonical.host}${canonical.path}`;
  const { error } = await supabase.rpc("report_phishing" as never, {
    p_expression: expression, p_host: canonical.host, p_hash: toBase64(await sha256Bytes(expression)), p_note: note?.slice(0, 300) ?? null,
  } as never);
  return !error;
}

// A link shared to the Android app waits here until the link check opens.
let pending: string | null = null;
export function setPendingLink(url: string) {
  pending = url;
  if (typeof window !== "undefined") window.dispatchEvent(new Event("passkey-x:check-link"));
}
export function takePendingLink(): string | null { const value = pending; pending = null; return value; }
