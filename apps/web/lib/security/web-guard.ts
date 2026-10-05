// Passkey-X Web Guard: decides whether a web page is safe, suspicious or dangerous. Pure and
// on-device; shared by the browser extension, the desktop app and the mobile app.
//
// Signals:
// * threat lists (Google Web Risk, licensed feeds, Passkey-X community reports, the
//   organization's block list) matched by hash prefix (see url-hash.ts);
// * look-alikes of the sites in the person's vault, of well-known brands, and of the
//   organization's own domains (homoglyphs, punycode, "brand.com.evil.site" tricks, typos);
// * risky page context: a password form on plain HTTP, an IP address or data: page asking for a
//   login, an unusual top-level domain asking for a login;
// * a vault password typed into a different site (password reuse / credential phishing).
//
// Only the verdict (site, reason) is ever reported to the organization, never browsing history.

import { assessSite, LOOKALIKE_EXPLANATIONS, type LookalikeReason } from "./phishing";
import { hostnameOf, registrableDomain } from "./domains";
import { hashedExpressions, PrefixSet, toBase64, prefixBytes } from "./url-hash";

export type GuardLevel = "safe" | "suspicious" | "dangerous";
export type ThreatType = "phishing" | "malware" | "unwanted" | "blocked";

export type GuardReason =
  | { code: "threat_list"; threat: ThreatType; source: string }
  | { code: "blocked_by_org" }
  | { code: "lookalike"; resembles: string; reason: LookalikeReason; of: "vault" | "brand" | "organization" }
  | { code: "insecure_login" }
  | { code: "ip_login" }
  | { code: "data_url" }
  | { code: "unusual_ending" }
  | { code: "password_reuse"; savedSite: string };

export type GuardVerdict = { level: GuardLevel; domain: string | null; reasons: GuardReason[] };

export type GuardPolicy = {
  webMode: "off" | "warn" | "block";
  /** Also stop on "suspicious" pages (default: only "dangerous" ones). */
  blockSuspicious: boolean;
  allowDomains: string[];
  blockDomains: string[];
  /** The organization's own domains, protected against look-alikes. */
  protectedDomains: string[];
  organizationName: string | null;
  communityIntel: boolean;
};

export const DEFAULT_GUARD_POLICY: GuardPolicy = {
  webMode: "warn", blockSuspicious: false, allowDomains: [], blockDomains: [], protectedDomains: [],
  organizationName: null, communityIntel: true,
};

/** Frequently impersonated sites. Look-alikes of these are flagged even if they are not in the vault. */
export const KNOWN_BRANDS = [
  "paypal.com", "microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com", "sharepoint.com",
  "google.com", "gmail.com", "apple.com", "icloud.com", "amazon.com", "facebook.com", "instagram.com", "whatsapp.com",
  "netflix.com", "linkedin.com", "dropbox.com", "docusign.com", "adobe.com", "github.com", "gitlab.com", "okta.com",
  "salesforce.com", "slack.com", "zoom.us", "atlassian.net", "chase.com", "wellsfargo.com", "bankofamerica.com",
  "americanexpress.com", "citi.com", "capitalone.com", "hsbc.com", "barclays.co.uk", "coinbase.com", "binance.com",
  "kraken.com", "metamask.io", "dhl.com", "fedex.com", "ups.com", "usps.com", "royalmail.com", "ebay.com",
  "yahoo.com", "steamcommunity.com", "roblox.com", "telegram.org", "twitter.com", "booking.com", "airbnb.com",
  "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "paytm.com", "phonepe.com", "irctc.co.in",
  "passkey-x.com",
];

// Real sites whose names are close to a brand above; never flagged as look-alikes of it.
const BRAND_LOOKALIKE_ALLOW = new Set([
  "paypay.ne.jp", "office.net", "live.net", "gmail.co", "outlook.live.com", "apple.news", "amazon.co.uk", "amazon.de",
  "amazon.in", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amazon.com.au", "amazonaws.com",
  "google.co.uk", "google.co.in", "google.de", "google.fr", "googleapis.com", "googleusercontent.com", "gstatic.com",
  "microsoft365.com", "office365.com", "skype.com", "ebay.co.uk", "ebay.de", "ups.de", "dhl.de", "yahoo.co.jp",
]);

const UNUSUAL_ENDINGS = new Set(["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
  "rest", "cam", "quest", "sbs", "cfd", "lol", "icu", "buzz", "monster", "bond", "cyou"]);

export function normalizeDomain(value: string): string | null {
  const host = hostnameOf(value.trim().replace(/^\*\./u, ""));
  return host && /^[a-z0-9.-]+$/u.test(host) && host.includes(".") ? host : null;
}

/** True when the host is the domain or one of its subdomains. */
export function matchesDomain(host: string, domains: Iterable<string>): boolean {
  for (const raw of domains) {
    const domain = normalizeDomain(raw);
    if (domain && (host === domain || host.endsWith(`.${domain}`))) return true;
  }
  return false;
}

const LEVEL_RANK: Record<GuardLevel, number> = { safe: 0, suspicious: 1, dangerous: 2 };

function raise(verdict: GuardVerdict, level: GuardLevel, reason: GuardReason) {
  verdict.reasons.push(reason);
  if (LEVEL_RANK[level] > LEVEL_RANK[verdict.level]) verdict.level = level;
}

export type PageContext = {
  /** Sites saved in the person's vault (when it is unlocked). */
  savedUrls?: Iterable<string | null | undefined>;
  /** The page shows a password field (reported by the content script). */
  hasPasswordField?: boolean;
  /** Registrable domains known to be legitimate (for example the public 2FA directory). */
  isKnownLegitimate?: (domain: string) => boolean;
};

/** Checks that need no network: look-alikes, organization lists and page context. */
export function assessPageLocally(url: string, policy: GuardPolicy = DEFAULT_GUARD_POLICY, context: PageContext = {}): GuardVerdict {
  let parsed: URL;
  try { parsed = new URL(url); } catch { return { level: "safe", domain: null, reasons: [] }; }
  if (parsed.protocol === "data:" || parsed.protocol === "blob:") {
    const verdict: GuardVerdict = { level: "safe", domain: null, reasons: [] };
    if (context.hasPasswordField) raise(verdict, "dangerous", { code: "data_url" });
    return verdict;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { level: "safe", domain: null, reasons: [] };
  const host = parsed.hostname.toLowerCase().replace(/\.$/u, "");
  const domain = /^\d+\.\d+\.\d+\.\d+$/u.test(host) || host.startsWith("[") ? host : registrableDomain(host.replace(/^www\./u, ""));
  const verdict: GuardVerdict = { level: "safe", domain, reasons: [] };
  if (["localhost", "127.0.0.1", "[::1]"].includes(host)) return verdict;
  if (matchesDomain(host, policy.allowDomains)) return verdict;
  if (matchesDomain(host, policy.blockDomains)) raise(verdict, "dangerous", { code: "blocked_by_org" });

  const legitimate = context.isKnownLegitimate?.(domain) ?? false;
  // Look-alike of a site in the vault (strongest: the person has an account there).
  const saved = context.savedUrls ? [...context.savedUrls] : [];
  if (saved.length) {
    const vault = assessSite(url, saved);
    if (vault.kind === "trusted") return verdict.reasons.length ? verdict : { level: "safe", domain, reasons: [] };
    if (vault.kind === "lookalike" && !legitimate) {
      const strong = vault.reason === "punycode" || vault.reason === "homoglyph" || vault.reason === "subdomain_trick";
      raise(verdict, strong ? "dangerous" : "suspicious", { code: "lookalike", resembles: vault.resembles, reason: vault.reason, of: "vault" });
    }
  }
  // Look-alike of the organization's own domains or of a well-known brand.
  for (const [list, of] of [[policy.protectedDomains, "organization"], [KNOWN_BRANDS, "brand"]] as const) {
    if (verdict.reasons.some((reason) => reason.code === "lookalike")) break;
    const domains = list.map((entry) => normalizeDomain(entry)).filter((entry): entry is string => Boolean(entry));
    if (!domains.length || BRAND_LOOKALIKE_ALLOW.has(domain) || legitimate) continue;
    const brand = assessSite(url, domains);
    if (brand.kind !== "lookalike") continue;
    const embedded = host.startsWith(`${brand.resembles}.`) || host.includes(`.${brand.resembles}.`);
    const strong = brand.reason === "punycode" || brand.reason === "homoglyph" || (brand.reason === "subdomain_trick" && embedded);
    // Weaker hints (typos, "brand-login.site") only matter where a password is asked for.
    if (strong) raise(verdict, "dangerous", { code: "lookalike", resembles: brand.resembles, reason: brand.reason, of });
    else if (context.hasPasswordField) raise(verdict, "suspicious", { code: "lookalike", resembles: brand.resembles, reason: brand.reason, of });
  }
  if (context.hasPasswordField) {
    if (parsed.protocol === "http:") raise(verdict, "suspicious", { code: "insecure_login" });
    if (/^\d+\.\d+\.\d+\.\d+$/u.test(host) || host.startsWith("[")) raise(verdict, "suspicious", { code: "ip_login" });
    const ending = host.split(".").pop() ?? "";
    if (UNUSUAL_ENDINGS.has(ending) && !legitimate) raise(verdict, "suspicious", { code: "unusual_ending" });
  }
  return verdict;
}

// ---------------------------------------------------------------------------
// Threat lists
// ---------------------------------------------------------------------------

export type ThreatMatch = { hash: string; threat: ThreatType; source: string };

/**
 * Looks the address up in the threat lists. The local prefix sets decide whether the server is
 * asked at all; only matching 4-byte prefixes are sent, and full hashes are compared here.
 */
export async function lookupThreats(
  url: string,
  sets: PrefixSet[],
  confirm: (prefixes: string[]) => Promise<ThreatMatch[]>,
): Promise<ThreatMatch | null> {
  const expressions = await hashedExpressions(url);
  const hits = expressions.filter((entry) => sets.some((set) => set.has(entry.prefix)));
  if (!hits.length) return null;
  const prefixes = [...new Set(hits.map((entry) => toBase64(prefixBytes(entry.prefix))))];
  const matches = await confirm(prefixes);
  const full = new Map(hits.map((entry) => [toBase64(entry.hash), entry]));
  const order: Record<ThreatType, number> = { malware: 0, phishing: 1, blocked: 2, unwanted: 3 };
  const found = matches.filter((match) => full.has(match.hash)).sort((a, b) => order[a.threat] - order[b.threat]);
  return found[0] ?? null;
}

export function withThreat(verdict: GuardVerdict, match: ThreatMatch | null): GuardVerdict {
  if (!match) return verdict;
  const next: GuardVerdict = { ...verdict, reasons: [...verdict.reasons] };
  raise(next, match.threat === "unwanted" ? "suspicious" : "dangerous", { code: "threat_list", threat: match.threat, source: match.source });
  return next;
}

/** What to do with a verdict under the organization's policy. */
export function guardAction(verdict: GuardVerdict, policy: GuardPolicy): "none" | "notice" | "warn" | "block" {
  if (policy.webMode === "off" || verdict.level === "safe") return "none";
  if (verdict.level === "suspicious") return policy.blockSuspicious ? (policy.webMode === "block" ? "block" : "warn") : "notice";
  return policy.webMode === "block" ? "block" : "warn";
}

/** Did the person type a vault password into a different site? Returns that site. */
export function passwordReuseSite(pageUrl: string, typed: string, credentials: { url: string; secret: string }[]): string | null {
  const host = hostnameOf(pageUrl);
  if (!host || typed.length < 6) return null;
  const domain = registrableDomain(host);
  let other: string | null = null;
  for (const credential of credentials) {
    const savedHost = hostnameOf(credential.url);
    if (!savedHost) continue;
    const savedDomain = registrableDomain(savedHost);
    if (savedDomain === domain) return null; // saved for this site too
    if (credential.secret === typed) other ??= savedDomain;
  }
  return other;
}

// ---------------------------------------------------------------------------
// Wording (shared by the warning page, the desktop alert and the admin console)
// ---------------------------------------------------------------------------

const THREAT_TITLES: Record<ThreatType, string> = {
  phishing: "Deceptive site ahead",
  malware: "This site may install harmful software",
  unwanted: "This site may trick you into installing unwanted programs",
  blocked: "Your organization blocks this site",
};

export function describeReason(reason: GuardReason): string {
  switch (reason.code) {
    case "threat_list": return reason.threat === "blocked" ? "This site is on your organization's block list." : `This site is on a ${reason.threat === "malware" ? "malware" : reason.threat === "unwanted" ? "harmful downloads" : "phishing"} list (${reason.source}).`;
    case "blocked_by_org": return "Your organization blocks this site.";
    case "lookalike": return `The address ${LOOKALIKE_EXPLANATIONS[reason.reason]} ${reason.resembles}${reason.of === "vault" ? ", where you have a saved login" : reason.of === "organization" ? ", your organization's site" : ""}.`;
    case "insecure_login": return "This page asks for a password without encryption (HTTP). Anyone on the network can read it.";
    case "ip_login": return "This page asks for a password on a bare IP address instead of a website name.";
    case "data_url": return "This login form was created inside the browser address bar, a common phishing trick.";
    case "unusual_ending": return "This login page uses a website ending that is often used for scams.";
    case "password_reuse": return `You entered the password you use for ${reason.savedSite} on a different site.`;
  }
}

export function verdictTitle(verdict: GuardVerdict): string {
  const threat = verdict.reasons.find((reason): reason is Extract<GuardReason, { code: "threat_list" }> => reason.code === "threat_list");
  if (threat) return THREAT_TITLES[threat.threat];
  if (verdict.reasons.some((reason) => reason.code === "blocked_by_org")) return THREAT_TITLES.blocked;
  const lookalike = verdict.reasons.find((reason): reason is Extract<GuardReason, { code: "lookalike" }> => reason.code === "lookalike");
  if (lookalike) return `This site is pretending to be ${lookalike.resembles}`;
  if (verdict.reasons.some((reason) => reason.code === "password_reuse")) return "Your password was entered on another site";
  return verdict.level === "dangerous" ? "Dangerous site" : "Be careful on this site";
}

/** Short machine kind for reports: phishing_site, malware_site, lookalike_site, ... */
export function verdictKind(verdict: GuardVerdict): string {
  const first = verdict.reasons[0];
  if (!first) return "safe";
  switch (first.code) {
    case "threat_list": return `${first.threat === "blocked" ? "blocked" : first.threat}_site`;
    case "blocked_by_org": return "blocked_site";
    case "lookalike": return "lookalike_site";
    case "password_reuse": return "password_reuse";
    default: return first.code;
  }
}
