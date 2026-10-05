// Passkey-X Web Guard in the browser: checks every page the person opens.
//
// * Local checks (look-alikes, organization lists, risky login pages) run on every navigation.
// * Threat lists: the device keeps the published hash-prefix list (downloaded when its version
//   changes) and the organization's own prefixes. Only when a page's prefix matches does it ask
//   the server, sending the 4-byte prefix, never the address.
// * Dangerous pages are replaced by a full-page warning (warning.html). Depending on the
//   organization's policy the person may go back only (block) or proceed after a warning (warn).
// * Findings (site + reason + what happened) are reported to the person's organization; normal
//   browsing is never reported.

import type { SupabaseClient } from "@supabase/supabase-js";
import {
  assessPageLocally, DEFAULT_GUARD_POLICY, describeReason, guardAction, lookupThreats, verdictKind, verdictTitle, withThreat,
  type GuardPolicy, type GuardVerdict, type ThreatMatch,
} from "../../web/lib/security/web-guard";
import { canonicalExpression, fromBase64, prefixOf, PrefixSet, sha256Bytes, toBase64 } from "../../web/lib/security/url-hash";

const DB = "passkey-x-guard";
const INTEL_REFRESH_MS = 6 * 60 * 60_000;
const VERDICT_TTL_MS = 30 * 60_000;
const BYPASS_KEY = "pxGuardBypass";
const INSTALL_KEY = "pxGuardInstall";

type Finding = {
  source: "extension"; category: "web" | "account"; kind: string; severity: "critical" | "high" | "medium" | "low";
  subject: string; detail: Record<string, unknown>; action: "warned" | "blocked" | "proceeded" | "reported" | "detected"; key?: string;
};

export type GuardDecision = {
  action: "none" | "notice" | "warn" | "block";
  verdict: GuardVerdict;
  title: string;
  reasons: string[];
  organizationName: string | null;
};

type Options = {
  supabase: SupabaseClient;
  supabaseUrl: string;
  publishableKey: string;
  savedUrls: () => string[];
  onAlert: (alert: { level: string; title: string; detail: string; site: string }) => void;
};

let options: Options | null = null;
let policy: GuardPolicy = DEFAULT_GUARD_POLICY;
let globalSet = PrefixSet.empty();
let organizationSet = PrefixSet.empty();
let intelCheckedAt = 0;
let intelLoading: Promise<void> | null = null;
const verdicts = new Map<string, { verdict: GuardVerdict; at: number }>();
const queue: Finding[] = [];
let flushTimer: ReturnType<typeof setTimeout> | undefined;

export function configureGuard(value: Options) { options = value; }
export function currentPolicy(): GuardPolicy { return policy; }

// ---------------------------------------------------------------------------
// Local storage of the prefix list (IndexedDB) and the install id
// ---------------------------------------------------------------------------

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains("intel")) request.result.createObjectStore("intel"); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function idb<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  const database = await db();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = database.transaction("intel", mode);
      const request = action(transaction.objectStore("intel"));
      transaction.oncomplete = () => resolve(request.result as T);
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

export async function installId(): Promise<string> {
  const stored = (await chrome.storage.local.get(INSTALL_KEY))[INSTALL_KEY];
  if (typeof stored === "string" && /^[0-9a-f-]{36}$/u.test(stored)) return stored;
  const id = crypto.randomUUID();
  await chrome.storage.local.set({ [INSTALL_KEY]: id });
  return id;
}

async function accessToken(): Promise<string | null> {
  if (!options) return null;
  const { data } = await options.supabase.auth.getSession();
  return data.session?.access_token ?? null;
}

async function callFunction<T>(name: string, body: unknown): Promise<T | null> {
  const token = await accessToken();
  if (!options || !token) return null;
  const response = await fetch(`${options.supabaseUrl}/functions/v1/${name}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, apikey: options.publishableKey, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) { await response.body?.cancel(); return null; }
  return await response.json() as T;
}

function parsePolicy(value: unknown): GuardPolicy {
  const raw = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  const list = (key: string) => Array.isArray(raw[key]) ? (raw[key] as unknown[]).filter((entry): entry is string => typeof entry === "string").slice(0, 2000) : [];
  const mode = raw.webMode === "off" || raw.webMode === "block" ? raw.webMode : "warn";
  return {
    webMode: mode, blockSuspicious: raw.blockSuspicious === true, allowDomains: list("allowDomains"), blockDomains: list("blockDomains"),
    protectedDomains: list("protectedDomains"), organizationName: typeof raw.organizationName === "string" ? raw.organizationName.slice(0, 80) : null,
    communityIntel: raw.communityIntel !== false,
  };
}

/** Loads the policy and threat lists; re-downloads the list only when its version changed. */
export function refreshIntel(force = false): Promise<void> {
  if (!force && Date.now() - intelCheckedAt < INTEL_REFRESH_MS) return Promise.resolve();
  intelLoading ??= (async () => {
    try {
      if (!globalSet.size) {
        const cached = await idb<{ bytes: Uint8Array; policy?: unknown } | undefined>("readonly", (store) => store.get("current")).catch(() => undefined);
        if (cached?.bytes) { try { globalSet = PrefixSet.decode(cached.bytes); } catch { /* replaced below */ } }
        if (cached?.policy) policy = parsePolicy(cached.policy);
      }
      const answer = await callFunction<{ version: number; url: string | null; organizationPrefixes: string[]; policy: unknown }>("threat-intel", { have: globalSet.version });
      if (!answer) return;
      policy = parsePolicy(answer.policy);
      organizationSet = new PrefixSet(Uint32Array.from(new Set(answer.organizationPrefixes.map((value) => prefixOf(fromBase64(value))))).sort(), 0);
      let bytes: Uint8Array | null = null;
      if (answer.url && answer.version !== globalSet.version) {
        const response = await fetch(answer.url, { signal: AbortSignal.timeout(30_000) });
        if (response.ok) {
          bytes = new Uint8Array(await response.arrayBuffer());
          globalSet = PrefixSet.decode(bytes);
        }
      }
      // Keep the list and the policy for the next start of the service worker (and offline use).
      const stored = bytes ?? (await idb<{ bytes?: Uint8Array } | undefined>("readonly", (store) => store.get("current")).catch(() => undefined))?.bytes;
      await idb("readwrite", (store) => store.put({ bytes: stored, policy: answer.policy }, "current")).catch(() => undefined);
      intelCheckedAt = Date.now();
      verdicts.clear();
    } catch { /* keep the previous lists */ }
    finally { intelLoading = null; }
  })();
  return intelLoading;
}

async function confirm(prefixes: string[]): Promise<ThreatMatch[]> {
  const answer = await callFunction<{ matches: ThreatMatch[] }>("threat-check", { prefixes });
  return answer?.matches ?? [];
}

// ---------------------------------------------------------------------------
// Checking pages
// ---------------------------------------------------------------------------

async function bypassed(host: string): Promise<boolean> {
  const stored = (await chrome.storage.session.get(BYPASS_KEY))[BYPASS_KEY];
  return Array.isArray(stored) && stored.includes(host);
}

export async function allowForSession(host: string) {
  const stored = (await chrome.storage.session.get(BYPASS_KEY))[BYPASS_KEY];
  const hosts = new Set(Array.isArray(stored) ? stored.filter((value): value is string => typeof value === "string") : []);
  hosts.add(host);
  await chrome.storage.session.set({ [BYPASS_KEY]: [...hosts].slice(-200) });
}

function cacheKey(url: string, hasPasswordField: boolean) {
  try { const parsed = new URL(url); return `${hasPasswordField ? "p" : "n"}:${parsed.origin}${parsed.pathname}`; } catch { return url; }
}

/** Decides what to do with a page. Never throws; a failed lookup counts as "no match". */
export async function checkPage(url: string, hasPasswordField = false): Promise<GuardDecision> {
  let verdict: GuardVerdict = { level: "safe", domain: null, reasons: [] };
  try {
    const parsed = new URL(url);
    if (!["http:", "https:", "data:"].includes(parsed.protocol) || ["passkey-x.com", "www.passkey-x.com"].includes(parsed.hostname)) {
      return { action: "none", verdict, title: "", reasons: [], organizationName: policy.organizationName };
    }
    void refreshIntel();
    const key = cacheKey(url, hasPasswordField);
    const cached = verdicts.get(key);
    if (cached && Date.now() - cached.at < VERDICT_TTL_MS) verdict = cached.verdict;
    else {
      verdict = assessPageLocally(url, policy, { savedUrls: options?.savedUrls() ?? [], hasPasswordField });
      if (parsed.protocol !== "data:" && verdict.level !== "dangerous") {
        const match = await lookupThreats(url, [globalSet, organizationSet], confirm).catch(() => null);
        verdict = withThreat(verdict, match);
      }
      verdicts.set(key, { verdict, at: Date.now() });
      if (verdicts.size > 500) verdicts.delete(verdicts.keys().next().value!);
    }
    let action = guardAction(verdict, policy);
    if ((action === "warn") && verdict.domain && await bypassed(parsed.hostname)) action = "notice";
    return { action, verdict, title: verdictTitle(verdict), reasons: verdict.reasons.map(describeReason), organizationName: policy.organizationName };
  } catch {
    return { action: "none", verdict, title: "", reasons: [], organizationName: policy.organizationName };
  }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

function severityOf(verdict: GuardVerdict): Finding["severity"] {
  if (verdict.reasons.some((reason) => reason.code === "threat_list" && reason.threat !== "unwanted")) return "critical";
  if (verdict.level === "dangerous") return "high";
  return verdict.level === "suspicious" ? "medium" : "low";
}

/** Records what happened on a dangerous or suspicious page (site and reason only). */
export function recordPage(url: string, decision: GuardDecision, action: Finding["action"]) {
  let host = "";
  try { host = new URL(url).hostname; } catch { host = "data URL"; }
  const severity = action === "proceeded" && severityOf(decision.verdict) === "high" ? "critical" : severityOf(decision.verdict);
  queue.push({
    source: "extension", category: "web", kind: verdictKind(decision.verdict), severity, subject: host.slice(0, 200), action,
    detail: { reasons: decision.verdict.reasons.map((reason) => reason.code), title: decision.title.slice(0, 120) },
  });
  if (severity === "critical" || severity === "high") {
    options?.onAlert({ level: decision.verdict.level, title: decision.title, detail: decision.reasons[0] ?? "", site: host });
  }
  scheduleFlush();
}

/** The person thinks a warning was a mistake: the organization's admins review the site. */
export function recordDispute(url: string, decision: GuardDecision) {
  let host = "";
  try { host = new URL(url).hostname; } catch { return; }
  queue.push({
    source: "extension", category: "web", kind: "disputed_warning", severity: "low", subject: host.slice(0, 200), action: "reported",
    detail: { reasons: decision.verdict.reasons.map((reason) => reason.code) }, key: `disputed_warning:${host}`,
  });
  scheduleFlush();
}

export function recordPasswordReuse(url: string, savedSite: string, siteLevel: GuardVerdict["level"]) {
  let host = "";
  try { host = new URL(url).hostname; } catch { return; }
  queue.push({
    source: "extension", category: "account", kind: "password_reuse", severity: siteLevel === "safe" ? "medium" : "critical",
    subject: host.slice(0, 200), action: "detected", detail: { saved_site: savedSite.slice(0, 200) },
    key: `password_reuse:${host}:${savedSite}`.slice(0, 300),
  });
  if (siteLevel !== "safe") {
    options?.onAlert({ level: "dangerous", title: `Your ${savedSite} password was entered on ${host}`, detail: `Change your ${savedSite} password now if ${host} is not a site you trust.`, site: host });
  }
  scheduleFlush();
}

function scheduleFlush() {
  clearTimeout(flushTimer);
  flushTimer = setTimeout(() => void flush(), 2000);
}

let endpointReportedAt = 0;

function browserName(): string {
  const agent = navigator.userAgent;
  return agent.includes("Edg/") ? "edge" : agent.includes("Brave") ? "brave" : agent.includes("Chrome/") ? "chrome" : "chromium";
}

export async function flush() {
  if (!options || !(await accessToken())) return;
  const id = await installId();
  try {
    if (Date.now() - endpointReportedAt > 12 * 60 * 60_000) {
      const { error } = await options.supabase.rpc("report_guard_endpoint", {
        p_install_id: id, p_kind: "extension", p_platform: browserName(), p_label: `${browserName()[0].toUpperCase()}${browserName().slice(1)} extension`,
        p_os_version: null, p_app_version: chrome.runtime.getManifest().version, p_posture: {},
        p_software_total: null, p_software_risky: null, p_protection_on: policy.webMode !== "off",
      });
      if (!error) endpointReportedAt = Date.now();
    }
    while (queue.length) {
      const batch = queue.splice(0, 50);
      const { error } = await options.supabase.rpc("report_guard_findings", { p_install_id: id, p_findings: batch });
      if (error) { queue.unshift(...batch.slice(0, 200 - queue.length)); break; }
    }
  } catch { /* retried with the next finding */ }
}

/** Reports the current page as phishing (only when the person chooses to). */
export async function reportPhishing(url: string, note?: string): Promise<boolean> {
  if (!options) return false;
  const canonical = canonicalExpression(url);
  if (!canonical) return false;
  const expression = `${canonical.host}${canonical.path}`;
  const { error } = await options.supabase.rpc("report_phishing", {
    p_expression: expression, p_host: canonical.host, p_hash: toBase64(await sha256Bytes(expression)), p_note: note?.slice(0, 300) ?? null,
  });
  if (error) return false;
  queue.push({ source: "extension", category: "web", kind: "reported_site", severity: "low", subject: canonical.host, action: "reported", detail: {} });
  scheduleFlush();
  return true;
}

/** Payload for the warning page (in its URL fragment; it holds only the site and the reasons). */
export function warningPageUrl(url: string, decision: GuardDecision): string {
  const payload = {
    url, title: decision.title, reasons: decision.reasons, level: decision.verdict.level, mode: decision.action,
    organization: decision.organizationName,
  };
  return `${chrome.runtime.getURL("warning.html")}#${encodeURIComponent(JSON.stringify(payload))}`;
}
