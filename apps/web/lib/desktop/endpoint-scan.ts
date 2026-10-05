// Endpoint Guard in the desktop app: checks this computer at start and every 6 hours.
//
// The app reads installed programs, security settings and browser protection; the rules in
// lib/security/endpoint-guard.ts turn them into findings on this computer. Only findings (and
// posture flags) are reported to the person's organization, never the program list. New serious
// findings raise the emergency alert window. Findings that are no longer present are closed.

import { hasSession, myGuardPolicy, reportGuardEndpoint, reportGuardFindings, resolveGuardFindings } from "@/lib/security/guard-client";
import { desktop, isDesktopApp } from "@/lib/desktop/bridge";
import {
  classifyPosture, classifySoftware, DEFAULT_ENDPOINT_POLICY, osSupport, postureFlags, sortFindings,
  type BrowserProtection, type EndpointFinding, type EndpointPolicy, type OsSupport, type Posture,
} from "@/lib/security/endpoint-guard";

export type ScanResult = {
  at: string;
  findings: EndpointFinding[];
  posture: Posture;
  browsers: BrowserProtection[];
  programCount: number;
  support: OsSupport;
  reported: boolean;
};

const INSTALL_RECORD = "px-guard-install";
const KEYS_RECORD = "px-guard-keys";
const SCAN_EVERY_MS = 6 * 60 * 60_000;

let last: ScanResult | null = null;
let running: Promise<ScanResult> | null = null;
const listeners = new Set<() => void>();

export const lastScan = () => last;
export const scanInProgress = () => running !== null;
export function subscribeScan(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }
const notify = () => listeners.forEach((listener) => listener());

export async function installId(): Promise<string> {
  const stored = await desktop.record.get(INSTALL_RECORD).catch(() => null);
  if (stored && /^[0-9a-f-]{36}$/u.test(stored)) return stored;
  const id = crypto.randomUUID();
  await desktop.record.set(INSTALL_RECORD, id).catch(() => undefined);
  return id;
}

async function loadPolicy(): Promise<EndpointPolicy> {
  if (!(await hasSession())) return DEFAULT_ENDPOINT_POLICY;
  const policy = await myGuardPolicy();
  return { softwareBlock: policy.softwareBlock, softwareAllow: policy.softwareAllow, requireExtension: policy.requireExtension };
}

async function report(result: ScanResult, previousKeys: string[]): Promise<boolean> {
  if (!(await hasSession())) return false;
  const id = await installId();
  const info = await desktop.info().catch(() => null);
  await reportGuardEndpoint({
    installId: id, kind: "desktop", platform: result.posture.os, label: result.posture.osName, osVersion: result.posture.osVersion,
    appVersion: info?.version ?? null, posture: postureFlags(result.posture, result.browsers), softwareTotal: result.programCount,
    softwareRisky: result.findings.filter((finding) => finding.category === "software").length,
  });
  await reportGuardFindings(id, result.findings);
  const current = new Set(result.findings.map((finding) => finding.key));
  await resolveGuardFindings(id, previousKeys.filter((key) => !current.has(key)));
  return true;
}

function alertFor(findings: EndpointFinding[]) {
  const serious = findings.filter((finding) => finding.severity === "critical" || finding.severity === "high");
  if (!serious.length) return;
  const first = serious[0];
  void desktop.endpoint.alert({
    level: "dangerous",
    title: serious.length === 1 ? first.subject : `${serious.length} security problems found on this computer`,
    detail: serious.length === 1 ? String(first.detail.why ?? "") : serious.slice(0, 3).map((finding) => finding.subject).join(" · "),
    site: "",
  }).catch(() => undefined);
}

/** Runs one check. New serious findings (not seen in the previous check) raise the alert window. */
export function runEndpointScan(options: { alert?: boolean } = {}): Promise<ScanResult> {
  running ??= (async () => {
    notify();
    try {
      const [programs, posture, browsers, policy] = await Promise.all([
        desktop.endpoint.programs().catch(() => []),
        desktop.endpoint.posture(),
        desktop.endpoint.browsers().catch(() => []),
        loadPolicy().catch(() => DEFAULT_ENDPOINT_POLICY),
      ]);
      const findings = sortFindings([...classifySoftware(programs, policy), ...classifyPosture(posture, browsers, policy)]);
      let previous: string[] = [];
      try { previous = JSON.parse((await desktop.record.get(KEYS_RECORD)) ?? "[]") as string[]; } catch { previous = []; }
      if (!Array.isArray(previous)) previous = [];
      const result: ScanResult = {
        at: new Date().toISOString(), findings, posture, browsers, programCount: programs.length, support: osSupport(posture), reported: false,
      };
      if (options.alert !== false) alertFor(findings.filter((finding) => !previous.includes(finding.key)));
      result.reported = await report(result, previous).catch(() => false);
      await desktop.record.set(KEYS_RECORD, JSON.stringify(findings.map((finding) => finding.key))).catch(() => undefined);
      last = result;
      return result;
    } finally {
      running = null;
      notify();
    }
  })();
  return running;
}

/** Starts the background checks in the desktop app. Returns a stop function. */
export function startEndpointGuard(): () => void {
  if (!isDesktopApp()) return () => undefined;
  const first = setTimeout(() => void runEndpointScan().catch(() => undefined), 30_000);
  const every = setInterval(() => void runEndpointScan().catch(() => undefined), SCAN_EVERY_MS);
  const onDemand = () => void runEndpointScan({ alert: false }).catch(() => undefined);
  window.addEventListener("passkey-x:guard-scan", onDemand);
  return () => { clearTimeout(first); clearInterval(every); window.removeEventListener("passkey-x:guard-scan", onDemand); };
}
