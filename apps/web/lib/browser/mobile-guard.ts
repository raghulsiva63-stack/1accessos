// Passkey-X Guard in the Android app: checks the phone's security settings when the app opens
// (at most every 6 hours) and receives links shared to "Check link with Passkey-X".

import { nativeAvailable, nativeRequest } from "@/lib/browser/native-autofill";
import { classifyPosture, DEFAULT_ENDPOINT_POLICY, postureFlags, type EndpointFinding, type Posture } from "@/lib/security/endpoint-guard";
import { hasSession, myGuardPolicy, reportGuardEndpoint, reportGuardFindings, resolveGuardFindings } from "@/lib/security/guard-client";
import { setPendingLink } from "@/lib/security/link-check";

const LAST_RUN = "px-guard-mobile-at";
const KEYS = "px-guard-mobile-keys";
const EVERY_MS = 6 * 60 * 60_000;

type DevicePosture = Posture & { label?: string; appVersion?: string };

function stored(key: string): string | null { try { return window.localStorage.getItem(key); } catch { return null; } }
function store(key: string, value: string) { try { window.localStorage.setItem(key, value); } catch { /* storage blocked */ } }

export async function runMobileGuard(force = false): Promise<EndpointFinding[] | null> {
  if (!nativeAvailable() || !(await hasSession())) return null;
  if (!force && Date.now() - Number(stored(LAST_RUN) ?? 0) < EVERY_MS) return null;
  const posture = await nativeRequest<DevicePosture>("devicePosture");
  const installId = await nativeRequest<string>("installId");
  if (!posture || typeof installId !== "string" || !/^[0-9a-f-]{36}$/u.test(installId)) return null;
  const policy = await myGuardPolicy().then((value) => ({ ...DEFAULT_ENDPOINT_POLICY, requireExtension: false, softwareBlock: value.softwareBlock, softwareAllow: value.softwareAllow }))
    .catch(() => DEFAULT_ENDPOINT_POLICY);
  const findings = classifyPosture(posture, [], policy, new Date(), "mobile");
  await reportGuardEndpoint({
    installId, kind: "mobile", platform: "android", label: posture.label || posture.osName, osVersion: posture.osName,
    appVersion: posture.appVersion ?? null, posture: postureFlags(posture),
  });
  await reportGuardFindings(installId, findings);
  let previous: string[] = [];
  try { previous = JSON.parse(stored(KEYS) ?? "[]") as string[]; } catch { previous = []; }
  const current = new Set(findings.map((finding) => finding.key));
  if (Array.isArray(previous)) await resolveGuardFindings(installId, previous.filter((key) => typeof key === "string" && !current.has(key)));
  store(KEYS, JSON.stringify([...current]));
  store(LAST_RUN, String(Date.now()));
  return findings;
}

/** Asks the app for a link shared to "Check link with Passkey-X". */
export async function receiveSharedLink(): Promise<boolean> {
  if (!nativeAvailable()) return false;
  const link = await nativeRequest<string | null>("pendingLink").catch(() => null);
  if (typeof link !== "string" || !/^https?:\/\//iu.test(link) || link.length > 2048) return false;
  setPendingLink(link);
  return true;
}
