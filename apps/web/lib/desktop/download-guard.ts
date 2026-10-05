// Download protection in the desktop app: every minute, new files in the Downloads folder are
// checked (name tricks, where they came from, known-malware hashes). Dangerous ones raise the
// emergency alert window and are reported to the person's organization as Guard findings
// (file name and source site only). Nothing is uploaded; only SHA-256 hashes of programs,
// installers, disk images and macro documents are looked up.

import { supabase } from "@/lib/supabase/client";
import { desktop, isDesktopApp, type DownloadFile } from "@/lib/desktop/bridge";
import { installId } from "@/lib/desktop/endpoint-scan";
import { assessDownload, hashesToCheck, safeHost, type DownloadAssessment, type FileThreat } from "@/lib/desktop/download-check";
import { assessPageLocally, DEFAULT_GUARD_POLICY, withThreat, type GuardPolicy, type GuardVerdict } from "@/lib/security/web-guard";
import { remoteMatches } from "@/lib/security/link-check";
import { hasSession, myGuardPolicy, reportGuardFindings } from "@/lib/security/guard-client";

export type CheckedDownload = DownloadFile & { assessment: DownloadAssessment; quarantined?: string };

const SINCE_RECORD = "px-downloads-since";
const EVERY_MS = 60_000;
const KEEP = 30;

let checked: CheckedDownload[] = [];
let version = 0;
const listeners = new Set<() => void>();
const seen = new Set<string>();

export const checkedDownloads = () => checked;
export const downloadsVersion = () => version;
export function subscribeDownloads(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }
const notify = () => { version += 1; listeners.forEach((listener) => listener()); };

async function policy(): Promise<GuardPolicy> {
  if (!(await hasSession().catch(() => false))) return DEFAULT_GUARD_POLICY;
  try { const record = await myGuardPolicy(); return { ...DEFAULT_GUARD_POLICY, ...record, webMode: record.webMode === "off" ? "warn" : record.webMode }; }
  catch { return DEFAULT_GUARD_POLICY; }
}

async function sourceVerdict(url: string | null, guardPolicy: GuardPolicy): Promise<GuardVerdict | null> {
  if (!url) return null;
  let verdict = assessPageLocally(url, guardPolicy, {});
  const matches = await remoteMatches(url).catch(() => null);
  if (matches?.length) verdict = withThreat(verdict, matches.find((match) => match.threat === "malware") ?? matches[0]);
  return verdict;
}

async function fileThreats(files: DownloadFile[]): Promise<Map<string, FileThreat>> {
  const hashes = hashesToCheck(files);
  const found = new Map<string, FileThreat>();
  if (!hashes.length || !supabase || !(await hasSession().catch(() => false))) return found;
  const { data, error } = await supabase.functions.invoke<{ matches?: FileThreat[] }>("file-check", { body: { hashes } });
  if (error) return found;
  for (const match of data?.matches ?? []) if (hashes.includes(match.sha256)) found.set(match.sha256, match);
  return found;
}

async function since(): Promise<number> {
  const stored = Number(await desktop.record.get(SINCE_RECORD).catch(() => null));
  if (Number.isFinite(stored) && stored > 0) return stored;
  // First run: only files from now on.
  const now = Date.now();
  await desktop.record.set(SINCE_RECORD, String(now)).catch(() => undefined);
  return now;
}

let running: Promise<void> | null = null;

/** Checks files that arrived since the last check. */
export function checkDownloads(): Promise<void> {
  running ??= (async () => {
    try {
      const from = await since();
      const files = (await desktop.downloads.recent(from)).filter((file) => !seen.has(`${file.path}:${file.modifiedMs}`));
      if (!files.length) return;
      const guardPolicy = await policy();
      const threats = await fileThreats(files).catch(() => new Map<string, FileThreat>());
      const results: CheckedDownload[] = [];
      for (const file of files) {
        seen.add(`${file.path}:${file.modifiedMs}`);
        const verdict = await sourceVerdict(file.sourceUrl, guardPolicy).catch(() => null);
        results.push({ ...file, assessment: assessDownload(file, verdict, file.sha256 ? threats.get(file.sha256.toLowerCase()) ?? null : null) });
      }
      await desktop.record.set(SINCE_RECORD, String(Math.max(from, ...files.map((file) => file.modifiedMs)))).catch(() => undefined);
      checked = [...results, ...checked].slice(0, KEEP);
      notify();
      const flagged = results.filter((result) => result.assessment.level !== "safe");
      const dangerous = flagged.filter((result) => result.assessment.level === "dangerous");
      if (dangerous.length) {
        const first = dangerous[0];
        void desktop.endpoint.alert({
          level: "dangerous",
          title: dangerous.length === 1 ? first.assessment.title : `${dangerous.length} dangerous downloads`,
          detail: `${first.assessment.reasons[0] ?? ""} Don't open it. Open Passkey-X › This computer › Downloads to block it.`.trim(),
          site: first.sourceUrl ? safeHost(first.sourceUrl) ?? "" : "",
        }).catch(() => undefined);
      }
      if (flagged.length && (await hasSession().catch(() => false))) {
        const id = await installId();
        await reportGuardFindings(id, flagged.map((result) => ({
          source: "desktop", category: "web", kind: result.assessment.kind ?? "risky_download",
          severity: result.assessment.level === "dangerous" ? "high" : "medium",
          subject: result.name.slice(0, 200), action: "detected",
          detail: { why: result.assessment.reasons.join(" ").slice(0, 500), site: result.sourceUrl ? safeHost(result.sourceUrl) : null, sha256: result.sha256 },
          key: `download:${result.sha256 ?? result.name}:${result.modifiedMs}`,
        }))).catch(() => undefined);
      }
    } finally { running = null; }
  })();
  return running;
}

/** Blocks a checked download by renaming it to "<name>.blocked". */
export async function quarantineDownload(path: string): Promise<string> {
  const moved = await desktop.downloads.quarantine(path);
  checked = checked.map((entry) => entry.path === path ? { ...entry, quarantined: moved } : entry);
  notify();
  return moved;
}

/** Starts the background check (desktop app only). Returns a stop function. */
export function startDownloadGuard(): () => void {
  if (!isDesktopApp()) return () => undefined;
  const run = () => void desktop.settings().then((settings) => settings.downloadProtection ? checkDownloads() : undefined).catch(() => undefined);
  const first = setTimeout(run, 10_000);
  const every = setInterval(run, EVERY_MS);
  return () => { clearTimeout(first); clearInterval(every); };
}
