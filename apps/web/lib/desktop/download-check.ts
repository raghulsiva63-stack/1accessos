// Download protection rules (pure). A downloaded file is judged by its name, where it came from
// (Guard's page rules and threat lists) and, for programs and similar files, its SHA-256 against
// known malware. Files never leave the computer.

import type { GuardVerdict } from "@/lib/security/web-guard";

const EXECUTABLE = new Set(["exe", "msi", "msix", "appx", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "cpl", "jar", "lnk", "reg", "dll", "app", "pkg", "command", "sh", "deb", "rpm", "appimage", "apk"]);
const CONTAINER = new Set(["dmg", "iso", "img", "vhd", "vhdx", "zip", "rar", "7z"]);
const MACRO = new Set(["docm", "xlsm", "pptm", "dotm", "xlam", "one"]);
const DECOY = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "bmp", "heic", "mp3", "mp4", "mov", "avi", "wav", "html", "htm", "eml", "invoice"]);
// Bidirectional overrides that flip how a name is shown (an RTL override makes "invoice[RLO]fdp.exe" look like "invoiceexe.pdf").
const BIDI_CODES = new Set([0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);
const isBidi = (char: string) => BIDI_CODES.has(char.codePointAt(0) ?? 0);

export type FileThreat = { sha256: string; signature: string | null; source: string };
export type DownloadAssessment = {
  level: "safe" | "suspicious" | "dangerous";
  kind: "dangerous_download" | "risky_download" | null;
  reasons: string[];
  title: string;
};

export function extensionOf(name: string) {
  const index = name.lastIndexOf(".");
  return index > 0 ? name.slice(index + 1).toLowerCase() : "";
}

export function fileType(name: string): "program" | "container" | "macro" | "other" {
  const ext = extensionOf(name);
  return EXECUTABLE.has(ext) ? "program" : CONTAINER.has(ext) ? "container" : MACRO.has(ext) ? "macro" : "other";
}

/** Name tricks: hidden direction characters and "report.pdf.exe" style double extensions. */
export function nameTricks(name: string): string[] {
  const reasons: string[] = [];
  if ([...name].some(isBidi)) reasons.push("The file name contains hidden characters that disguise its real type.");
  const parts = [...name].filter((char) => !isBidi(char)).join("").toLowerCase().split(".");
  if (parts.length >= 3) {
    const last = parts[parts.length - 1];
    const before = parts[parts.length - 2];
    if ((EXECUTABLE.has(last) || MACRO.has(last)) && DECOY.has(before)) reasons.push(`It is named like a .${before} file but is really a .${last} file.`);
  }
  if (/\s{6,}\.[a-z0-9]+$/iu.test(name) && fileType(name) === "program") reasons.push("Spaces hide the program extension at the end of the name.");
  return reasons;
}

/** Combines what is known about one downloaded file. */
export function assessDownload(file: { name: string; sourceUrl: string | null }, source: GuardVerdict | null, threat: FileThreat | null): DownloadAssessment {
  const reasons: string[] = [];
  const type = fileType(file.name);
  const risky = type !== "other";
  const RANK: Record<DownloadAssessment["level"], number> = { safe: 0, suspicious: 1, dangerous: 2 };
  let level = "safe" as DownloadAssessment["level"];
  const raise = (next: DownloadAssessment["level"]) => {
    if (RANK[next] > RANK[level]) level = next;
  };
  if (threat) {
    reasons.push(`It is known malware${threat.signature ? ` (${threat.signature})` : ""}, reported by ${threat.source}.`);
    raise("dangerous");
  }
  const tricks = nameTricks(file.name);
  if (tricks.length) { reasons.push(...tricks); raise("dangerous"); }
  if (source && source.level !== "safe") {
    const host = source.domain ?? (file.sourceUrl ? safeHost(file.sourceUrl) : null);
    reasons.push(source.level === "dangerous" ? `It came from ${host ?? "a site"} that Guard flags as dangerous.` : `It came from ${host ?? "a site"} that looks suspicious.`);
    raise(source.level === "dangerous" && risky ? "dangerous" : "suspicious");
  }
  if (risky && level !== "safe" && type === "macro") reasons.push("Office files with macros can run code when opened.");
  const kind = level === "dangerous" ? "dangerous_download" : level === "suspicious" ? "risky_download" : null;
  const title = level === "dangerous" ? `Dangerous download: ${file.name}` : level === "suspicious" ? `Check this download: ${file.name}` : file.name;
  return { level, kind, reasons, title };
}

export function safeHost(url: string) {
  try { return new URL(url).hostname; } catch { return null; }
}

/** Valid SHA-256 hex digests, de-duplicated, at most `limit`. */
export function hashesToCheck(files: { sha256: string | null }[], limit = 10): string[] {
  return [...new Set(files.map((file) => file.sha256?.toLowerCase() ?? "").filter((hash) => /^[0-9a-f]{64}$/u.test(hash)))].slice(0, limit);
}
