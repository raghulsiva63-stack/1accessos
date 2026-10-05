// Passkey-X Endpoint Guard rules: turn a computer's (or phone's) facts into findings. Pure; runs on
// the device. Only findings leave the device, never the full software list.
//
// The data tables below are dated; update them with each release.

export type Severity = "critical" | "high" | "medium" | "low";
export type EndpointFinding = {
  source: "desktop" | "mobile";
  category: "software" | "device";
  kind: string;
  severity: Severity;
  subject: string;
  detail: Record<string, string | number | boolean | null>;
  action: "detected";
  key: string;
};

export type Program = { name: string; version: string; publisher: string };

export type Posture = {
  os: string;
  osName: string;
  osVersion: string;
  osBuild?: number | null;
  diskEncrypted?: boolean | null;
  firewall?: boolean | null;
  antivirus?: boolean | null;
  autoUpdates?: boolean | null;
  gatekeeper?: boolean | null;
  // Mobile
  screenLock?: boolean | null;
  rooted?: boolean | null;
  developerMode?: boolean | null;
  usbDebugging?: boolean | null;
  unknownSources?: boolean | null;
  patchAgeDays?: number | null;
};

export type BrowserProtection = { browser: string; installed: boolean; protected: boolean };

export type EndpointPolicy = { softwareBlock: string[]; softwareAllow: string[]; requireExtension: boolean };

export const DEFAULT_ENDPOINT_POLICY: EndpointPolicy = { softwareBlock: [], softwareAllow: [], requireExtension: false };

type Rule = {
  kind: string;
  severity: Severity;
  pattern: RegExp;
  versions?: (version: string) => boolean;
  why: string;
};

const exact = (...versions: string[]) => (version: string) => versions.some((value) => version === value || version.startsWith(`${value}-`) || version.startsWith(`${value}+`));

/** Built-in software rules (checked against the program name, then the version when given). */
export const SOFTWARE_RULES: Rule[] = [
  // Builds known to have been compromised by their supply chain.
  { kind: "compromised_software", severity: "critical", pattern: /^3cx\s*desktop\s*app/iu, versions: exact("18.12.407", "18.12.416", "18.11.1213", "18.12.402"), why: "This 3CX Desktop App build was trojanized in the 2023 supply-chain attack." },
  { kind: "compromised_software", severity: "critical", pattern: /^(xz-utils|liblzma5|xz|xz-libs)$/iu, versions: exact("5.6.0", "5.6.1"), why: "XZ Utils 5.6.0/5.6.1 contain a backdoor (CVE-2024-3094)." },
  { kind: "compromised_software", severity: "critical", pattern: /^ccleaner$/iu, versions: exact("5.33.6162"), why: "CCleaner 5.33.6162 shipped with malware (2017 supply-chain attack)." },
  // Piracy activators and cracks are a common way malware gets installed.
  { kind: "piracy_tool", severity: "critical", pattern: /\b(kmspico|kmsauto|kms\s?tools|re-?loader|windows\s+loader|keygen|crack(ed)?|activator)\b/iu, why: "Piracy tools and cracks frequently carry malware and disable security features." },
  // No longer receives security updates.
  { kind: "unsupported_software", severity: "high", pattern: /^adobe flash player/iu, why: "Flash Player stopped receiving security updates in 2020." },
  { kind: "unsupported_software", severity: "high", pattern: /^microsoft silverlight/iu, why: "Silverlight stopped receiving security updates in 2021." },
  { kind: "unsupported_software", severity: "high", pattern: /^quicktime/iu, why: "QuickTime for Windows no longer receives security updates." },
  { kind: "unsupported_software", severity: "high", pattern: /^java(\(tm\))?\s*(6|7)\b|^java\s*(6|7)\s*update/iu, why: "Java 6 and 7 no longer receive security updates." },
  { kind: "unsupported_software", severity: "medium", pattern: /^python\s*2\./iu, why: "Python 2 stopped receiving security updates in 2020." },
  { kind: "unsupported_software", severity: "high", pattern: /^microsoft office\b.*\b(2007|2010|2013)\b/iu, why: "This Office version no longer receives security updates." },
  { kind: "unsupported_software", severity: "medium", pattern: /^microsoft office\b.*\b(2016|2019)\b/iu, why: "Office 2016 and 2019 stopped receiving security updates in October 2025." },
  { kind: "unsupported_software", severity: "high", pattern: /^adobe (acrobat|reader)\s*(x|xi|9|8|2015|2017)\b/iu, why: "This Acrobat/Reader version no longer receives security updates." },
  // Remote-control tools: legitimate, but the favourite tool of support scammers.
  { kind: "remote_access_tool", severity: "medium", pattern: /^(anydesk|teamviewer|ultraviewer|rustdesk|supremo|ammyy|aeroadmin|screenconnect client|connectwise control|logmein|remoteutilities|getscreen)/iu, why: "Remote-control software lets someone else operate this computer. Remove it unless your IT team uses it." },
  // Programs that change browser settings, show ads or push paid "fixes".
  { kind: "unwanted_software", severity: "medium", pattern: /^(onelaunch|wave browser|webdiscover|segurazo|santivirus|bytefence|pc accelerate|driver support|reimage repair|restoro|pc app store|mysearchdial|search protect|safer-networking browser)/iu, why: "This program is known to change browser settings, show ads or push paid repairs." },
  { kind: "crypto_miner", severity: "high", pattern: /^(nicehash|xmrig|kryptex|minergate|cudo miner)/iu, why: "Cryptocurrency mining software uses this computer's power and is often installed without consent." },
  { kind: "p2p_software", severity: "low", pattern: /^(µtorrent|utorrent|bittorrent|vuze|frostwire|limewire|bitcomet)/iu, why: "File-sharing programs are a common source of malware and copyright problems." },
];

function matchesName(name: string, entries: string[]): boolean {
  const lower = name.toLowerCase();
  return entries.some((entry) => entry && lower.includes(entry.toLowerCase()));
}

export function classifySoftware(programs: Program[], policy: EndpointPolicy = DEFAULT_ENDPOINT_POLICY, source: EndpointFinding["source"] = "desktop"): EndpointFinding[] {
  const findings = new Map<string, EndpointFinding>();
  for (const program of programs) {
    if (!program.name || matchesName(program.name, policy.softwareAllow)) continue;
    const subject = `${program.name}${program.version ? ` ${program.version}` : ""}`.slice(0, 200);
    const key = `software:${program.name.toLowerCase().slice(0, 150)}`;
    if (matchesName(program.name, policy.softwareBlock)) {
      findings.set(key, { source, category: "software", kind: "blocked_software", severity: "high", subject, key, action: "detected",
        detail: { why: "Your organization does not allow this program.", publisher: program.publisher || null } });
      continue;
    }
    for (const rule of SOFTWARE_RULES) {
      if (!rule.pattern.test(program.name)) continue;
      if (rule.versions && !rule.versions(program.version.trim())) continue;
      const existing = findings.get(key);
      if (!existing || severityRank(rule.severity) < severityRank(existing.severity)) {
        findings.set(key, { source, category: "software", kind: rule.kind, severity: rule.severity, subject, key, action: "detected",
          detail: { why: rule.why, publisher: program.publisher || null } });
      }
    }
  }
  return [...findings.values()];
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
function severityRank(severity: Severity) { return SEVERITY_ORDER[severity]; }

// ---------------------------------------------------------------------------
// Operating system support (dates as published by Microsoft, Apple, Canonical and Debian)
// ---------------------------------------------------------------------------

/** Windows 11 builds: end of support for Home/Pro and for Enterprise/Education. */
const WINDOWS_11 = [
  { build: 22000, release: "21H2", consumer: "2023-10-10", enterprise: "2024-10-08" },
  { build: 22621, release: "22H2", consumer: "2024-10-08", enterprise: "2025-10-14" },
  { build: 22631, release: "23H2", consumer: "2025-11-11", enterprise: "2026-11-10" },
  { build: 26100, release: "24H2", consumer: "2026-10-13", enterprise: "2027-10-12" },
  { build: 26200, release: "25H2", consumer: "2027-10-12", enterprise: "2028-10-10" },
];
const WINDOWS_10_END = "2025-10-14";
/** Oldest macOS major version still receiving security updates (Apple supports the latest three). */
const MACOS_OLDEST_SUPPORTED = 15;
const LINUX_SUPPORT: Record<string, Record<string, string>> = {
  ubuntu: { "18.04": "2023-05-31", "20.04": "2025-05-31", "22.04": "2027-06-01", "24.04": "2029-05-31", "25.04": "2026-01-31", "25.10": "2026-07-31" },
  debian: { "10": "2024-06-30", "11": "2026-08-31", "12": "2028-06-30", "13": "2030-06-30" },
};

export type OsSupport = { status: "supported" | "ending" | "unsupported" | "unknown"; endsOn: string | null; label: string };

export function osSupport(posture: Posture, now = new Date()): OsSupport {
  const ending = (date: string): OsSupport["status"] => {
    const end = new Date(`${date}T23:59:59Z`).getTime();
    if (now.getTime() > end) return "unsupported";
    return end - now.getTime() < 60 * 24 * 60 * 60_000 ? "ending" : "supported";
  };
  if (posture.os === "windows") {
    const build = posture.osBuild ?? Number.parseInt(posture.osVersion.split(".")[2] ?? "", 10);
    if (!Number.isFinite(build) || !build) return { status: "unknown", endsOn: null, label: posture.osName };
    if (build < 22000) return { status: ending(WINDOWS_10_END), endsOn: WINDOWS_10_END, label: "Windows 10" };
    const enterprise = /enterprise|education/iu.test(posture.osName);
    const known = [...WINDOWS_11].reverse().find((entry) => build >= entry.build);
    if (!known) return { status: "unknown", endsOn: null, label: posture.osName };
    const date = enterprise ? known.enterprise : known.consumer;
    // Builds newer than the table are treated as supported.
    if (build >= WINDOWS_11[WINDOWS_11.length - 1].build + 100) return { status: "supported", endsOn: null, label: `${posture.osName}` };
    return { status: ending(date), endsOn: date, label: `Windows 11 ${known.release}` };
  }
  if (posture.os === "macos") {
    const major = Number.parseInt(posture.osVersion.split(".")[0] ?? "", 10);
    if (!Number.isFinite(major)) return { status: "unknown", endsOn: null, label: "macOS" };
    return { status: major >= MACOS_OLDEST_SUPPORTED ? "supported" : "unsupported", endsOn: null, label: `macOS ${posture.osVersion}` };
  }
  if (posture.os === "linux") {
    const family = /ubuntu/iu.test(posture.osName) ? "ubuntu" : /debian/iu.test(posture.osName) ? "debian" : null;
    const date = family ? LINUX_SUPPORT[family][posture.osVersion] ?? LINUX_SUPPORT[family][posture.osVersion.split(".")[0]] : undefined;
    if (!date) return { status: "unknown", endsOn: null, label: posture.osName };
    return { status: ending(date), endsOn: date, label: posture.osName };
  }
  if (posture.os === "android") {
    const age = posture.patchAgeDays;
    if (age == null) return { status: "unknown", endsOn: null, label: posture.osName };
    return { status: age > 365 ? "unsupported" : age > 90 ? "ending" : "supported", endsOn: null, label: posture.osName };
  }
  return { status: "unknown", endsOn: null, label: posture.osName };
}

function deviceFinding(source: EndpointFinding["source"], flag: string, kind: string, severity: Severity, subject: string, why: string): EndpointFinding {
  return { source, category: "device", kind, severity, subject, key: `device:${flag}`, action: "detected", detail: { why } };
}

export function classifyPosture(posture: Posture, browsers: BrowserProtection[] = [], policy: EndpointPolicy = DEFAULT_ENDPOINT_POLICY, now = new Date(), source: EndpointFinding["source"] = "desktop"): EndpointFinding[] {
  const findings: EndpointFinding[] = [];
  const support = osSupport(posture, now);
  if (support.status === "unsupported") {
    findings.push(deviceFinding(source, "os_supported", "os_unsupported", "high", `${support.label} no longer receives security updates`,
      source === "mobile" ? "This phone's last security update is more than a year old." : "Upgrade to a supported version to keep receiving security fixes."));
  } else if (support.status === "ending") {
    findings.push(deviceFinding(source, "os_supported", "os_support_ending", source === "mobile" ? "medium" : "low",
      source === "mobile" ? `${support.label}: security update is ${posture.patchAgeDays} days old` : `${support.label} support ends on ${support.endsOn}`,
      "Install the latest updates or plan the upgrade now."));
  }
  if (posture.diskEncrypted === false) {
    findings.push(deviceFinding(source, "disk_encrypted", "disk_not_encrypted", "high", "Disk encryption is off",
      posture.os === "macos" ? "Turn on FileVault in System Settings › Privacy & Security." : posture.os === "windows" ? "Turn on BitLocker or Device encryption in Settings › Privacy & security." : "A lost or stolen computer exposes every file on an unencrypted disk."));
  }
  if (posture.firewall === false) {
    findings.push(deviceFinding(source, "firewall", "firewall_off", "high", "Firewall is off",
      posture.os === "macos" ? "Turn on the firewall in System Settings › Network › Firewall." : "Turn on Windows Firewall for all networks in Windows Security."));
  }
  if (posture.antivirus === false) {
    findings.push(deviceFinding(source, "antivirus", "antivirus_off", "high", "No active antivirus protection", "Turn on Microsoft Defender or your organization's antivirus."));
  }
  if (posture.autoUpdates === false) {
    findings.push(deviceFinding(source, "auto_updates", "auto_updates_off", "medium", "Automatic updates are turned off", "Turn automatic updates back on so security fixes install promptly."));
  }
  if (posture.gatekeeper === false) {
    findings.push(deviceFinding(source, "gatekeeper", "gatekeeper_off", "high", "Gatekeeper is turned off", "Unsigned apps can run without checks. Run `sudo spctl --master-enable` to turn it back on."));
  }
  if (posture.screenLock === false) {
    findings.push(deviceFinding(source, "screen_lock", "no_screen_lock", "high", "No screen lock", "Set a PIN, pattern or password so a lost device can't be opened."));
  }
  if (posture.rooted === true) {
    findings.push(deviceFinding(source, "rooted", "rooted_device", "critical", "This device is rooted", "Rooted devices let apps bypass Android's security. Use an unmodified device for work."));
  }
  if (posture.usbDebugging === true) {
    findings.push(deviceFinding(source, "usb_debugging", "usb_debugging_on", "medium", "USB debugging is on", "Turn off USB debugging in Developer options when you don't need it."));
  }
  if (posture.unknownSources === true) {
    findings.push(deviceFinding(source, "unknown_sources", "unknown_sources_allowed", "medium", "Apps from unknown sources are allowed", "Only install apps from Google Play or your organization's store."));
  }
  for (const browser of browsers) {
    if (!browser.installed || browser.protected) continue;
    const name = browser.browser === "edge" ? "Microsoft Edge" : browser.browser === "brave" ? "Brave" : browser.browser === "chromium" ? "Chromium" : "Google Chrome";
    findings.push(deviceFinding(source, `browser:${browser.browser}`, "browser_unprotected", policy.requireExtension ? "high" : "medium",
      `${name} is not protected by Passkey-X`, `Install the Passkey-X extension in ${name} so dangerous sites are blocked there too.`));
  }
  return findings;
}

/** Posture flags reported with the device (true = good), for the admin console. */
export function postureFlags(posture: Posture, browsers: BrowserProtection[] = [], now = new Date()): Record<string, boolean | number> {
  const flags: Record<string, boolean | number> = {};
  const set = (key: string, value: boolean | null | undefined) => { if (typeof value === "boolean") flags[key] = value; };
  set("disk_encrypted", posture.diskEncrypted);
  set("firewall", posture.firewall);
  set("antivirus", posture.antivirus);
  set("auto_updates", posture.autoUpdates);
  set("screen_lock", posture.screenLock);
  set("rooted", posture.rooted);
  set("developer_mode", posture.developerMode);
  set("usb_debugging", posture.usbDebugging);
  set("unknown_sources", posture.unknownSources);
  if (typeof posture.patchAgeDays === "number") flags.patch_age_days = Math.max(0, Math.min(10_000, Math.round(posture.patchAgeDays)));
  const support = osSupport(posture, now).status;
  if (support !== "unknown") flags.os_supported = support !== "unsupported";
  const installed = browsers.filter((browser) => browser.installed);
  if (installed.length) flags.browser_protection = installed.every((browser) => browser.protected);
  return flags;
}

export function sortFindings<T extends { severity: Severity }>(findings: T[]): T[] {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}
