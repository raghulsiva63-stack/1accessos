import assert from "node:assert/strict";
import { register } from "node:module";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const rules = await import("../../apps/web/lib/security/endpoint-guard.ts");
const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");
const now = new Date("2026-10-05T12:00:00Z");
const migration = await read("supabase/migrations/20261006090000_guard.sql");

test("risky software: compromised builds, piracy tools, unsupported, remote access, organization lists", () => {
  const programs = [
    { name: "3CX Desktop App", version: "18.12.416", publisher: "3CX" },
    { name: "3CX Desktop App", version: "20.0.1", publisher: "3CX" },
    { name: "xz-utils", version: "5.6.1-1", publisher: "Debian" },
    { name: "xz-utils", version: "5.4.5-0.3", publisher: "Debian" },
    { name: "KMSpico 10.2", version: "", publisher: "" },
    { name: "Adobe Flash Player 32 NPAPI", version: "32.0.0.465", publisher: "Adobe" },
    { name: "AnyDesk", version: "8.0.9", publisher: "AnyDesk Software GmbH" },
    { name: "TeamViewer", version: "15.50", publisher: "TeamViewer" },
    { name: "Microsoft Office Professional Plus 2016", version: "16.0.4266", publisher: "Microsoft" },
    { name: "Google Chrome", version: "141.0", publisher: "Google LLC" },
    { name: "Steam", version: "2.10", publisher: "Valve" },
  ];
  const policy = { softwareBlock: ["steam"], softwareAllow: ["teamviewer"], requireExtension: false };
  const findings = rules.classifySoftware(programs, policy);
  const by = Object.fromEntries(findings.map((finding) => [finding.subject, finding]));
  assert.equal(by["3CX Desktop App 18.12.416"].kind, "compromised_software");
  assert.equal(by["3CX Desktop App 18.12.416"].severity, "critical");
  assert.equal(by["xz-utils 5.6.1-1"].kind, "compromised_software");
  assert.equal(by["KMSpico 10.2"].kind, "piracy_tool");
  assert.equal(by["Adobe Flash Player 32 NPAPI 32.0.0.465"].kind, "unsupported_software");
  assert.equal(by["AnyDesk 8.0.9"].kind, "remote_access_tool");
  assert.equal(by["Microsoft Office Professional Plus 2016 16.0.4266"].severity, "medium");
  assert.equal(by["Steam 2.10"].kind, "blocked_software");
  assert.equal(findings.some((finding) => /TeamViewer|Chrome|3CX Desktop App 20|xz-utils 5\.4/u.test(finding.subject)), false);
  // One open finding per program name (the server keeps it open until it is gone).
  assert.equal(new Set(findings.map((finding) => finding.key)).size, findings.length);
  assert.ok(findings.every((finding) => finding.source === "desktop" && finding.action === "detected" && finding.key.startsWith("software:")));
});

test("operating system support follows the published end dates", () => {
  const windows = (build, name = "Microsoft Windows 11 Pro") => rules.osSupport({ os: "windows", osName: name, osVersion: `10.0.${build}`, osBuild: build }, now);
  assert.equal(windows(19045, "Microsoft Windows 10 Pro").status, "unsupported");
  assert.equal(windows(22631).status, "unsupported");
  assert.equal(windows(22631, "Microsoft Windows 11 Enterprise").status, "ending");
  assert.equal(windows(22631, "Microsoft Windows 11 Enterprise").endsOn, "2026-11-10");
  assert.equal(windows(26100).status, "ending");
  assert.equal(windows(26200).status, "supported");
  assert.equal(windows(27000).status, "supported");
  assert.equal(rules.osSupport({ os: "macos", osName: "macOS", osVersion: "14.7.1" }, now).status, "unsupported");
  assert.equal(rules.osSupport({ os: "macos", osName: "macOS", osVersion: "26.0" }, now).status, "supported");
  assert.equal(rules.osSupport({ os: "linux", osName: "Ubuntu 20.04.6 LTS", osVersion: "20.04" }, now).status, "unsupported");
  assert.equal(rules.osSupport({ os: "linux", osName: "Ubuntu 24.04.1 LTS", osVersion: "24.04" }, now).status, "supported");
  assert.equal(rules.osSupport({ os: "linux", osName: "Fedora Linux 42", osVersion: "42" }, now).status, "unknown");
});

test("device settings and browser protection become findings and flags", () => {
  const posture = { os: "windows", osName: "Microsoft Windows 11 Pro", osVersion: "10.0.26200", osBuild: 26200, diskEncrypted: false, firewall: false, antivirus: true, autoUpdates: null };
  const browsers = [{ browser: "chrome", installed: true, protected: true }, { browser: "edge", installed: true, protected: false }, { browser: "brave", installed: false, protected: false }];
  const findings = rules.classifyPosture(posture, browsers, { softwareBlock: [], softwareAllow: [], requireExtension: true }, now);
  assert.deepEqual(findings.map((finding) => finding.kind).sort(), ["browser_unprotected", "disk_not_encrypted", "firewall_off"]);
  assert.equal(findings.find((finding) => finding.kind === "browser_unprotected").severity, "high");
  assert.equal(findings.find((finding) => finding.kind === "browser_unprotected").key, "device:browser:edge");
  const flags = rules.postureFlags(posture, browsers, now);
  assert.deepEqual(flags, { disk_encrypted: false, firewall: false, antivirus: true, os_supported: true, browser_protection: false });
  const phone = { os: "android", osName: "Android 13", osVersion: "13", screenLock: false, rooted: true, usbDebugging: true, patchAgeDays: 400 };
  const mobile = rules.classifyPosture(phone, [], rules.DEFAULT_ENDPOINT_POLICY, now, "mobile");
  assert.deepEqual(mobile.map((finding) => finding.kind).sort(), ["no_screen_lock", "os_unsupported", "rooted_device", "usb_debugging_on"]);
  assert.equal(rules.sortFindings(mobile)[0].kind, "rooted_device");
  // Every reported flag is accepted by the database.
  const sql = migration;
  for (const key of Object.keys({ ...flags, ...rules.postureFlags(phone, [], now) })) assert.match(sql, new RegExp(`'${key}'`), key);
});

