import assert from "node:assert/strict";
import { register } from "node:module";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const autotype = await import("../../apps/web/lib/desktop/autotype.ts");
const references = await import("../../apps/web/lib/desktop/references.ts");
const downloads = await import("../../apps/web/lib/desktop/download-check.ts");
const presentation = await import("../../apps/web/lib/desktop/presentation.ts");
const requests = await import("../../apps/web/lib/desktop/requests.ts");
const ssh = await import("../../apps/web/lib/desktop/ssh-keys.ts");
const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

const item = (id, title, extra = {}, contentType = "login") => ({
  id, contentType, revision: 1, deletedAt: null,
  payload: { version: 1, title, username: "ann@acme.com", secret: "S3cret!pass", updatedAt: "2026-01-01T00:00:00Z", ...extra },
});
// RFC 6238 test seed (ASCII "12345678901234567890").
const TOTP_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("auto-type types without asking only for an explicit rule or remembered choice", () => {
  const vpn = item("vpn", "Acme VPN", { fields: { "Auto-type window": "Cisco Secure Client*" } });
  const rdp = item("rdp", "Jump host", { url: "rdp://jump.acme.local" });
  const github = item("gh", "GitHub", { url: "https://github.com" });
  const items = [vpn, rdp, github, item("old", "Old", { archived: true }), item("note", "Note", {}, "secure-note")];

  const ruled = autotype.planAutoType(items, { app: "csc_ui.exe", title: "Cisco Secure Client - Login" });
  assert.equal(ruled.automatic?.id, "vpn");
  assert.equal(ruled.browser, false);

  // A name match is only a suggestion.
  const named = autotype.planAutoType(items, { app: "GitHubDesktop.exe", title: "Sign in to GitHub" });
  assert.equal(named.automatic, null);
  assert.deepEqual(named.candidates.map((c) => [c.item.id, c.reason]), [["gh", "name"]]);
  // Words inside other words don't match ("Notgithubby").
  assert.equal(autotype.planAutoType(items, { app: "x", title: "Notgithubby" }).candidates.length, 0);

  // Remembered choice for this exact window.
  const approvals = autotype.rememberApproval([], { app: "C:\\Windows\\mstsc.exe", title: "Windows Security" }, "rdp", new Date("2026-10-01T00:00:00Z"));
  assert.equal(approvals[0].app, "mstsc");
  assert.equal(autotype.planAutoType(items, { app: "mstsc.exe", title: "Windows  Security" }, approvals).automatic?.id, "rdp");
  assert.equal(autotype.planAutoType(items, { app: "evil.exe", title: "Windows Security" }, approvals).automatic, null);
  // Two strong matches → ask.
  const both = autotype.rememberApproval(approvals, { app: "csc_ui", title: "Cisco Secure Client - Login" }, "rdp");
  assert.equal(autotype.planAutoType(items, { app: "csc_ui.exe", title: "Cisco Secure Client - Login" }, both).automatic, null);
  // Browsers always ask, even with a rule.
  const browserRule = item("bank", "Bank", { fields: { "Auto-type window": "*Bank*" } });
  const inBrowser = autotype.planAutoType([browserRule], { app: "chrome.exe", title: "My Bank - Google Chrome" });
  assert.equal(inBrowser.browser, true);
  assert.equal(inBrowser.automatic, null);
  assert.equal(inBrowser.candidates[0].item.id, "bank");
  assert.equal(autotype.isBrowser("/Applications/Safari"), true);
  assert.equal(autotype.isBrowser("Code.exe"), false);
  assert.deepEqual(autotype.parseApprovals("not json"), []);
  assert.equal(autotype.parseApprovals(JSON.stringify(both)).length, 2);
});

test("auto-type sequences become key steps with control characters removed", async () => {
  assert.equal(autotype.wildcardMatch("*Remote ?esktop*", "jump - Remote Desktop Connection"), true);
  assert.equal(autotype.wildcardMatch("a.b", "axb"), false);
  assert.equal(autotype.parseSequence("{USERNAME}{BOGUS}"), null);
  assert.equal(autotype.parseSequence("{USERNAME"), null);
  const login = item("a", "A", { secret: "pa\nss", fields: { totp: TOTP_SEED, Pin: "4321", "Auto-type sequence": "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{DELAY 300}{S:pin}{ENTER}" } });
  const steps = await autotype.buildSteps(login, undefined, 59_000);
  assert.deepEqual(steps, [
    { type: "text", value: "ann@acme.com" }, { type: "key", key: "tab" }, { type: "text", value: "pass" }, { type: "key", key: "tab" },
    { type: "text", value: "287082" }, { type: "delay", ms: 300 }, { type: "text", value: "4321" }, { type: "key", key: "enter" },
  ]);
  assert.equal(autotype.itemSequence(item("b", "B", { username: "" })), "{PASSWORD}{ENTER}");
  await assert.rejects(autotype.buildSteps(item("c", "C"), "{TOTP}"), autotype.AutoTypeError);
  await assert.rejects(autotype.buildSteps(item("d", "D", { secret: "" }), "{PASSWORD}"), /no password/u);
  autotype.forgetSteps(steps);
  assert.equal(steps.length, 0);
  assert.match(autotype.autoTypeErrorMessage("accessibility"), /Accessibility/u);
});

test("pkx references resolve all-or-nothing across vaults", async () => {
  assert.deepEqual(references.parseReference("px://Work/Production DB/password"), { vault: "Work", item: "Production DB", field: "password" });
  assert.deepEqual(references.parseReference("px://GitHub/token"), { vault: null, item: "GitHub", field: "token" });
  assert.equal(references.parseReference("px://only"), null);
  assert.equal(references.parseReference("https://x/y"), null);
  assert.equal(references.parseReference("px://a//b"), null);
  const sources = [
    { vaultName: "Work", items: [item("db", "Production DB", { secret: "pg-pass", fields: { host: "db.acme" } }), item("gh", "GitHub", { secret: "ghp_x", fields: { totp: TOTP_SEED } })] },
    { vaultName: "Personal", items: [item("gh2", "GitHub", { secret: "mine" }), item("gone", "Old", { secret: "x" })] },
  ];
  sources[1].items[1].deletedAt = "2026-01-01";
  assert.deepEqual(await references.resolveReferences(["px://Work/Production DB/password", "px://production db/HOST", "px://Work/GitHub/totp"], sources, 59_000),
    { values: { "px://Work/Production DB/password": "pg-pass", "px://production db/HOST": "db.acme", "px://Work/GitHub/totp": "287082" } });
  assert.deepEqual(await references.resolveReferences(["px://GitHub/password"], sources), { error: "ambiguous", reference: "px://GitHub/password" });
  assert.deepEqual(await references.resolveReferences(["px://Work/Production DB/password", "px://Old/password"], sources), { error: "not_found", reference: "px://Old/password" });
  assert.deepEqual(await references.resolveReferences(["px://Work/GitHub/nope"], sources), { error: "not_found", reference: "px://Work/GitHub/nope" });
  assert.equal(references.describeReferences(["px://Work/GitHub/password"], sources)[0].label, "GitHub · password");
  assert.equal(references.referenceFor("Work", "A/B 100%", "password"), "px://Work/A%2FB 100%25/password");
  assert.equal(references.parseReference(references.referenceFor("Work", "A/B 100%", "password")).item, "A/B 100%");
});

test("downloads: disguised names, dangerous sources and known malware are flagged", () => {
  assert.equal(downloads.fileType("Setup.EXE"), "program");
  assert.equal(downloads.fileType("report.xlsm"), "macro");
  assert.equal(downloads.fileType("photo.png"), "other");
  assert.equal(downloads.nameTricks("invoice.pdf.exe").length, 1);
  assert.equal(downloads.nameTricks("invoice\u202Efdp.exe").length, 1);
  assert.equal(downloads.nameTricks("archive.tar.gz").length, 0);
  assert.equal(downloads.assessDownload({ name: "invoice.pdf.exe", sourceUrl: null }, null, null).level, "dangerous");
  const clean = downloads.assessDownload({ name: "setup.exe", sourceUrl: "https://vendor.example/setup.exe" }, { level: "safe", domain: "vendor.example", reasons: [] }, null);
  assert.equal(clean.level, "safe");
  assert.equal(clean.kind, null);
  const phishy = { level: "dangerous", domain: "evil.example", reasons: [] };
  assert.equal(downloads.assessDownload({ name: "setup.exe", sourceUrl: "https://evil.example/a" }, phishy, null).level, "dangerous");
  assert.equal(downloads.assessDownload({ name: "photo.png", sourceUrl: "https://evil.example/a" }, phishy, null).level, "suspicious");
  const malware = downloads.assessDownload({ name: "tool.zip", sourceUrl: null }, null, { sha256: "a".repeat(64), signature: "AgentTesla", source: "MalwareBazaar" });
  assert.equal(malware.kind, "dangerous_download");
  assert.match(malware.reasons[0], /AgentTesla/u);
  assert.deepEqual(downloads.hashesToCheck([{ sha256: "A".repeat(64) }, { sha256: "a".repeat(64) }, { sha256: "xyz" }, { sha256: null }]), ["a".repeat(64)]);
});

test("presentation mode and native requests", () => {
  const off = { active: false, manual: false, detected: false, reasons: [] };
  assert.deepEqual(presentation.nextPresentation(off, { sharing: true, reasons: ["OBS Studio"] }, true), { manual: false, detected: true, reasons: ["OBS Studio"], active: true });
  assert.equal(presentation.nextPresentation(off, { sharing: true, reasons: ["OBS Studio"] }, false).active, false);
  assert.equal(presentation.nextPresentation({ ...off, manual: true }, { sharing: false, reasons: [] }, true).active, true);

  const id = "0123456789abcdef01234567";
  requests.receive("ssh", { id, keyId: "k", keyName: "Laptop\u0007", fingerprint: "SHA256:x", client: "ssh", locked: true }, 1_000);
  assert.equal(requests.pendingSsh(2_000).keyName, "Laptop");
  assert.equal(requests.pendingSsh(1_000 + requests.LIFETIME.ssh), null);
  requests.receive("ssh", { id: "short" }, 1_000);
  requests.receive("cli", { id, refs: ["px://a/b", 7], command: "npm start", cwd: "/app", client: "pkx" }, 1_000);
  assert.deepEqual(requests.pendingCli(1_500).refs, ["px://a/b"]);
  requests.finishCli(id);
  assert.equal(requests.pendingCli(1_500), null);
  requests.receive("auto-type", { token: id, title: "Login", app: "app.exe" }, 1_000);
  assert.equal(requests.pendingAutoType(1_500).token, id);
  requests.receive("auto-type", { error: "no_window" }, 1_000);
  assert.equal(requests.pendingAutoType(1_500).error, "no_window");
  requests.clearRequests();
  assert.equal(requests.pendingAutoType(1_500), null);
});

test("ssh keys: only OpenSSH keys go to the agent, setup snippets per system", () => {
  const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
  const keys = [item("k1", "Laptop", { secret: pem }, "ssh-key"), item("k2", "Old RSA", { secret: "-----BEGIN RSA PRIVATE KEY-----" }, "ssh-key"), item("l", "Login", { secret: pem })];
  assert.deepEqual(ssh.agentKeyInputs(keys), [{ id: "k1", name: "Laptop", privateKey: pem }]);
  assert.equal(Buffer.from(ssh.randomSeed(), "base64").length, 32);
  assert.match(ssh.setupSnippets("/home/ann/.passkey-x/ssh-agent.sock", "linux").shell, /^export SSH_AUTH_SOCK="\/home\/ann/u);
  assert.match(ssh.setupSnippets("\\\\.\\pipe\\passkey-x-ssh-agent-ann", "windows").shell, /^setx SSH_AUTH_SOCK/u);
  assert.match(ssh.sshErrorMessage("unsupported:ssh-rsa"), /Ed25519/u);
  const payload = ssh.sshKeyPayload(" ", pem, "ssh-ed25519 AAAA laptop", "SHA256:abc", new Date("2026-10-01T00:00:00Z"));
  assert.equal(payload.title, "SSH key");
  assert.equal(payload.fields.publicKey, "ssh-ed25519 AAAA laptop");
});

test("desktop 1.2 native boundary: commands allow-listed, policies in templates, pkx bundled", async () => {
  const build = await read("apps/desktop/src-tauri/build.rs");
  const capability = JSON.parse(await read("apps/desktop/src-tauri/capabilities/desktop.json"));
  const bridge = await read("apps/web/lib/desktop/bridge.ts");
  const commands = ["auto_type_info", "auto_type_present", "auto_type_perform", "ssh_agent_load", "ssh_agent_status", "ssh_agent_reply", "ssh_agent_forget",
    "ssh_key_generate", "ssh_key_inspect", "cli_reply", "cli_info", "cli_install_path", "downloads_recent", "download_quarantine", "reveal_path",
    "presentation_check", "sprawl_scan", "sprawl_extract", "sprawl_read_export", "sprawl_trash"];
  for (const command of commands) {
    assert.match(build, new RegExp(`"${command}"`), command);
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll("_", "-")}`), command);
    assert.match(bridge, new RegExp(`"${command}"`), command);
  }
  const cargo = await read("apps/desktop/src-tauri/Cargo.toml");
  assert.match(cargo, /name = "pkx"/u);
  assert.match(cargo, /default-run = "passkey-x"/u);
  const admx = await read("apps/desktop/policy/windows/PasskeyX.admx");
  const adml = await read("apps/desktop/policy/windows/en-US/PasskeyX.adml");
  for (const name of ["autoType", "sshAgent", "commandLine", "downloadProtection"]) {
    assert.match(admx, new RegExp(`valueName="${name}"`), name);
    assert.match(adml, new RegExp(`id="${name}_Help"`), name);
  }
  // The auto-type shortcut checks the target is still in front before every step.
  const native = await read("apps/desktop/src-tauri/src/autotype.rs");
  assert.match(native, /target_changed/u);
  const fileCheck = await read("supabase/functions/file-check/index.ts");
  assert.match(fileCheck, /requireUser/u);
  assert.match(await read("supabase/config.toml"), /\[functions\.file-check\]\nverify_jwt = true/u);
});
