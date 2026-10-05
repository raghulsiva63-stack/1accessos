import assert from "node:assert/strict";
import { register } from "node:module";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const web = await import("../../apps/web/lib/desktop/browser-link.ts");
const extension = await import("../../apps/extension/src/desktop-link.ts");
const bridge = await import("../../apps/web/lib/desktop/bridge.ts");
const offline = await import("../../apps/web/lib/desktop/offline-cache.ts");
const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("extension and desktop derive the same pairing key and code, and messages interoperate", async () => {
  const pairingId = extension.base64url(crypto.getRandomValues(new Uint8Array(16)));
  assert.match(pairingId, /^[A-Za-z0-9_-]{22}$/u);
  const browserKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const desktopKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const browserPublic = new Uint8Array(await crypto.subtle.exportKey("raw", browserKeys.publicKey));
  const desktopPublic = new Uint8Array(await crypto.subtle.exportKey("raw", desktopKeys.publicKey));
  assert.match(extension.base64url(browserPublic), /^[A-Za-z0-9_-]{87}$/u);
  const inBrowser = await extension.pairingSecrets(browserKeys.privateKey, desktopPublic, pairingId);
  const inDesktop = await web.pairingSecrets(desktopKeys.privateKey, browserPublic, pairingId);
  assert.match(inBrowser.code, /^\d{6}$/u);
  assert.equal(inBrowser.code, inDesktop.code);

  const root = crypto.getRandomValues(new Uint8Array(32));
  const request = await extension.seal(inBrowser.key, pairingId, "unlock", { identityId: "me", nonce: "n1" });
  assert.deepEqual(await web.openLinkMessage(inDesktop.key, pairingId, "unlock", request), { identityId: "me", nonce: "n1" });
  const reply = await web.sealLinkMessage(inDesktop.key, pairingId, "unlock-result", { identityId: "me", root: extension.base64url(root), nonce: "n1" });
  const opened = await extension.open(inBrowser.key, pairingId, "unlock-result", reply);
  assert.deepEqual(extension.fromBase64url(opened.root), root);
  // Bound to the message type and the pairing.
  await assert.rejects(extension.open(inBrowser.key, pairingId, "unlock", reply));
  const otherId = extension.base64url(crypto.getRandomValues(new Uint8Array(16)));
  await assert.rejects(extension.open(inBrowser.key, otherId, "unlock-result", reply));
  // A different pairing gets a different key.
  const other = await extension.pairingSecrets(browserKeys.privateKey, desktopPublic, otherId);
  await assert.rejects(web.openLinkMessage(other.key, pairingId, "unlock", request));
  await assert.rejects(extension.pairingSecrets(browserKeys.privateKey, new Uint8Array(65), pairingId));
});

test("managed computers only accept accounts on the allowed email domains", () => {
  assert.equal(bridge.policyAllowsEmail(bridge.UNMANAGED_POLICY, "anyone@example.com"), true);
  const policy = { ...bridge.UNMANAGED_POLICY, allowedEmailDomains: ["acme.com"] };
  assert.equal(bridge.policyAllowsEmail(policy, "Ann@ACME.com"), true);
  assert.equal(bridge.policyAllowsEmail(policy, "ann@acme.com.evil.io"), false);
  assert.equal(bridge.policyAllowsEmail(policy, "ann@sub.acme.com"), false);
  assert.equal(bridge.policyAllowsEmail(policy, ""), false);
  assert.equal(bridge.policyAllowsEmail(policy, null), false);
});

test("offline copy is used only for connection failures and only when enabled", async () => {
  assert.equal(offline.isNetworkError(new TypeError("Failed to fetch")), true);
  assert.equal(offline.isNetworkError({ message: "TypeError: NetworkError when attempting to fetch resource." }), true);
  assert.equal(offline.isNetworkError({ code: "42501", message: "permission denied" }), false);
  // Disabled: errors pass through untouched, nothing is restored.
  await offline.configureOfflineCache(false);
  await assert.rejects(offline.withOfflineCopy(() => Promise.reject(new TypeError("Failed to fetch")), async () => {}, async () => ["saved"]), /Failed to fetch/u);
  // Enabled: network failure falls back to the saved copy and reports offline; other errors pass through.
  offline.configureOfflineCache(true);
  let saved = null;
  assert.deepEqual(await offline.withOfflineCopy(async () => ["fresh"], async (value) => { saved = value; }, async () => null), ["fresh"]);
  assert.deepEqual(saved, ["fresh"]);
  assert.equal(offline.isOffline(), false);
  assert.deepEqual(await offline.withOfflineCopy(() => Promise.reject(new TypeError("Failed to fetch")), async () => {}, async () => ["saved"]), ["saved"]);
  assert.equal(offline.isOffline(), true);
  await assert.rejects(offline.withOfflineCopy(() => Promise.reject({ code: "42501", message: "denied" }), async () => {}, async () => ["saved"]));
  await assert.rejects(offline.withOfflineCopy(() => Promise.reject(new TypeError("Failed to fetch")), async () => {}, async () => null), /Failed to fetch/u);
  offline.markOnline();
});

test("desktop native boundary: new commands are allow-listed and policies match the templates", async () => {
  const build = await read("apps/desktop/src-tauri/build.rs");
  const capability = JSON.parse(await read("apps/desktop/src-tauri/capabilities/desktop.json"));
  for (const command of ["desktop_policy", "browser_link_send"]) {
    assert.match(build, new RegExp(`"${command}"`));
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll("_", "-")}`), command);
  }
  const lib = await read("apps/desktop/src-tauri/src/lib.rs");
  assert.match(lib, /fn browser_link_send\([^)]*\)[^{]*\{\s*if !state\.settings\.get\(\)\.browser_integration/u);
  assert.match(lib, /\.visible\(!\(hidden && has_tray\)\)/u);
  const managed = await read("apps/desktop/src-tauri/src/managed.rs");
  const names = [...managed.matchAll(/^\s+\("([a-zA-Z]+)", Kind::/gmu)].map((match) => match[1]);
  assert.equal(names.length, 18);
  const admx = await read("apps/desktop/policy/windows/PasskeyX.admx");
  const mobileconfig = await read("apps/desktop/policy/macos/com.vlightsoft.passkeyx.mobileconfig");
  for (const name of names) {
    assert.match(admx, new RegExp(`valueName="${name}"`), name);
    assert.ok(Object.keys(bridge.UNMANAGED_POLICY).includes(name), name);
  }
  assert.match(admx, /key="SOFTWARE\\Policies\\Vlightsoft\\Passkey-X"/u);
  assert.match(managed, /SOFTWARE\\Policies\\Vlightsoft\\Passkey-X/u);
  assert.match(mobileconfig, /<string>com\.vlightsoft\.passkeyx<\/string>/u);
  // Only HKLM / forced managed preferences / root-owned files are read.
  assert.match(managed, /HKEY_LOCAL_MACHINE/u);
  assert.doesNotMatch(managed, /HKEY_CURRENT_USER/u);
  assert.match(managed, /CFPreferencesAppValueIsForced/u);
});

test("extension asks for native messaging only when pairing", async () => {
  const manifest = JSON.parse(await read("apps/extension/public/manifest.json"));
  assert.ok(!manifest.permissions.includes("nativeMessaging"));
  assert.deepEqual(manifest.optional_permissions, ["nativeMessaging"]);
  const link = await read("apps/extension/src/desktop-link.ts");
  assert.match(link, /connectNative\(HOST\)/u);
  assert.match(link, /generateKey\(\{ name: "ECDH", namedCurve: "P-256" \}, false/u);
  const host = await read("apps/desktop/src-tauri/src/browser_link.rs");
  assert.match(host, /pub const UAT_EXTENSION_ID: &str = "egkaneajfcaomheahcmopioiemmplebg"/u);
  assert.match(host, /if expected\.is_empty\(\) \|\| !same\(token, &expected\) \|\| !allowed/u);
});
