import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(await readFile(new URL("../public/manifest.json", import.meta.url), "utf8"));
const content = await readFile(new URL("../src/content.ts", import.meta.url), "utf8");
const background = await readFile(new URL("../src/background.ts", import.meta.url), "utf8");
const popup = await readFile(new URL("../popup.html", import.meta.url), "utf8");
const boundary = await readFile(new URL("../src/message-boundary.ts", import.meta.url), "utf8");

test("Manifest V3 extension has no remote code and protects extension pages", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  assert.match(manifest.content_security_policy.extension_pages, /object-src 'none'/);
  assert.deepEqual(manifest.content_scripts[0].matches, ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"]);
  assert.equal("key" in manifest, false, "store builds must not ship a manifest key");
  assert.equal(manifest.commands["fill-login"].suggested_key.default, "Alt+Shift+X");
});

test("web pairing is production-origin bound and authentication is session-only", () => {
  assert.deepEqual(manifest.externally_connectable.matches.sort(), ["https://passkey-x.com/*"]);
  assert.doesNotMatch(popup, /login-password|type="email"/);
  assert.match(background, /chrome\.storage\.session/);
  assert.doesNotMatch(background, /signInWithPassword/);
  assert.match(boundary, /https:\/\/passkey-x\.com/);
  assert.match(boundary, /request\.extensionId === extensionId/);
  assert.match(manifest.content_security_policy.extension_pages, /wasm-unsafe-eval/);
});

test("production package has no development backend fallback", () => {
  assert.deepEqual(manifest.host_permissions.sort(), [
    "https://passkey-x.com/*",
    "https://wkkmyacbhqloubtwvjom.supabase.co/*",
  ]);
  assert.doesNotMatch(background, /egqgzkirazabocqwdlfp/u);
  assert.doesNotMatch(background, /sb_publishable_[A-Za-z0-9_-]{20,}/u);
  assert.match(background, /production configuration is missing/u);
});

test("fill path requires the extension sender and an exact page origin", () => {
  assert.match(content, /sender\.id !== chrome\.runtime\.id/);
  assert.match(content, /request\.origin !== location\.origin/);
  assert.doesNotMatch(content, /innerHTML|insertAdjacentHTML|eval\(/);
});

test("service worker keeps vault state in memory and rejects origin substitution", () => {
  assert.match(background, /let vaults: VaultContext\[\] = \[\]/);
  assert.match(background, /let accountRoot: Uint8Array \| null = null/);
  assert.match(background, /request\.origin !== origin/);
  assert.match(background, /context\.key\.fill\(0\)/);
  assert.match(background, /accountRoot\?\.fill\(0\)/);
  assert.match(background, /60_000/);
  assert.match(background, /ignoredOrigins/);
  assert.doesNotMatch(background, /console\.log/);
});

test("shared workspaces and fill-only capsules stay origin-bound and are consumed at fill time", () => {
  assert.match(background, /workspace_memberships/);
  assert.match(background, /access_capsules/);
  assert.match(background, /capsule-recipient:v1/);
  assert.match(background, /capsule-payload:v1/);
  assert.match(background, /consume_access_capsule/);
  assert.match(background, /sameSite\(item\.url, origin\)/);
});

test("plain-HTTP pages never get save prompts or fills, and www/apex share logins", () => {
  const safeOriginSource = (source) => source.match(/function safeOrigin\(value: string\) \{[\s\S]*?\n\}/u)[0].replace("(value: string)", "(value)");
  for (const source of [background, content]) {
    const safeOrigin = new Function(`${safeOriginSource(source)}; return safeOrigin;`)();
    assert.equal(safeOrigin("http://example.com/login"), "");
    assert.equal(safeOrigin("https://example.com/login"), "https://example.com");
    assert.equal(safeOrigin("http://localhost:3000/login"), "http://localhost:3000");
    assert.equal(safeOrigin("javascript:alert(1)"), "");
  }
  const helpers = background.match(/function siteKey[^\n]*\n\s*function sameSite[^\n]*/u)[0]
    .replace("(origin: string)", "(origin)").replace("(url: string, origin: string)", "(url, origin)");
  const sameSite = new Function(`${safeOriginSource(background)}\n${helpers}; return sameSite;`)();
  assert.equal(sameSite("https://www.example.com/login", "https://example.com"), true);
  assert.equal(sameSite("https://example.com/login", "https://www.example.com"), true);
  assert.equal(sameSite("https://login.example.com/", "https://example.com"), false);
  assert.equal(sameSite("https://example.com/", "https://example.com.evil.test"), false);
  assert.equal(sameSite("https://example.com:8443/", "https://example.com"), false);
  assert.equal(sameSite("http://example.com/", "https://example.com"), false);
});
