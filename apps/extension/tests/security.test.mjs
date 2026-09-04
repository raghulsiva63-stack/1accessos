import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(await readFile(new URL("../public/manifest.json", import.meta.url), "utf8"));
const content = await readFile(new URL("../src/content.ts", import.meta.url), "utf8");
const background = await readFile(new URL("../src/background.ts", import.meta.url), "utf8");

test("Manifest V3 extension has no remote code and protects extension pages", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  assert.match(manifest.content_security_policy.extension_pages, /object-src 'none'/);
  assert.deepEqual(manifest.content_scripts[0].matches, ["http://*/*", "https://*/*"]);
  assert.equal(manifest.commands["fill-login"].suggested_key.default, "Alt+Shift+X");
});

test("fill path requires the extension sender and an exact page origin", () => {
  assert.match(content, /sender\.id !== chrome\.runtime\.id/);
  assert.match(content, /request\.origin !== location\.origin/);
  assert.doesNotMatch(content, /innerHTML|insertAdjacentHTML|eval\(/);
});

test("service worker keeps vault state in memory and rejects origin substitution", () => {
  assert.match(background, /let vault: VaultContext \| null = null/);
  assert.match(background, /request\.origin !== origin/);
  assert.match(background, /vault\?\.key\.fill\(0\)/);
  assert.match(background, /60_000/);
  assert.match(background, /ignoredOrigins/);
  assert.doesNotMatch(background, /console\.log/);
});
