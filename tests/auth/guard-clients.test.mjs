import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("extension: Web Guard adds no new permissions and its warning page is built", async () => {
  const manifest = JSON.parse(await read("apps/extension/public/manifest.json"));
  assert.deepEqual([...manifest.permissions].sort(), ["activeTab", "storage", "tabs"]);
  assert.deepEqual(manifest.optional_permissions, ["nativeMessaging"]);
  assert.deepEqual(manifest.host_permissions.sort(), ["https://passkey-x.com/*", "https://wkkmyacbhqloubtwvjom.supabase.co/*"]);
  assert.match(await read("apps/extension/vite.config.ts"), /warning: resolve\(import\.meta\.dirname, "warning\.html"\)/u);
  const warning = await read("apps/extension/src/warning.ts");
  assert.doesNotMatch(warning, /innerHTML|insertAdjacentHTML|document\.write/u, "warning page shows text only");
  const background = await read("apps/extension/src/background.ts");
  // Proceeding is only possible for the page this tab was warned about, and never when blocked.
  assert.match(background, /warned\.url !== request\.url \|\| warned\.decision\.action !== "warn"/u);
  const guard = await read("apps/extension/src/web-guard.ts");
  assert.match(guard, /lookupThreats\(url, \[globalSet, organizationSet\], confirm\)/u);
  assert.doesNotMatch(guard, /threat-check", \{ url/u, "addresses are never sent");
});

test("desktop: Guard commands are allow-listed; the alert window can only close itself or open the check", async () => {
  const build = await read("apps/desktop/src-tauri/build.rs");
  const main = JSON.parse(await read("apps/desktop/src-tauri/capabilities/desktop.json"));
  const alert = JSON.parse(await read("apps/desktop/src-tauri/capabilities/alert.json"));
  for (const command of ["endpoint_inventory", "endpoint_posture", "endpoint_browsers", "guard_alert", "alert_dismiss", "alert_open_main"]) {
    assert.match(build, new RegExp(`"${command}"`), command);
  }
  for (const permission of ["allow-endpoint-inventory", "allow-endpoint-posture", "allow-endpoint-browsers", "allow-guard-alert"]) assert.ok(main.permissions.includes(permission), permission);
  assert.ok(!main.permissions.includes("allow-alert-dismiss"));
  assert.deepEqual(alert.windows, ["alert"]);
  assert.deepEqual(alert.permissions.sort(), ["allow-alert-dismiss", "allow-alert-open-main"]);
  assert.equal(alert.remote, undefined);
  const lib = await read("apps/desktop/src-tauri/src/lib.rs");
  assert.match(lib, /WebviewUrl::App\("desktop-alert\.html"\.into\(\)\)/u);
  assert.match(lib, /\.always_on_top\(true\)/u);
  assert.match(lib, /if kind == "guard-alert"/u);
  // Vault messages still require "Browser extension" to be on.
  assert.match(lib, /if !relay_app\.state::<AppState>\(\)\.settings\.get\(\)\.browser_integration \{/u);
  const endpoint = await read("apps/desktop/src-tauri/src/endpoint.rs");
  assert.doesNotMatch(endpoint, /runas|sudo|Start-Process.*-Verb/u, "no elevation");
});

test("android: share target only, device facts through the official-origin bridge", async () => {
  const manifest = await read("apps/mobile/android/app/src/main/AndroidManifest.xml");
  assert.match(manifest, /android:name="\.LinkCheckActivity" android:exported="true"/u);
  assert.match(manifest, /<action android:name="android\.intent\.action\.SEND" \/>/u);
  assert.doesNotMatch(manifest, /android\.intent\.action\.VIEW/u, "Passkey-X never becomes a browser");
  assert.doesNotMatch(manifest, /READ_SMS|QUERY_ALL_PACKAGES|ACCESS_FINE_LOCATION/u);
  const activity = await read("apps/mobile/android/app/src/main/java/com/vlightsoft/passkeyx/MainActivity.java");
  assert.match(activity, /case "devicePosture"/u);
  assert.match(activity, /Set\.of\("https:\/\/passkey-x\.com"\)/u);
});

test("threat services: Web Risk only on prefix hits, with a daily cap; feeds need their own licence keys", async () => {
  const check = await read("supabase/functions/threat-check/index.ts");
  assert.match(check, /WEB_RISK_DAILY_LIMIT/u);
  assert.match(check, /const listed = prefixes\.filter/u);
  assert.match(check, /\[AQgw\]==\$/u);
  const sync = await read("supabase/functions/threat-sync/index.ts");
  assert.match(sync, /threatLists:computeDiff/u);
  assert.match(sync, /URLHAUS_AUTH_KEY/u);
  assert.doesNotMatch(sync, /openphish\.com\/feed\.txt|raw\.githubusercontent\.com\/openphish/u, "the free OpenPhish feed is non-commercial");
  const config = await read("supabase/config.toml");
  assert.match(config, /\[functions\.threat-sync\]\nverify_jwt = false/u);
  assert.match(config, /\[functions\.threat-check\]\nverify_jwt = true/u);
});
