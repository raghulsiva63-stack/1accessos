import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  challengeFor, parseLinkRequest, parsePastedCode, parsePendingLink, pendingLinkValue, PLATFORM_LABELS,
  randomToken, returnUrl, signInUrl,
} from "../../apps/web/lib/desktop/handoff.ts";

const read = (path) => readFile(path, "utf8");

test("PKCE challenge matches RFC 7636 and tokens are url-safe", async () => {
  assert.equal(await challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  const verifier = randomToken(48);
  assert.match(verifier, /^[A-Za-z0-9_-]{64}$/);
  await assert.rejects(challengeFor("short"));
});

test("the approval page only accepts well-formed requests with a fixed app label", () => {
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  const state = "s".repeat(32);
  const url = signInUrl("https://passkey-x.com/", { challenge, state, port: 51234, platform: "windows" });
  assert.ok(url.startsWith("https://passkey-x.com/desktop-link/?"));
  const parsed = parseLinkRequest(new URL(url).search);
  assert.deepEqual(parsed, { challenge, state, port: 51234, platform: "windows" });
  assert.equal(PLATFORM_LABELS[parsed.platform], "Passkey-X for Windows");
  assert.equal(parseLinkRequest(`?challenge=bad&state=${state}&port=51234&platform=macos`), null);
  assert.equal(parseLinkRequest(`?challenge=${challenge}&state=x&port=51234&platform=macos`), null);
  assert.equal(parseLinkRequest(`?challenge=${challenge}&state=${state}&port=80&platform=macos`), null);
  assert.equal(parseLinkRequest(`?challenge=${challenge}&state=${state}&port=51234&platform=Security%20Check`), null);
});

test("the code goes back to 127.0.0.1 on this computer; pasting accepts only a bare code", () => {
  const code = "c".repeat(43);
  const state = "s".repeat(32);
  assert.equal(returnUrl(51234, code, state), `http://127.0.0.1:51234/callback?code=${code}&state=${state}`);
  assert.throws(() => returnUrl(51234, "bad", state));
  assert.throws(() => returnUrl(22, code, state));
  assert.equal(parsePastedCode(`  ${code} `), code);
  assert.equal(parsePastedCode("hello"), null);
});

test("a pending approval survives an SSO redirect for 10 minutes only", () => {
  const request = { challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", state: "s".repeat(32), port: 51234, platform: "macos" };
  const now = 1_000_000;
  assert.deepEqual(parsePendingLink(pendingLinkValue(request, now), now + 60_000), request);
  assert.equal(parsePendingLink(pendingLinkValue(request, now), now + 11 * 60_000), null);
  assert.equal(parsePendingLink("{bad", now), null);
});

test("desktop never shows a password form or loads the website in its window", async () => {
  const page = await read("apps/web/app/page.tsx");
  assert.match(page, /inDesktopApp \? <DesktopSignIn notice=\{policyNotice\} \/> : <AuthScreen/);
  assert.match(page, /!profile && inDesktopApp\) return <DesktopFinishSetup/);
  const signIn = await read("apps/web/components/desktop/desktop-sign-in.tsx");
  assert.match(signIn, /functions\.invoke<\{ tokenHash\?: string \}>\("desktop-session"/);
  assert.match(signIn, /verifyOtp\(\{ token_hash: data\.tokenHash, type: "magiclink" \}\)/);
  assert.doesNotMatch(signIn, /signInWithPassword/);
  const conf = JSON.parse(await read("apps/desktop/src-tauri/tauri.conf.json"));
  assert.equal(conf.build.frontendDist, "../dist");
  assert.match(conf.app.security.csp["connect-src"], /https:\/\/wkkmyacbhqloubtwvjom\.supabase\.co/);
  assert.equal(conf.app.security.csp["object-src"], "'none'");
  assert.doesNotMatch(conf.app.security.csp["script-src"], /'unsafe-inline'|'unsafe-eval'/);
  const lib = await read("apps/desktop/src-tauri/src/lib.rs");
  assert.match(lib, /WebviewUrl::App\("index\.html"\.into\(\)\)/);
  assert.match(lib, /\.content_protected\(true\)/);
  assert.doesNotMatch(lib, /WebviewUrl::External/);
  const capability = JSON.parse(await read("apps/desktop/src-tauri/capabilities/desktop.json"));
  assert.equal(capability.remote, undefined, "no website may call native commands");
  assert.deepEqual(capability.windows, ["main"]);
});

test("the sign-in handoff is single-use, short-lived and PKCE-bound on the server", async () => {
  const sql = await read("supabase/migrations/20261003090000_desktop_sign_in.sql");
  assert.match(sql, /interval '2 minutes'/);
  assert.match(sql, /set failed_at = now\(\)/);
  assert.match(sql, /session_mfa_satisfied\(\)/);
  assert.match(sql, /grant execute on function public\.redeem_desktop_handoff\(text, text\) to service_role;/);
  assert.doesNotMatch(sql, /grant execute on function public\.redeem_desktop_handoff\(text, text\) to authenticated/);
  const fn = await read("supabase/functions/desktop-session/index.ts");
  assert.match(fn, /redeem_desktop_handoff/);
  assert.match(fn, /generateLink\(\{ type: "magiclink"/);
});

test("desktop keeps secrets out of plain storage and shared links point at passkey-x.com", async () => {
  const client = await read("apps/web/lib/supabase/client.ts");
  assert.match(client, /isDesktopApp\(\) \? desktopAuthStorage\(\) : window\.sessionStorage/);
  const guards = await read("apps/web/components/enterprise/vault-guards.tsx");
  assert.match(guards, /await desktop\.copy\(value/);
  for (const file of ["apps/web/components/app/referral-card.tsx", "apps/web/components/app/emergency-access-view.tsx", "apps/web/components/app/shell/collaboration-views.tsx"]) {
    assert.doesNotMatch(await read(file), /window\.location\.origin/, file);
  }
});
