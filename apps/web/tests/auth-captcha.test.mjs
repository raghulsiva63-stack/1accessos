import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const root = fileURLToPath(new URL("..", import.meta.url));
const vite = await createServer({ appType: "custom", configFile: false, root, resolve: { alias: { "@": root } }, server: { middlewareMode: true, hmr: false } });
after(async () => vite.close());
const captcha = await vite.ssrLoadModule("/lib/auth/captcha.ts");
const sessions = await vite.ssrLoadModule("/lib/auth/session-machine.ts");

test("CAPTCHA remains optional until a production site key is configured", () => {
  assert.equal(captcha.captchaReady(false, null), true);
  assert.deepEqual(captcha.captchaOptions(null), {});
});

test("CAPTCHA-enabled auth rejects absent and whitespace-only tokens", () => {
  assert.equal(captcha.captchaReady(true, null), false);
  assert.equal(captcha.captchaReady(true, "   "), false);
});

test("CAPTCHA tokens are normalized before submission", () => {
  assert.equal(captcha.captchaReady(true, " token "), true);
  assert.deepEqual(captcha.captchaOptions(" token "), { captchaToken: "token" });
});

test("same-account sign-in and token refresh preserve in-memory vault setup", () => {
  assert.deepEqual(sessions.authSessionTransition("user-a", "user-a", "SIGNED_IN"), {
    nextUserId: "user-a",
    accountChanged: false,
    clearVaultState: false,
    passwordRecovery: false,
  });
  assert.equal(sessions.authSessionTransition("user-a", "user-a", "TOKEN_REFRESHED").clearVaultState, false);
});

test("account changes and sign-out clear vault state while recovery is explicit", () => {
  assert.equal(sessions.authSessionTransition("user-a", "user-b", "SIGNED_IN").clearVaultState, true);
  assert.equal(sessions.authSessionTransition("user-a", null, "SIGNED_OUT").clearVaultState, true);
  assert.equal(sessions.authSessionTransition(null, "user-a", "PASSWORD_RECOVERY").passwordRecovery, true);
});
