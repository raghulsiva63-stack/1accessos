import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const root = fileURLToPath(new URL("..", import.meta.url));
const vite = await createServer({ appType: "custom", configFile: false, root, resolve: { alias: { "@": root } }, server: { middlewareMode: true, hmr: false } });
after(async () => vite.close());
const captcha = await vite.ssrLoadModule("/lib/auth/captcha.ts");

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
