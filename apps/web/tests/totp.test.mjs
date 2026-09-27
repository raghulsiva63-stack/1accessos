import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const root = fileURLToPath(new URL("..", import.meta.url));
const vite = await createServer({
  appType: "custom",
  configFile: false,
  root,
  resolve: { alias: { "@": root } },
  server: { middlewareMode: true, hmr: false },
});

after(async () => vite.close());

const { decodeBase32, parseTotp, totpCode, secondsRemaining, findTotpField } = await vite.ssrLoadModule("/lib/vault/totp.ts");

// RFC 6238 Appendix B: ASCII "12345678901234567890" for SHA-1.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("base32 decodes the RFC 6238 seed", () => {
  assert.equal(new TextDecoder().decode(decodeBase32(RFC_SECRET)), "12345678901234567890");
  assert.throws(() => decodeBase32("not base32!"));
});

test("TOTP matches RFC 6238 SHA-1 vectors", async () => {
  const config = { ...parseTotp(`otpauth://totp/Example:alice?secret=${RFC_SECRET}&digits=8`) };
  assert.equal(config.digits, 8);
  assert.equal(await totpCode(config, 59_000), "94287082");
  assert.equal(await totpCode(config, 1_111_111_109_000), "07081804");
  assert.equal(await totpCode(config, 20_000_000_000_000), "65353130");
});

test("parses otpauth metadata and bare secrets, rejects junk", () => {
  const parsed = parseTotp("otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60&algorithm=SHA256");
  assert.equal(parsed.issuer, "GitHub");
  assert.equal(parsed.account, "alice@example.com");
  assert.equal(parsed.period, 60);
  assert.equal(parsed.algorithm, "SHA-256");
  assert.equal(parseTotp("JBSW Y3DP EHPK 3PXP").digits, 6);
  assert.equal(parseTotp("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"), null);
  assert.equal(parseTotp("hello"), null);
  assert.equal(secondsRemaining({ period: 30 }, 59_000), 1);
  assert.deepEqual(findTotpField({ Notes: "x", TOTP: "JBSWY3DPEHPK3PXP" }), ["TOTP", "JBSWY3DPEHPK3PXP"]);
});
