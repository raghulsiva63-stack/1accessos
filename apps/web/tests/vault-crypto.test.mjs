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

test("derives a key and authenticates an encrypted envelope", async () => {
  const cryptoModule = await vite.ssrLoadModule("/lib/crypto/vault.ts");
  const profile = {
    algorithm: "ARGON2ID",
    memoryKib: 65536,
    iterations: 3,
    parallelism: 1,
    hashLength: 32,
  };
  const salt = cryptoModule.randomBytes(16);
  await assert.rejects(
    () => cryptoModule.deriveMasterKey("a correct test password", salt, { ...profile, memoryKib: 8192, iterations: 1 }),
    /secure range/i,
  );
  await assert.rejects(
    () => cryptoModule.deriveMasterKey("a correct test password", salt, { ...profile, memoryKib: 16_777_216 }),
    /secure range/i,
  );
  const wrappingKey = await cryptoModule.deriveMasterKey("a correct test password", salt, profile);
  const secret = cryptoModule.randomBytes(32);
  const envelope = await cryptoModule.wrapKey(wrappingKey, secret, "1accessos:test:v1");
  const recovered = await cryptoModule.unwrapKey(wrappingKey, envelope, "1accessos:test:v1");

  assert.deepEqual(recovered, secret);
  await assert.rejects(
    () => cryptoModule.unwrapKey(wrappingKey, envelope, "1accessos:changed-context:v1"),
    /incorrect|changed/i,
  );
});

test("creates a versioned 256-bit recovery key", async () => {
  const cryptoModule = await vite.ssrLoadModule("/lib/crypto/vault.ts");
  const recovery = cryptoModule.createRecoveryKey();

  assert.equal(recovery.secret.byteLength, 32);
  assert.match(recovery.display, /^PX-RK1-[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(cryptoModule.parseRecoveryKey(recovery.display), recovery.secret);
  assert.throws(() => cryptoModule.parseRecoveryKey("not-a-key"), /valid Passkey-X/i);
});

test("round-trips a password-protected portable export", async () => {
  const cryptoModule = await vite.ssrLoadModule("/lib/crypto/vault.ts");
  const payload = { product: "Passkey-X", items: [{ title: "Synthetic only" }] };
  const encrypted = await cryptoModule.createEncryptedExport(payload, "synthetic export password");

  assert.equal(encrypted.format, "passkey-x-export");
  assert.deepEqual(await cryptoModule.openEncryptedExport(encrypted, "synthetic export password"), payload);
  await assert.rejects(
    () => cryptoModule.openEncryptedExport(encrypted, "another wrong password"),
    /incorrect|changed/i,
  );
});

test("generator, CSV parser, and health analysis stay local and deterministic in shape", async () => {
  const tools = await vite.ssrLoadModule("/lib/vault/tools.ts");
  const password = tools.generatePassword({
    length: 30,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    avoidAmbiguous: true,
  });
  assert.equal(password.length, 30);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[a-z]/);
  assert.match(password, /\d/);

  const rows = tools.parseLoginCsv('name,url,username,password\n"Example",https://example.invalid,user,secret');
  assert.deepEqual(rows, [{ title: "Example", url: "https://example.invalid", username: "user", secret: "secret", notes: undefined }]);

  const now = new Date().toISOString();
  const health = tools.passwordHealth([
    { id: "1", contentType: "login", revision: 1, deletedAt: null, payload: { version: 1, title: "One", secret: "RepeatedPassword1", updatedAt: now } },
    { id: "2", contentType: "login", revision: 1, deletedAt: null, payload: { version: 1, title: "Two", secret: "RepeatedPassword1", updatedAt: now } },
  ]);
  assert.ok(health.score < 100);
  assert.ok(health.findings.some((finding) => finding.title === "Reused password"));
});
