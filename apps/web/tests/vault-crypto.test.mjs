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
    memoryKib: 8192,
    iterations: 1,
    parallelism: 1,
    hashLength: 32,
  };
  const salt = cryptoModule.randomBytes(16);
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
  assert.match(recovery.display, /^1A-RK1-[A-Za-z0-9_-]{43}$/);
});
