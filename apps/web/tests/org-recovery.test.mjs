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

const recovery = await vite.ssrLoadModule("/lib/enterprise/org-recovery.ts");
const emergency = await vite.ssrLoadModule("/lib/enterprise/emergency.ts");
const vault = await vite.ssrLoadModule("/lib/crypto/vault.ts");

const TENANT = "11111111-1111-4111-8111-111111111111";
const MEMBER = "22222222-2222-4222-8222-222222222222";

test("organization recovery kit opens a member's sealed root key and nothing else", async () => {
  const { kit, publicKey } = await recovery.generateRecoveryKit(TENANT);
  assert.equal(publicKey.length, 65);
  assert.match(kit.fingerprint, /^[0-9a-f]{4}(:[0-9a-f]{4}){5}$/u);
  const rootKey = vault.randomBytes(32);
  const envelope = await recovery.sealRootForOrganization(rootKey, publicKey, kit.key_id, TENANT, MEMBER);
  const parsed = recovery.parseRecoveryKit(JSON.stringify(kit), TENANT);
  const opened = await recovery.openRootWithKit(parsed, envelope, TENANT, MEMBER);
  assert.deepEqual(opened, rootKey);
  // Bound to the member and tenant.
  await assert.rejects(recovery.openRootWithKit(parsed, envelope, TENANT, "33333333-3333-4333-8333-333333333333"));
  // A different organization's kit cannot open it.
  const other = await recovery.generateRecoveryKit(TENANT);
  await assert.rejects(recovery.openRootWithKit(other.kit, envelope, TENANT, MEMBER));
  assert.throws(() => recovery.parseRecoveryKit(JSON.stringify(kit), "44444444-4444-4444-8444-444444444444"), /different organization/u);
});

test("release codes round-trip and reject tampering", async () => {
  const code = vault.randomBytes(32);
  const text = recovery.formatReleaseCode(code);
  assert.ok(text.startsWith("PX-ORC1-"));
  assert.deepEqual(recovery.parseReleaseCode(` ${text} `), code);
  assert.throws(() => recovery.parseReleaseCode("PX-RK1-abc"), /PX-ORC1/u);
  const rootKey = vault.randomBytes(32);
  const release = await vault.wrapKey(code, rootKey, recovery.releaseContext("req-1"));
  assert.deepEqual(await vault.unwrapKey(code, release, recovery.releaseContext("req-1")), rootKey);
  await assert.rejects(vault.unwrapKey(code, release, recovery.releaseContext("req-2")));
});

test("emergency access links, envelopes and release timing", async () => {
  const token = vault.randomBytes(32);
  const id = "55555555-5555-4555-8555-555555555555";
  const link = emergency.parseEmergencyLink(`#emergency=${id}.${vault.toBase64Url(token)}`);
  assert.equal(link.id, id);
  assert.deepEqual(link.token, token);
  assert.equal(emergency.parseEmergencyLink(`#emergency=${id}.short`), null);
  assert.equal(emergency.parseEmergencyLink("#invite=x.y"), null);

  // Grantor wraps the workspace key with T; grantee wraps T with their root key; both open.
  const workspaceKey = vault.randomBytes(32);
  const granteeRoot = vault.randomBytes(32);
  const keyAad = emergency.emergencyKeyAad(id, TENANT, MEMBER, 1);
  const wrappedWorkspace = await vault.wrapKey(token, workspaceKey, keyAad);
  const wrappedSecret = await vault.wrapKey(granteeRoot, token, emergency.emergencySecretAad(id));
  const secret = await vault.unwrapKey(granteeRoot, wrappedSecret, emergency.emergencySecretAad(id));
  assert.deepEqual(await vault.unwrapKey(secret, wrappedWorkspace, keyAad), workspaceKey);
  await assert.rejects(vault.unwrapKey(secret, wrappedWorkspace, emergency.emergencyKeyAad(id, TENANT, MEMBER, 2)));

  const requested = { status: "requested", requested_at: "2026-01-01T00:00:00Z", wait_hours: 48 };
  assert.equal(emergency.releaseTime(requested).toISOString(), "2026-01-03T00:00:00.000Z");
  assert.equal(emergency.isReleased(requested, Date.parse("2026-01-02T23:59:00Z")), false);
  assert.equal(emergency.isReleased(requested, Date.parse("2026-01-03T00:00:01Z")), true);
  assert.equal(emergency.isReleased({ ...requested, status: "approved" }, 0), true);
  assert.equal(emergency.describeWait(0), "immediately");
  assert.equal(emergency.describeWait(72), "3 days");
});
