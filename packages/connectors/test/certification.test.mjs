import assert from "node:assert/strict";
import test from "node:test";
import {
  assertMinimumScopes, assertPrivacySafeResult, createConnectorContext,
  defineConnector, redactConnectorError, runConnectorCertification,
} from "../src/index.mjs";

const manifest = defineConnector({
  key: "example-directory",
  name: "Example Directory",
  category: "identity",
  authScheme: "oauth2",
  capabilities: ["authorize","discover","reconcile","health"],
  minimumScopes: ["users.read","apps.read"],
});

test("connector manifests require exact minimum scopes", () => {
  assert.equal(assertMinimumScopes(manifest,["users.read","apps.read","audit.read"]),true);
  assert.throws(() => assertMinimumScopes(manifest,["users.read"]),/apps\.read/u);
});

test("privacy boundary rejects secret and page-content shaped results", () => {
  assert.deepEqual(assertPrivacySafeResult({ records: [{ accountRefHash: "abc",activityBucket: "2026-09-01" }] }),{ records: [{ accountRefHash: "abc",activityBucket: "2026-09-01" }] });
  assert.throws(() => assertPrivacySafeResult({ accessToken: "sensitive" }),/secret-shaped/u);
  assert.throws(() => assertPrivacySafeResult({ pageContent: "sensitive" }),/disallowed discovery/u);
});

test("connector errors redact credential-shaped material", () => {
  const safe = redactConnectorError(new Error("Bearer abcdefghijklmnopqrstuvwxyz123456 leaked"));
  assert.doesNotMatch(safe.message,/abcdefghijklmnopqrstuvwxyz/u);
});

test("certification proves health, privacy, and deterministic reconciliation", async () => {
  const context = createConnectorContext({ tenantId: "tenant-a",connectorId: "connector-a",invocationId: "run-a" });
  const adapter = {
    async health() { return { status: "healthy",checkedAt: "2026-09-05T07:00:00Z" }; },
    async discover() { return { records: [{ accountRefHash: "sha256:example",activityBucket: "2026-09-01" }],nextCursor: null }; },
    async reconcile() { return { dryRun: true,proposals: [],sideEffects: 0 }; },
  };
  const result = await runConnectorCertification({ manifest,adapter,context });
  assert.equal(result.result,"passed");
  assert.equal(result.evidenceSha256.length,64);
  assert.ok(Object.values(result.checks).every(Boolean));
});


test("connector error boundary never reflects arbitrary provider content", () => {
  const expected = {
    code: "CONNECTOR_OPERATION_FAILED",
    message: "Connector operation failed. Check the connection and try again.",
  };
  for (const reason of [
    new Error("password=short-secret"),
    new Error("email=person@example.invalid"),
    new Error("api_key=11111111-2222-4333-8444-555555555555"),
    "https://provider.invalid/?token=tiny",
    { toString() { throw new Error("must not inspect arbitrary provider objects"); } },
    null,
  ]) assert.deepEqual(redactConnectorError(reason), expected);
});
