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
  const result = await runConnectorCertification({ manifest,adapter,context,grantedScopes: ["users.read","apps.read"] });
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

function certificationFixture() {
  return {
    manifest,
    grantedScopes: ['users.read','apps.read'],
    context: createConnectorContext({tenantId:'tenant-a',connectorId:'connector-a',invocationId:'run-a'}),
    adapter: {
      async health() { return {status:'healthy'}; },
      async discover() { return {records:[{accountRefHash:'sha256:fixture'}],nextCursor:null}; },
      async reconcile() { return {dryRun:true,proposals:[],sideEffects:0}; },
    },
  };
}

test('certification rejects missing grants before contacting the adapter', async () => {
  for (const grantedScopes of [undefined,[],['users.read']]) {
    const fixture = certificationFixture();
    fixture.adapter.health = async () => { assert.fail('adapter must not run without verified scopes'); };
    await assert.rejects(runConnectorCertification({...fixture,grantedScopes}), /grantedScopes|scopes/u);
  }
});

test('degraded health cannot pass the contract check', async () => {
  const fixture = certificationFixture();
  fixture.adapter.health = async () => ({status:'degraded'});
  await assert.rejects(runConnectorCertification(fixture), /health/u);
});

test('reconciliation must explicitly report dry-run and no side effects', async () => {
  for (const result of [{proposals:[]},{dryRun:false,sideEffects:0,proposals:[]},{dryRun:true,sideEffects:1,proposals:[]}]) {
    const fixture = certificationFixture();
    fixture.adapter.reconcile = async () => result;
    await assert.rejects(runConnectorCertification(fixture), /zero side effects/u);
  }
});

test('contract evidence binds the tenant, grants, manifest and observed data', async () => {
  const baseline = await runConnectorCertification(certificationFixture());
  assert.equal(baseline.validationLevel,'adapter_contract');
  assert.equal(baseline.certifiedForProduction,false);
  for (const change of ['tenant','grants','manifest','observation']) {
    const fixture = certificationFixture();
    if (change === 'tenant') fixture.context = {...fixture.context,tenantId:'tenant-b'};
    if (change === 'grants') fixture.grantedScopes.push('audit.read');
    if (change === 'manifest') fixture.manifest = {...manifest,name:'Different adapter version'};
    if (change === 'observation') fixture.adapter.discover = async () => ({records:[],nextCursor:null});
    const result = await runConnectorCertification(fixture);
    assert.notEqual(result.evidenceSha256,baseline.evidenceSha256,change);
  }
  const reordered = certificationFixture();
  reordered.grantedScopes.reverse();
  assert.equal((await runConnectorCertification(reordered)).evidenceSha256,baseline.evidenceSha256);
});

test('JSON object ordering does not masquerade as reconciliation changes', async () => {
  const fixture = certificationFixture(); let calls = 0;
  fixture.adapter.reconcile = async () => ++calls === 1
    ? {dryRun:true,proposals:[],sideEffects:0}
    : {sideEffects:0,proposals:[],dryRun:true};
  assert.equal((await runConnectorCertification(fixture)).result,'passed');
});

test('privacy validation rejects non-JSON data without executing getters', () => {
  let accessed = false;
  const getter = Object.defineProperty({},'value',{enumerable:true,get(){accessed=true;return 'sensitive';}});
  const cycle = {}; cycle.self = cycle;
  const arrayWithMetadata = []; arrayWithMetadata.label = "omitted by JSON";
  for (const result of [getter,cycle,Array(5),arrayWithMetadata,new Map([['secret','value']]),new Date(),{value:undefined},{value:NaN},{value:1n},{[Symbol('hidden')]:'value'}]) {
    assert.throws(() => assertPrivacySafeResult(result));
  }
  assert.equal(accessed,false);
  let deep = {}; for(let i=0;i<34;i++) deep={child:deep};
  assert.throws(() => assertPrivacySafeResult(deep),/structural limits/u);
});


test('reused mutable adapter results cannot hide a changed dry run', async () => {
  const fixture = certificationFixture();
  const shared = {dryRun:true,proposals:[],sideEffects:0};
  let calls = 0;
  fixture.adapter.reconcile = async () => {
    if (++calls === 2) shared.proposals.push({action:'review'});
    return shared;
  };
  await assert.rejects(runConnectorCertification(fixture), /not deterministic/u);
});
