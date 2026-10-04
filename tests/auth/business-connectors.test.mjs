import assert from "node:assert/strict";
import { register } from "node:module";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const formats = await import("../../supabase/functions/_shared/connector-formats.ts");
const sharing = await import("../../apps/web/lib/enterprise/key-sharing.ts");
const connectors = await import("../../apps/web/lib/enterprise/connectors.ts");
const migration = await import("../../apps/web/lib/enterprise/team-migration.ts");

const payload = {
  source: "passkey-x", type: "audit_events", tenant_id: "11111111-1111-4111-8111-111111111111",
  events: [
    { sequence: 7, occurred_at: "2026-10-05T10:00:00.000Z", action: "vault.exported", target_type: "vault", target_id: null, actor_identity_id: "a", metadata: { n: 1 }, event_hash: "ab" },
    { sequence: 8, occurred_at: "2026-10-05T10:00:01.000Z", action: "policy.changed", metadata: {} },
  ],
};

test("SIEM shapes carry metadata only and authenticate per vendor", () => {
  const splunk = formats.shapeSiem("splunk_hec", { index: "security", sourcetype: "px" }, "hec-token", payload);
  assert.equal(splunk.headers.Authorization, "Splunk hec-token");
  const lines = splunk.body.split("\n").map((line) => JSON.parse(line));
  assert.equal(lines.length, 2);
  assert.deepEqual([lines[0].index, lines[0].sourcetype, lines[0].event.action, lines[0].time], ["security", "px", "vault.exported", 1791194400]);

  const datadog = formats.shapeSiem("datadog", { service: "px", tags: "env:prod" }, "dd-key", payload);
  assert.equal(datadog.headers["DD-API-KEY"], "dd-key");
  const logs = JSON.parse(datadog.body);
  assert.equal(logs[0].ddtags, "source:passkey-x,tenant:11111111-1111-4111-8111-111111111111,env:prod");
  assert.equal(logs[1].message, "policy.changed");

  const sentinel = formats.shapeSiem("sentinel", {}, "bearer", payload);
  assert.equal(sentinel.headers.Authorization, "Bearer bearer");
  assert.deepEqual(Object.keys(JSON.parse(sentinel.body)[0]).sort(),
    ["Action", "ActorIdentityId", "EventHash", "Metadata", "Sequence", "Source", "TargetId", "TargetType", "TenantId", "TimeGenerated"]);

  const elastic = formats.shapeSiem("elastic", { index: "px-audit" }, "base64key", payload);
  assert.equal(elastic.headers["Content-Type"], "application/x-ndjson");
  const ndjson = elastic.body.trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(ndjson[0], { create: { _index: "px-audit" } });
  assert.equal(ndjson[1]["@timestamp"], "2026-10-05T10:00:00.000Z");
  assert.ok(elastic.body.endsWith("\n"));
  assert.equal(formats.elasticBulkFailed('{"errors":true}'), true);
  assert.equal(formats.elasticBulkFailed('{"errors":false,"items":[]}'), false);
  assert.throws(() => formats.shapeSiem("ftp", {}, "x", payload));
});

test("vendor destinations only reach their own hosts", () => {
  assert.equal(formats.hostAllowedForFormat("slack", new URL("https://hooks.slack.com/services/x")), true);
  assert.equal(formats.hostAllowedForFormat("slack", new URL("https://hooks.slack.com.evil.io/services/x")), false);
  assert.equal(formats.hostAllowedForFormat("teams", new URL("https://prod-1.westeurope.logic.azure.com/workflows/x")), true);
  assert.equal(formats.hostAllowedForFormat("teams", new URL("https://logic.azure.com.evil.io/x")), false);
  assert.equal(formats.hostAllowedForFormat("datadog", new URL("https://http-intake.logs.datadoghq.eu/api/v2/logs")), true);
  assert.equal(formats.hostAllowedForFormat("datadog", new URL("https://evil.example/api/v2/logs")), false);
  assert.equal(formats.hostAllowedForFormat("sentinel", new URL("https://a.westeurope-1.ingest.monitor.azure.com/x")), true);
  const token = formats.sentinelTokenRequest({ tenant_id: "11111111-2222-3333-4444-555555555555", client_id: "11111111-2222-3333-4444-666666666666", endpoint: "https://a.ingest.monitor.azure.com" }, "s3cret");
  assert.equal(token.url, "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token");
  assert.match(token.body, /scope=https%3A%2F%2Fmonitor\.azure\.com%2F%2F\.default/);
  assert.throws(() => formats.sentinelTokenRequest({ tenant_id: "x", client_id: "y" }, "s"));
});

test("chat messages are escaped, link back to the right admin tab and never include secrets", () => {
  const slack = JSON.parse(formats.shapeChat("slack", {
    event: "alerts", severity: "critical", title: "<!channel> Vault exported by <@U1>", app_url: "https://passkey-x.com",
  }).body);
  assert.equal(slack.blocks[0].text.text, "Critical: <!channel> Vault exported by <@U1>"); // plain_text header is not parsed
  assert.doesNotMatch(slack.text, /<!channel>/);
  assert.match(slack.text, /&lt;!channel&gt;/);
  assert.equal(slack.blocks[2].elements[0].url, "https://passkey-x.com/?view=admin&tab=alerts");

  const teams = JSON.parse(formats.shapeChat("teams", {
    event: "weekly_report", score: 70, score_week_ago: 76, two_step_pct: 80, passkey_pct: 20, alerts_new_7d: 1,
    top_risks: [{ key: "breached_passwords", count: 2 }, { key: "<script>", count: 9 }], app_url: "javascript:alert(1)",
  }).body);
  const card = teams.attachments[0].content;
  assert.equal(teams.attachments[0].contentType, "application/vnd.microsoft.card.adaptive");
  assert.match(card.body[1].text, /Security score 70\/100 \(-6 since last week\)/);
  assert.equal(card.body.length, 5);
  assert.equal(card.actions[0].url, "https://passkey-x.com/?view=admin&tab=reports");
  assert.equal(card.body[0].color, "Warning");
  assert.doesNotMatch(JSON.stringify(teams), /script/);

  const breach = formats.chatMessage({ event: "breach_watch", severity: "high", title: "x" });
  assert.match(breach.link, /tab=breach$/);
  assert.match(formats.chatMessage({ event: "test", channel: "#sec" }).heading, /connected/);
});

test("member sharing keys: sealed workspace keys open only for the intended grant", async () => {
  const pair = await sharing.generateSharingKeyPair();
  assert.match(pair.fingerprint, /^[0-9a-f]{4}(:[0-9a-f]{4}){5}$/);
  assert.equal(pair.publicKey.length, 65);
  const workspaceKey = crypto.getRandomValues(new Uint8Array(32));
  const context = sharing.grantContext("t", "w", "r", 1);
  const box = await sharing.sealToPublicKey(workspaceKey, pair.publicKey, context);
  assert.equal(box.ephemeralPublicKey.length, 65);
  assert.equal(box.ciphertext.length, 48);
  assert.deepEqual(await sharing.openSealedKey(pair.privateKeyPkcs8, box, context), workspaceKey);
  await assert.rejects(sharing.openSealedKey(pair.privateKeyPkcs8, box, sharing.grantContext("t", "w", "someone-else", 1)));
  await assert.rejects(sharing.openSealedKey(pair.privateKeyPkcs8, box, sharing.grantContext("t", "w", "r", 2)));
  const other = await sharing.generateSharingKeyPair();
  await assert.rejects(sharing.openSealedKey(other.privateKeyPkcs8, box, context));
  await assert.rejects(sharing.sealToPublicKey(new Uint8Array(16), pair.publicKey, context));
  await assert.rejects(sharing.sealToPublicKey(workspaceKey, new Uint8Array(65), context));
});

test("sharing key bootstrap, incoming grants and pending deliveries", async () => {
  const rootKey = crypto.getRandomValues(new Uint8Array(32));
  const calls = [];
  const tables = { identity_sharing_keys: null, identity_sharing_key_secrets: null, workspace_key_grants: [] };
  const query = (table) => {
    const chain = {
      select: () => chain, eq: () => chain, limit: () => chain, in: () => chain,
      maybeSingle: async () => ({ data: tables[table], error: null }),
      then: (resolve) => resolve({ data: tables[table], error: null }),
    };
    return chain;
  };
  globalThis.__pxSupabase = {
    from: query,
    rpc: async (name, args) => {
      calls.push([name, args]);
      if (name === "publish_sharing_key") {
        tables.identity_sharing_keys = { public_key: args.p_public_key, fingerprint: args.p_fingerprint };
        tables.identity_sharing_key_secrets = { nonce: args.p_nonce, wrapped_private_key: args.p_wrapped_private_key };
      }
      if (name === "grants_to_seal") return { data: tables.pending ?? [], error: null };
      return { data: null, error: null };
    },
  };
  const first = await sharing.ensureSharingKey("me", rootKey);
  assert.equal(calls[0][0], "publish_sharing_key");
  assert.equal(calls[0][1].p_replace, false);
  assert.doesNotMatch(JSON.stringify(calls[0][1]), new RegExp(Buffer.from(first.privateKeyPkcs8).toString("hex").slice(0, 40)));
  const again = await sharing.ensureSharingKey("me", rootKey);
  assert.equal(calls.length, 1, "existing key is reused");
  assert.equal(again.fingerprint, first.fingerprint);

  // An administrator seals a key to "me"; my device accepts it.
  const workspaceKey = crypto.getRandomValues(new Uint8Array(32));
  const box = await sharing.sealToPublicKey(workspaceKey, first.publicKey, sharing.grantContext("t", "w", "me", 3));
  const hex = (bytes) => `\\x${Buffer.from(bytes).toString("hex")}`;
  tables.workspace_key_grants = [{ id: "g1", tenant_id: "t", workspace_id: "w", key_version: 3,
    ephemeral_public_key: hex(box.ephemeralPublicKey), nonce: hex(box.nonce), ciphertext: hex(box.ciphertext) }];
  assert.deepEqual(await sharing.acceptIncomingGrants("me", rootKey, again), ["w"]);
  assert.equal(calls.at(-1)[0], "accept_workspace_key_grant");

  // Pending deliveries: sealed when this device holds the workspace key, skipped otherwise.
  const recipient = await sharing.generateSharingKeyPair();
  tables.pending = [
    { grant_id: "p1", workspace_id: "w1", recipient_identity_id: "r1", key_version: 1, public_key: hex(recipient.publicKey), fingerprint: recipient.fingerprint },
    { grant_id: "p2", workspace_id: "w-unknown", recipient_identity_id: "r2", key_version: 1, public_key: hex(recipient.publicKey), fingerprint: recipient.fingerprint },
    { grant_id: "p3", workspace_id: "w1", recipient_identity_id: "r3", key_version: 1, public_key: null, fingerprint: null },
    { grant_id: "p4", workspace_id: "w1", recipient_identity_id: "r4", key_version: 1, public_key: hex(recipient.publicKey), fingerprint: "0000:0000:0000:0000:0000:0000" },
  ];
  const store = new Map();
  globalThis.localStorage = { getItem: (key) => store.get(key) ?? null, setItem: (key, value) => store.set(key, String(value)) };
  const vault = { identityId: "admin", tenantId: "t", workspaceId: "w1", keyVersion: 1, key: crypto.getRandomValues(new Uint8Array(32)) };
  // Background runs only deliver access the administrator asked for themselves.
  const automatic = await sharing.sealPendingGrants("t", [vault], { sealerIdentityId: "admin", approvedOnly: true });
  assert.deepEqual([automatic.sealed, automatic.needsApproval], [0, 4]);
  const outcome = await sharing.sealPendingGrants("t", [vault], { sealerIdentityId: "admin" });
  assert.deepEqual([outcome.sealed, outcome.waiting, outcome.keyChanged.length], [1, 3, 0]);
  assert.equal(sharing.pinnedFingerprint("admin", "r1"), recipient.fingerprint);
  const sealCall = calls.find(([name]) => name === "seal_workspace_key_grant");
  assert.equal(sealCall[1].p_grant_id, "p1");
  const opened = await sharing.openSealedKey(recipient.privateKeyPkcs8, {
    ephemeralPublicKey: Buffer.from(sealCall[1].p_ephemeral_public_key.slice(2), "hex"),
    nonce: Buffer.from(sealCall[1].p_nonce.slice(2), "hex"), ciphertext: Buffer.from(sealCall[1].p_ciphertext.slice(2), "hex"),
  }, sharing.grantContext("t", "w1", "r1", 1));
  assert.deepEqual(opened, vault.key);
  // A different key for the same person is not used until an administrator trusts it.
  const replaced = await sharing.generateSharingKeyPair();
  tables.pending = [{ grant_id: "p5", workspace_id: "w1", recipient_identity_id: "r1", key_version: 1, public_key: hex(replaced.publicKey), fingerprint: replaced.fingerprint, requested_by: "admin" }];
  const changed = await sharing.sealPendingGrants("t", [vault], { sealerIdentityId: "admin", approvedOnly: true });
  assert.deepEqual([changed.sealed, changed.keyChanged.map((entry) => entry.identityId)], [0, ["r1"]]);
  await assert.rejects(sharing.grantWorkspaceAccess(vault, { identity_id: "r1", public_key: hex(replaced.publicKey), fingerprint: replaced.fingerprint }, "viewer"), /changed/);
  sharing.trustRecipientKey("admin", "r1", replaced.fingerprint);
  assert.equal((await sharing.sealPendingGrants("t", [vault], { sealerIdentityId: "admin", approvedOnly: true })).sealed, 1);
  delete globalThis.__pxSupabase;
  delete globalThis.localStorage;
});

test("chat webhook URLs and connector errors", () => {
  assert.equal(connectors.validChatUrl("slack", "https://hooks.slack.com/services/T000/B000/abcdefghij"), true);
  assert.equal(connectors.validChatUrl("slack", "https://hooks.slack.com.evil.io/services/T000/B000/abcdefghij"), false);
  assert.equal(connectors.validChatUrl("teams", "https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x"), true);
  assert.equal(connectors.validChatUrl("teams", "https://hooks.slack.com/services/T000/B000/abcdefghij"), false);
  for (const field of Object.values(connectors.DESTINATIONS).flatMap((destination) => destination.fields)) {
    if (field.pattern) assert.doesNotThrow(() => new RegExp(`^(?:${field.pattern})$`, "v"), field.key);
  }
  assert.equal(connectors.connectorErrorMessage({ code: "42501", message: "x" }), "Your organization role does not allow this.");
  assert.equal(connectors.apiKeyState({ revoked_at: null, expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString() }), "expiring");
  assert.equal(connectors.apiKeyState({ revoked_at: "2026-01-01", expires_at: "2099-01-01" }), "revoked");
});

test("team migration plan: shared folders become workspaces, private ones are skipped", () => {
  const entry = (collection, shared) => ({ kind: "login", collection, shared, payload: { title: "x" } });
  const plan = migration.defaultPlan([entry("Engineering", true), entry("Engineering", true), entry("Private", false), entry(undefined, false)]);
  assert.deepEqual(plan.map((step) => [step.collection, step.target]), [["", "skip"], ["Engineering", "new"], ["Private", "skip"]]);
  const keepass = migration.defaultPlan([entry("Servers / Linux", undefined), entry(undefined, undefined)]);
  assert.deepEqual(keepass.map((step) => [step.collection, step.target, step.name]), [["", "skip", "Imported items"], ["Servers / Linux", "new", "Linux"]]);
});

test("database: connectors keep secrets write-only and sync group access", async () => {
  const sql = await readFile(new URL("../../supabase/migrations/20261005090000_business_connectors.sql", import.meta.url), "utf8");
  assert.match(sql, /revoke all on private\.chat_channel_secrets from public, anon, authenticated/);
  assert.match(sql, /revoke all on private\.audit_webhook_credentials from public, anon, authenticated/);
  assert.match(sql, /revoke all on private\.org_api_key_hashes from public, anon, authenticated/);
  assert.match(sql, /token_hash\) values \(v_id, extensions\.digest\(v_token, 'sha256'\)\)/);
  assert.doesNotMatch(sql, /grant select[^;]*chat_channel_secrets/i);
  const config = await readFile(new URL("../../supabase/config.toml", import.meta.url), "utf8");
  assert.match(config, /\[functions\.org-api\]\nverify_jwt = false/);
  const relay = await readFile(new URL("../../supabase/functions/audit-relay/index.ts", import.meta.url), "utf8");
  assert.match(relay, /hostAllowedForFormat/);
  assert.doesNotMatch(relay, /console\.(log|error)\([^)]*credential/);
});
