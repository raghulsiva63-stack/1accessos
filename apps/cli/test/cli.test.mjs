import assert from "node:assert/strict";
import test from "node:test";
import { commandPath, parseArguments, run } from "../src/index.mjs";

test("parses workspace and cursor without accepting positional secrets", () => {
  assert.deepEqual(parseArguments(["sync", "--workspace", "workspace-id", "--cursor", "42"]), {
    command: "sync",
    options: { workspace: "workspace-id", cursor: "42" },
  });
  assert.equal(commandPath("sync", { workspace: "workspace-id", cursor: "42" }), "/sync/changes?workspace_id=workspace-id&cursor=42");
});

test("requires the access token through the environment", async () => {
  await assert.rejects(() => run(["workspaces"], {}, async () => { throw new Error("fetch should not run"); }), /PASSKEY_X_ACCESS_TOKEN/u);
});

test("sends a bearer token and renders JSON", async () => {
  let authorization = "";
  const result = await run(["workspaces"], { PASSKEY_X_ACCESS_TOKEN: "synthetic-token", PASSKEY_X_API_URL: "https://example.test/v1/" }, async (_url, init) => {
    authorization = init.headers.authorization;
    return { ok: true, json: async () => ({ workspaces: [] }) };
  });
  assert.equal(authorization, "Bearer synthetic-token");
  assert.match(result.output, /"workspaces": \[\]/u);
});
