import assert from "node:assert/strict";
import test from "node:test";
import { PasskeyXApi } from "../src/index.mjs";

test("sends JWT authorization and ciphertext API requests", async () => {
  const seen = [];
  const api = new PasskeyXApi({
    baseUrl: "https://example.invalid/v1/",
    accessToken: "synthetic-jwt",
    fetch: async (url, options) => {
      seen.push({ url, options });
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  await api.vaultItems("00000000-0000-4000-8000-000000000001");
  assert.equal(seen[0].options.headers.authorization, "Bearer synthetic-jwt");
  assert.match(seen[0].url, /workspace_id=/);
});

test("surfaces safe structured API errors", async () => {
  const api = new PasskeyXApi({ baseUrl: "https://example.invalid/v1", accessToken: "synthetic", fetch: async () => new Response(JSON.stringify({ error: { code: "conflict", message: "Refresh and retry", request_id: "request-1" } }), { status: 409 }) });
  await assert.rejects(() => api.itemTypes(), (error) => error.code === "conflict" && error.requestId === "request-1");
});
