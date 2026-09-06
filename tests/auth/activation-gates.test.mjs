import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import vm from "node:vm";

for (const [name, flag, error] of [["sent-sms-hook", "SENT_DM_SMS_ENABLED", "sms_disabled"], ["billing", "BILLING_ENABLED", "billing_disabled"]]) {
  test(`${name} blocks provider and database work unless explicitly activated on the server`, async () => {
    const source = (await readFile(new URL(`../../supabase/functions/${name}/index.ts`, import.meta.url), "utf8")).replace(/^import[\s\S]*?;\n/gm, "");
    for (const value of [undefined, "false", "TRUE", "1", " true "]) {
      let handler;
      const forbidden = () => assert.fail("Disabled endpoint attempted a side effect");
      const context = vm.createContext({
        Request, Response, Headers,
        Deno: { env: { get: key => key === flag ? value : undefined }, serve: callback => { handler = callback; } },
        json: (...args) => { const offset = typeof args[0] === "number" ? 0 : 1; return Response.json(args[offset + 1], { status: args[offset] }); },
        corsHeaders: () => ({}), fetch: forbidden, adminSupabase: forbidden, stripeClient: forbidden, required: forbidden,
      });
      vm.runInContext(stripTypeScriptTypes(source), context);
      const response = await handler(new Request("https://example.invalid/", { method: "POST", body: "malformed body" }));
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { error });
    }
  });
}
