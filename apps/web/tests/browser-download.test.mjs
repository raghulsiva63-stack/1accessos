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
const { downloadBlob } = await vite.ssrLoadModule("/lib/browser/download.ts");

test("download remains connected and keeps its object URL alive after click", () => {
  const events = [];
  let scheduled;
  const anchor = {
    href: "",
    download: "",
    rel: "",
    style: { display: "" },
    click() { events.push("click"); },
    remove() { events.push("remove"); },
  };
  const documentObject = {
    body: { append(value) { assert.equal(value, anchor); events.push("append"); } },
    createElement(name) { assert.equal(name, "a"); return anchor; },
  };
  const urlObject = {
    createObjectURL(value) { assert.ok(value instanceof Blob); events.push("create"); return "blob:test"; },
    revokeObjectURL(value) { assert.equal(value, "blob:test"); events.push("revoke"); },
  };

  downloadBlob(new Blob(["recovery"]), "passkey-x-recovery-key.json", {
    documentObject,
    urlObject,
    schedule(callback, delay) { scheduled = callback; assert.equal(delay, 60_000); events.push("schedule"); },
  });

  assert.deepEqual(events, ["create", "append", "click", "remove", "schedule"]);
  assert.equal(anchor.href, "blob:test");
  assert.equal(anchor.download, "passkey-x-recovery-key.json");
  assert.equal(anchor.rel, "noopener");
  scheduled();
  assert.deepEqual(events, ["create", "append", "click", "remove", "schedule", "revoke"]);
});

test("download revokes immediately when the browser rejects the click", () => {
  const events = [];
  const anchor = {
    href: "", download: "", rel: "", style: { display: "" },
    click() { throw new Error("blocked"); },
    remove() { events.push("remove"); },
  };
  assert.throws(() => downloadBlob(new Blob(["x"]), "safe.json", {
    documentObject: { body: { append() {} }, createElement() { return anchor; } },
    urlObject: {
      createObjectURL() { return "blob:blocked"; },
      revokeObjectURL(value) { events.push(`revoke:${value}`); },
    },
    schedule() { throw new Error("must not schedule"); },
  }), /blocked/);
  assert.deepEqual(events, ["revoke:blob:blocked", "remove"]);
});

test("unsafe filenames are rejected before an object URL is created", () => {
  assert.throws(() => downloadBlob(new Blob(["x"]), "../secret.json", {
    documentObject: {},
    urlObject: { createObjectURL() { throw new Error("must not run"); } },
  }), /safe download filename/);
});
