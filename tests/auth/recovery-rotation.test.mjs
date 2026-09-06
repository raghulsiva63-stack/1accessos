import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const page = await readFile("apps/web/app/page.tsx", "utf8");

test("onboarding uses the delayed browser download helper and gates vault creation", () => {
  assert.match(page, /downloadBlob\(recoveryFile\(recoveryKey\)/);
  assert.match(page, /setPendingSetup\(/);
  assert.match(page, /async function finishSetup\(\)/);
  assert.match(page, /disabled=\{!pendingSetup \|\| !downloaded \|\| busy\}/);
  assert.match(page, /onClick=\{\(\) => void finishSetup\(\)\}/);
});

test("bootstrap is deferred until after recovery download confirmation", () => {
  const preparation = page.slice(page.indexOf("async function setup"), page.indexOf("function download()"));
  const completion = page.slice(page.indexOf("async function finishSetup"), page.indexOf("function UnlockScreen"));
  assert.doesNotMatch(preparation, /rpc\("bootstrap_personal_vault"/);
  assert.match(completion, /rpc\("bootstrap_personal_vault"/);
  assert.match(page, /No vault record is created until the recovery file has downloaded/);
});
