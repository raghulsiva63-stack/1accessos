import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { readAppShell } from "../../scripts/lib/app-source.mjs";

const page = await readAppShell();

test("onboarding uses the delayed browser download helper and gates vault creation", () => {
  assert.match(page, /downloadBlob\(recoveryFile\(recoveryKey\)/);
  assert.match(page, /setPendingSetup\(/);
  assert.match(page, /async function finishSetup\(\)/);
  assert.match(page, /disabled=\{!pendingSetup \|\| !downloaded \|\| !savedConfirmed \|\| busy\}/);
  assert.match(page, /onClick=\{\(\) => void finishSetup\(\)\}/);
});

test("bootstrap is deferred until after recovery download confirmation", () => {
  const preparation = page.slice(page.indexOf("async function setup"), page.indexOf("function download()"));
  const completion = page.slice(page.indexOf("async function finishSetup"), page.indexOf("function UnlockScreen"));
  assert.doesNotMatch(preparation, /rpc\("bootstrap_personal_vault"/);
  assert.match(completion, /rpc\("bootstrap_personal_vault"/);
  assert.match(page, /No vault record is created until the file download is started and you explicitly confirm it is stored/);
  assert.match(page, /authSessionTransition\(activeUserId\.current/);
  assert.match(page, /action="vault-setup"/);
});
