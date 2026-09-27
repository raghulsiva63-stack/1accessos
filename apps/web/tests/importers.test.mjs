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

const { importFromText, parseCsv, detectCsvFormat } = await vite.ssrLoadModule("/lib/vault/importers.ts");

test("CSV parser keeps quoted commas, quotes and multi-line notes", () => {
  const rows = parseCsv('a,b,c\r\n"x, y","say ""hi""","line 1\nline 2"\n');
  assert.deepEqual(rows, [["a", "b", "c"], ["x, y", 'say "hi"', "line 1\nline 2"]]);
});

test("detects common password manager exports", () => {
  assert.equal(detectCsvFormat(["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"]), "bitwarden-csv");
  assert.equal(detectCsvFormat(["url", "username", "password", "totp", "extra", "name", "grouping", "fav"]), "lastpass");
  assert.equal(detectCsvFormat(["title", "url", "username", "password", "otpauth", "favorite", "archived", "tags", "notes"]), "1password");
  assert.equal(detectCsvFormat(["name", "url", "username", "password", "note"]), "chrome");
  assert.equal(detectCsvFormat(["url", "username", "password", "httprealm", "formactionorigin"]), "firefox");
});

test("LastPass secure notes, TOTP and folders map correctly", () => {
  const csv = "url,username,password,totp,extra,name,grouping,fav\nhttps://mail.example.com,ann,pw1,JBSWY3DP,note,Mail,Work,1\nhttp://sn,,,,secret text,Wifi,Home,0\n";
  const result = importFromText(csv, "lastpass.csv");
  assert.equal(result.format, "lastpass");
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0].kind, "login");
  assert.deepEqual(result.entries[0].payload.fields, { TOTP: "JBSWY3DP" });
  assert.equal(result.entries[0].payload.favorite, true);
  assert.deepEqual(result.entries[0].payload.tags, ["Work"]);
  assert.equal(result.entries[1].kind, "secure-note");
  assert.equal(result.entries[1].payload.notes, "secret text");
});

test("Bitwarden JSON imports logins, notes and cards and rejects encrypted exports", () => {
  const json = JSON.stringify({ encrypted: false, folders: [{ id: "f1", name: "Finance" }], items: [
    { type: 1, name: "Bank", folderId: "f1", login: { username: "u", password: "p", uris: [{ uri: "https://bank.example" }] } },
    { type: 2, name: "Note", notes: "hello" },
    { type: 3, name: "Visa", card: { cardholderName: "Ann", number: "4111111111111111", expMonth: "1", expYear: "2030", code: "123" } },
  ] });
  const result = importFromText(json, "bitwarden.json");
  assert.deepEqual(result.entries.map((entry) => entry.kind), ["login", "secure-note", "payment-card"]);
  assert.deepEqual(result.entries[0].payload.tags, ["Finance"]);
  assert.equal(result.entries[2].payload.fields.Expiry, "1/2030");
  assert.throws(() => importFromText(JSON.stringify({ encrypted: true, data: "x" }), "enc.json"), /encrypted Bitwarden export/u);
});

test("rejects files without usable columns", () => {
  assert.throws(() => importFromText("foo,bar\n1,2\n", "x.csv"), /username or password column/u);
});
