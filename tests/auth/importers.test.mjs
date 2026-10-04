import assert from "node:assert/strict";
import { register } from "node:module";
import { deflateRawSync } from "node:zlib";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const importers = await import("../../apps/web/lib/vault/importers.ts");
const zip = await import("../../apps/web/lib/vault/zip.ts");
const { importFromText, importFromFile, findDuplicates, detectCsvFormat, normalizeCollection, parseXml, FORMAT_LABELS, MAX_IMPORT_ITEMS } = importers;

const SECRET = "Tr0ub4dor&3-SuperSecret";

// ---------------------------------------------------------------- ZIP builder for .1pux fixtures
function crc32(bytes) { return zip.crc32(bytes); }
function buildZip(files, { encryptFlag = false } = {}) {
  const locals = []; const centrals = []; let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name, "utf8");
    const raw = Buffer.from(file.data);
    const method = file.method ?? 0;
    const body = method === 8 ? deflateRawSync(raw) : raw;
    const flags = encryptFlag ? 1 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(flags, 6); local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc32(raw), 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(raw.length, 22); local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(flags, 8); central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc32(raw), 16); central.writeUInt32LE(body.length, 20); central.writeUInt32LE(raw.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, name, body); centrals.push(central, name);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...locals, cd, eocd]));
}
const named = (bytes, name) => Object.assign(new Blob([bytes]), { name });

const exportData = JSON.stringify({ accounts: [{ attrs: { accountName: "Ann" }, vaults: [
  { attrs: { name: "Private" }, items: [
    { state: "active", categoryUuid: "001", favIndex: 1, overview: { title: "GitHub", url: "https://github.com/login", tags: ["dev"] }, details: {
      loginFields: [{ designation: "username", value: "ann" }, { designation: "password", value: SECRET }],
      notesPlain: "work account", sections: [{ title: "", fields: [{ title: "one-time password", id: "TOTP_1", value: { totp: "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP" } }] }] } },
    { state: "archived", categoryUuid: "001", overview: { title: "Old" }, details: { loginFields: [{ designation: "password", value: "old" }] } },
    { state: "active", categoryUuid: "003", overview: { title: "Door code" }, details: { notesPlain: "1234#" } },
  ] },
  { attrs: { name: "Marketing Team" }, items: [
    { state: "active", categoryUuid: "002", overview: { title: "Company Visa" }, details: { sections: [{ fields: [
      { id: "cardholder", title: "cardholder name", value: { string: "Acme Inc" } },
      { id: "ccnum", title: "number", value: { creditCardNumber: "4111111111111111" } },
      { id: "cvv", title: "verification number", value: { concealed: "999" } },
      { id: "expiry", title: "expiry date", value: { monthYear: 202812 } }] }] } },
    { state: "active", categoryUuid: "004", overview: { title: "Me" }, details: { sections: [{ fields: [
      { id: "firstname", title: "first name", value: { string: "Ann" } }, { id: "lastname", title: "last name", value: { string: "Lee" } },
      { id: "email", title: "email", value: { email: { email_address: "ann@example.com", provider: null } } }] }] } },
  ] },
] }] });

// ---------------------------------------------------------------- Backward compatibility

test("existing CSV and Bitwarden JSON behaviour is unchanged, with collections added", () => {
  const csv = "url,username,password,totp,extra,name,grouping,fav\nhttps://mail.example.com,ann,pw1,JBSWY3DP,note,Mail,Work,1\nhttp://sn,,,,secret text,Wifi,Home,0\n";
  const result = importFromText(csv, "lastpass.csv");
  assert.equal(result.format, "lastpass");
  assert.equal(result.entries[0].kind, "login");
  assert.deepEqual(result.entries[0].payload.fields, { TOTP: "JBSWY3DP" });
  assert.deepEqual(result.entries[0].payload.tags, ["Work"]);
  assert.equal(result.entries[1].kind, "secure-note");
  assert.deepEqual(result.collections, [{ name: "Home", count: 1, shared: false }, { name: "Work", count: 1, shared: false }]);
  assert.deepEqual(result.warnings, []);

  const json = JSON.stringify({ encrypted: false, folders: [{ id: "f1", name: "Finance" }], items: [
    { type: 1, name: "Bank", folderId: "f1", login: { username: "u", password: "p", uris: [{ uri: "https://bank.example" }] } },
    { type: 2, name: "Note", notes: "hello" },
    { type: 3, name: "Visa", card: { cardholderName: "Ann", number: "4111111111111111", expMonth: "1", expYear: "2030", code: "123" } },
  ] });
  const bw = importFromText(json, "bitwarden.json");
  assert.deepEqual(bw.entries.map((entry) => entry.kind), ["login", "secure-note", "payment-card"]);
  assert.deepEqual(bw.entries[0].payload.tags, ["Finance"]);
  assert.equal(bw.entries[0].collection, "Finance");
  assert.equal(bw.entries[0].shared, undefined);
  assert.equal(bw.entries[2].payload.fields.Expiry, "1/2030");
  assert.throws(() => importFromText(JSON.stringify({ encrypted: true, data: "x" }), "enc.json"), /encrypted Bitwarden export/u);
  assert.throws(() => importFromText("foo,bar\n1,2\n", "x.csv"), /username or password column/u);

  assert.equal(detectCsvFormat(["title", "url", "username", "password", "otpauth", "favorite", "archived", "tags", "notes"]), "1password");
  assert.equal(detectCsvFormat(["name", "url", "username", "password", "note"]), "chrome");
  assert.equal(detectCsvFormat(["url", "username", "password", "httprealm", "formactionorigin"]), "firefox");
  const chrome = importFromText("name,url,username,password,note\nShop,https://shop.example,ann,pw,\n", "Chrome Passwords.csv");
  assert.equal(chrome.format, "chrome");
  assert.deepEqual(chrome.collections, []);
  const dash = importFromText("username,title,password,note,url,category,otpSecret\nann,Bank,pw,,https://bank.example,Finance/Retail,\n", "credentials.csv");
  assert.equal(dash.format, "dashlane");
  assert.equal(dash.entries[0].collection, "Finance / Retail");
  for (const format of ["keeper-csv", "keeper-json", "keepass-xml", "keepassxc-csv", "apple-csv", "1password-1pux"]) assert.ok(FORMAT_LABELS[format]);
});

// ---------------------------------------------------------------- Collections and sharing

test("LastPass Shared- folders and Bitwarden organization collections are marked shared", () => {
  const csv = `url,username,password,totp,extra,name,grouping,fav\nhttps://x.example,ann,${SECRET},,,X,Shared-Marketing\\Social,0\nhttps://y.example,bob,pw,,,Y,Personal,0\n`;
  const lp = importFromText(csv, "lastpass.csv");
  assert.equal(lp.entries[0].collection, "Shared-Marketing / Social");
  assert.equal(lp.entries[0].shared, true);
  assert.deepEqual(lp.entries[0].payload.tags, ["Shared-Marketing", "Social"]);
  assert.equal(lp.entries[1].shared, undefined);
  assert.deepEqual(lp.collections.map((c) => [c.name, c.shared]), [["Personal", false], ["Shared-Marketing / Social", true]]);

  const org = JSON.stringify({ encrypted: false, collections: [{ id: "c1", name: "Engineering/Backend" }, { id: "c2", name: "Ops" }], items: [
    { type: 1, name: "DB", collectionIds: ["c1"], organizationId: "o1", login: { username: "root", password: "pw", uris: [{ uri: "https://db.example" }] } },
    { type: 1, name: "Pager", collectionIds: ["c2", "c1"], organizationId: "o1", login: { username: "ops", password: "pw2" } },
    { type: 2, name: "Runbook", collectionIds: ["c2"], notes: "steps" },
  ] });
  const bw = importFromText(org, "bitwarden_org.json");
  assert.equal(bw.entries[0].collection, "Engineering / Backend");
  assert.equal(bw.entries[0].shared, true);
  assert.deepEqual(bw.entries[0].payload.tags, ["Engineering/Backend"]);
  assert.deepEqual(bw.collections, [{ name: "Engineering / Backend", count: 1, shared: true }, { name: "Ops", count: 2, shared: true }]);

  const bwCsv = importFromText("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nFinance,login,Bank,,,0,https://bank.example,ann,pw,\n", "org.csv");
  assert.equal(bwCsv.format, "bitwarden-csv");
  assert.equal(bwCsv.entries[0].collection, "Finance");
  assert.equal(bwCsv.entries[0].shared, true);
});

test("normalizeCollection trims, joins with ' / ' and caps at 120 characters", () => {
  assert.equal(normalizeCollection(" A \\ B//C "), "A / B / C");
  assert.equal(normalizeCollection(["x/y", "z"]), "x/y / z");
  assert.equal(normalizeCollection(""), undefined);
  assert.ok(normalizeCollection("a".repeat(300)).length <= 120);
});

// ---------------------------------------------------------------- Keeper

test("Keeper CSV (no header) needs the hint and maps shared folders and TOTP", () => {
  const csv = [
    `Work\\Infra,AWS,admin,${SECRET},https://aws.amazon.com,root acct,,TFC:Keeper,otpauth://totp/AWS?secret=ABC,Account ID,1234`,
    `,Team wiki,wiki,pw,https://wiki.example,,Engineering\\Docs`,
    `Personal,Alarm code,,,,4321,`,
  ].join("\n");
  const result = importFromText(csv, "keeper.csv", "keeper-csv");
  assert.equal(result.format, "keeper-csv");
  assert.equal(result.entries.length, 3);
  const [aws, wiki, note] = result.entries;
  assert.equal(aws.collection, "Work / Infra");
  assert.equal(aws.shared, undefined);
  assert.deepEqual(aws.payload.fields, { TOTP: "otpauth://totp/AWS?secret=ABC", "Account ID": "1234" });
  assert.equal(aws.payload.secret, SECRET);
  assert.equal(wiki.collection, "Engineering / Docs");
  assert.equal(wiki.shared, true);
  assert.equal(note.kind, "secure-note");
  assert.deepEqual(result.collections.map((c) => c.name), ["Engineering / Docs", "Personal", "Work / Infra"]);
  // Without the hint the header-less file cannot be identified, and the message says what to do.
  assert.throws(() => importFromText(csv, "keeper.csv"), (error) => /Keeper/u.test(error.message) && !error.message.includes(SECRET));
});

test("Keeper JSON maps folders, shared folders, custom fields and record types", () => {
  const json = JSON.stringify({
    shared_folders: [{ path: "Finance Team", manage_users: false }],
    records: [
      { title: "Bank", login: "ann", password: SECRET, login_url: "https://bank.example", notes: "n", $type: "login",
        custom_fields: { "$oneTimeCode": "otpauth://totp/Bank?secret=XYZ", "$text:Branch": "Main st", "PIN hint": "birthday" },
        folders: [{ shared_folder: "Finance Team", folder: "Cards", can_edit: true, can_share: false }] },
      { title: "Router", login: "admin", password: "pw", $type: "login", folders: [{ folder: "Home\\Network" }] },
      { title: "Secret plan", notes: "world domination", $type: "encryptedNotes" },
      { title: "Corp card", $type: "bankCard", custom_fields: { "$paymentCard": { cardNumber: "5555444433331111", cardExpirationDate: "01/2030", cardSecurityCode: "321" }, "$text:cardholderName": "Acme" } },
    ],
  });
  const result = importFromText(json, "keeper.json", "keeper-json");
  assert.equal(result.format, "keeper-json");
  const [bank, router, note, card] = result.entries;
  assert.equal(bank.collection, "Finance Team / Cards");
  assert.equal(bank.shared, true);
  assert.deepEqual(bank.payload.fields, { TOTP: "otpauth://totp/Bank?secret=XYZ", Branch: "Main st", "PIN hint": "birthday" });
  assert.equal(router.collection, "Home / Network");
  assert.equal(router.shared, undefined);
  assert.equal(note.kind, "secure-note");
  assert.equal(card.kind, "payment-card");
  assert.equal(card.payload.secret, "5555444433331111");
  assert.equal(card.payload.username, "Acme");
  assert.equal(card.payload.fields["Security code"], "321");
  assert.deepEqual(result.collections, [{ name: "Finance Team / Cards", count: 1, shared: true }, { name: "Home / Network", count: 1, shared: false }]);
});

// ---------------------------------------------------------------- KeePass / KeePassXC

const keepassXml = `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><Generator>KeePass</Generator><RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>rb0000000000000000000w==</RecycleBinUUID></Meta>
  <Root>
    <Group>
      <UUID>root000000000000000000==</UUID><Name>Database</Name>
      <Entry><UUID>e1</UUID>
        <String><Key>Title</Key><Value>Top level</Value></String>
        <String><Key>UserName</Key><Value>top</Value></String>
        <String><Key>Password</Key><Value Protected="True">${SECRET.replace("&", "&amp;")}</Value></String>
      </Entry>
      <Group><UUID>g1</UUID><Name>Work</Name>
        <Group><UUID>g2</UUID><Name>Servers &amp; DBs</Name>
          <Entry><UUID>e2</UUID><Tags>prod;db</Tags>
            <String><Key>Title</Key><Value>Postgres &lt;main&gt; &#233;</Value></String>
            <String><Key>UserName</Key><Value>postgres</Value></String>
            <String><Key>Password</Key><Value Protected="True">p&apos;w&quot;</Value></String>
            <String><Key>URL</Key><Value>https://db.example.com</Value></String>
            <String><Key>Notes</Key><Value><![CDATA[line <1>
line 2]]></Value></String>
            <String><Key>otp</Key><Value>otpauth://totp/x?secret=JBSWY3DP</Value></String>
            <String><Key>Port</Key><Value>5432</Value></String>
            <Binary><Key>key.pem</Key><Value Ref="0" /></Binary>
            <History>
              <Entry><UUID>e2</UUID><String><Key>Title</Key><Value>Old postgres</Value></String><String><Key>Password</Key><Value>old</Value></String></Entry>
            </History>
          </Entry>
        </Group>
      </Group>
      <Group><UUID>g3</UUID><Name>Personal</Name>
        <Entry><String><Key>Title</Key><Value>Wifi note</Value></String><String><Key>Notes</Key><Value>&lol9; stays literal</Value></String>
          <String><Key>TimeOtp-Secret-Base32</Key><Value>GEZDGNBV</Value></String></Entry>
      </Group>
      <Group><UUID>rb0000000000000000000w==</UUID><Name>Papierkorb</Name>
        <Entry><String><Key>Title</Key><Value>Deleted</Value></String><String><Key>Password</Key><Value>gone</Value></String></Entry>
      </Group>
      <Group><UUID>rb2</UUID><Name>Recycle Bin</Name>
        <Entry><String><Key>Title</Key><Value>Also deleted</Value></String></Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>`;

test("KeePass XML keeps nested groups, skips root name, Recycle Bin and history", () => {
  const result = importFromText(keepassXml, "Database.xml", "keepass-xml");
  assert.equal(result.format, "keepass-xml");
  assert.equal(result.entries.length, 3);
  const [top, pg, wifi] = result.entries;
  assert.equal(top.collection, undefined);
  assert.equal(top.payload.secret, SECRET);
  assert.equal(pg.collection, "Work / Servers & DBs");
  assert.equal(pg.payload.title, "Postgres <main> é");
  assert.equal(pg.payload.secret, "p'w\"");
  assert.equal(pg.payload.notes, "line <1>\nline 2");
  assert.deepEqual(pg.payload.fields, { TOTP: "otpauth://totp/x?secret=JBSWY3DP", Port: "5432" });
  assert.deepEqual(pg.payload.tags, ["Work", "Servers & DBs", "prod", "db"]);
  assert.equal(wifi.kind, "secure-note");
  assert.equal(wifi.payload.notes, "&lol9; stays literal");
  assert.equal(wifi.payload.fields.TOTP, "GEZDGNBV");
  assert.ok(result.entries.every((entry) => !["Deleted", "Also deleted", "Old postgres"].includes(entry.payload.title)));
  assert.deepEqual(result.collections.map((c) => c.name), ["Personal", "Work / Servers & DBs"]);
  assert.ok(result.warnings.some((warning) => /2 items in the Recycle Bin/u.test(warning)));
  assert.ok(result.warnings.some((warning) => /attachments/u.test(warning)));
});

test("XML with a DTD / entity bomb is refused and never expanded", () => {
  const bomb = `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<KeePassFile><Root><Group><Name>R</Name><Entry><String><Key>Title</Key><Value>&lol2;</Value></String></Entry></Group></Root></KeePassFile>`;
  assert.throws(() => importFromText(bomb, "bomb.xml"), /document type definition/u);
  assert.throws(() => parseXml("<a><!ENTITY x 'y'></a>"), /document type definition/u);
  assert.throws(() => importFromText("<KeePassFile><Root><Group></Root></KeePassFile>", "broken.xml"), /could not be read/u);
  assert.throws(() => importFromText("<html><body/></html>", "page.xml"), /not a KeePass export/u);
  const deep = `<KeePassFile><Root>${"<Group>".repeat(500)}${"</Group>".repeat(500)}</Root></KeePassFile>`;
  assert.throws(() => importFromText(deep, "deep.xml"), /could not be read/u);
});

test("KeePassXC CSV maps Root/A/B to collection A / B and skips the Recycle Bin", () => {
  const csv = `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Root","Mail","ann","${SECRET}","https://mail.example","","","0","2026-01-01",""
"Root/Work/Cloud","AWS","admin","pw","https://aws.amazon.com","","otpauth://totp/aws?secret=ABC","0","",""
"Root/Recycle Bin","Gone","x","y","","","","0","",""`;
  const result = importFromText(csv, "keepassxc.csv", "keepass-xml");
  assert.equal(result.format, "keepassxc-csv");
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0].collection, undefined);
  assert.equal(result.entries[1].collection, "Work / Cloud");
  assert.deepEqual(result.entries[1].payload.tags, ["Work", "Cloud"]);
  assert.deepEqual(result.entries[1].payload.fields, { TOTP: "otpauth://totp/aws?secret=ABC" });
  assert.equal(result.skipped, 1);
  assert.equal(result.warnings.length, 1);
});

test("Apple Passwords CSV is detected and maps OTPAuth", () => {
  const csv = `Title,URL,Username,Password,Notes,OTPAuth\nexample.com (ann),https://example.com/,ann,${SECRET},,otpauth://totp/Example?secret=JBSWY3DP\n`;
  const result = importFromText(csv, "Passwords.csv", "apple-csv");
  assert.equal(result.format, "apple-csv");
  assert.equal(result.entries[0].payload.title, "example.com (ann)");
  assert.equal(result.entries[0].payload.secret, SECRET);
  assert.deepEqual(result.entries[0].payload.fields, { TOTP: "otpauth://totp/Example?secret=JBSWY3DP" });
});

// ---------------------------------------------------------------- 1Password .1pux

test("1Password .1pux with stored and deflated entries imports vaults as collections", async () => {
  for (const method of [0, 8]) {
    const bytes = buildZip([{ name: "export.attributes", data: "{}", method }, { name: "export.data", data: exportData, method }, { name: "files/abc.pdf", data: "%PDF", method: 0 }]);
    const result = await importFromFile(named(bytes, "1PasswordExport.1pux"), "1password-1pux");
    assert.equal(result.format, "1password-1pux");
    assert.deepEqual(result.entries.map((entry) => entry.kind), ["login", "secure-note", "payment-card", "identity"]);
    const [gh, , card, me] = result.entries;
    assert.equal(gh.payload.username, "ann");
    assert.equal(gh.payload.secret, SECRET);
    assert.equal(gh.payload.favorite, true);
    assert.equal(gh.payload.fields.TOTP, "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP");
    assert.deepEqual(gh.payload.tags, ["dev"]);
    assert.equal(gh.collection, "Private");
    assert.equal(gh.shared, undefined);
    assert.equal(card.payload.secret, "4111111111111111");
    assert.equal(card.payload.username, "Acme Inc");
    assert.equal(card.payload.fields.Expiry, "12/2028");
    assert.equal(card.payload.fields["Security code"], "999");
    assert.equal(card.shared, true);
    assert.deepEqual(card.payload.tags, ["Marketing Team"]);
    assert.equal(me.payload.username, "Ann Lee");
    assert.equal(me.payload.fields.email, "ann@example.com");
    assert.equal(result.skipped, 1);
    assert.deepEqual(result.collections, [{ name: "Marketing Team", count: 2, shared: true }, { name: "Private", count: 2, shared: false }]);
    assert.ok(result.warnings.some((warning) => /archived/u.test(warning)));
    assert.ok(result.warnings.some((warning) => /attachments/u.test(warning)));
  }
});

test(".1pux rejects encrypted, non-zip, missing export.data and oversize entries", async () => {
  const encrypted = buildZip([{ name: "export.data", data: exportData, method: 8 }], { encryptFlag: true });
  await assert.rejects(importFromFile(named(encrypted, "x.1pux")), /encrypted/u);
  await assert.rejects(importFromFile(named(new TextEncoder().encode(exportData), "x.1pux")), /not a valid 1Password export/u);
  await assert.rejects(importFromFile(named(buildZip([{ name: "other.txt", data: "hi" }]), "x.1pux")), /does not contain export.data/u);
  await assert.rejects(importFromFile(named(buildZip([{ name: "credentials.csv", data: "a" }]), "dashlane.zip")), /Unzip it/u);
  // Declared size above the 50 MB limit.
  const big = buildZip([{ name: "export.data", data: "{}", method: 0 }]);
  const view = new DataView(big.buffer);
  const cdStart = view.getUint32(big.length - 6, true);
  view.setUint32(cdStart + 24, 60 * 1024 * 1024, true);
  await assert.rejects(importFromFile(named(big, "x.1pux")), /too large/u);
  // Corrupted payload fails CRC.
  const corrupt = buildZip([{ name: "export.data", data: exportData, method: 0 }]);
  corrupt[30 + "export.data".length + 5] ^= 0xff;
  await assert.rejects(importFromFile(named(corrupt, "x.1pux")), /damaged/u);
  // Deflate data that expands beyond its declared size is cut off.
  const bomb = buildZip([{ name: "export.data", data: "a".repeat(200000), method: 8 }]);
  const bombView = new DataView(bomb.buffer);
  bombView.setUint32(bombView.getUint32(bomb.length - 6, true) + 24, 1000, true);
  await assert.rejects(importFromFile(named(bomb, "x.1pux")), /larger than expected|damaged/u);
});

test("importFromFile reads text formats and passes the hint", async () => {
  const keeper = await importFromFile(named(new TextEncoder().encode("Folder,Site,user,pw,https://s.example,,\n"), "keeper.csv"), "keeper-csv");
  assert.equal(keeper.format, "keeper-csv");
  assert.equal(keeper.entries[0].collection, "Folder");
  const xml = await importFromFile(named(new TextEncoder().encode(keepassXml), "db.xml"));
  assert.equal(xml.format, "keepass-xml");
});

// ---------------------------------------------------------------- Duplicates and limits

test("findDuplicates flags matches against the vault and earlier rows in the file", () => {
  const csv = "name,url,username,password\nMail,https://www.mail.example/login,Ann,pw1\nMail again,https://mail.example/,ann,pw1\nMail other,https://mail.example,ann,pw2\nNew,https://new.example,bob,pw\n";
  const { entries } = importFromText(csv, "chrome.csv");
  const existing = [{ kind: "login", payload: { title: "Bob", url: "new.example", username: "BOB", secret: "pw" } }];
  assert.deepEqual(findDuplicates(entries, existing), [1, 3]);
  const notes = [{ kind: "secure-note", payload: { title: "A", notes: "x" } }, { kind: "secure-note", payload: { title: "B", notes: "y" } }, { kind: "secure-note", payload: { title: "A", notes: "x" } }];
  assert.deepEqual(findDuplicates(notes, []), [2]);
});

test("size and item limits are enforced", async () => {
  assert.throws(() => importFromText("x".repeat(10 * 1024 * 1024 + 1), "big.csv"), /too large/u);
  await assert.rejects(importFromFile(named(new Uint8Array(10 * 1024 * 1024 + 1), "big.csv")), /too large/u);
  const rows = ["name,url,username,password"];
  for (let index = 0; index <= MAX_IMPORT_ITEMS; index += 1) rows.push(`n${index},https://s${index}.example,u,p`);
  assert.throws(() => importFromText(rows.join("\n"), "many.csv"), /more than 5000 items/u);
  assert.throws(() => importFromText("name,url,username,password\n", "empty.csv"), /does not contain any records/u);
});

test("error messages and warnings never contain the password value", async () => {
  const cases = [
    () => importFromText(`{"items": [ {"type": 1, "login": {"password": "${SECRET}" } ] `, "broken.json"),
    () => importFromText(`<KeePassFile><Root><Group><Entry><String><Key>Password</Key><Value>${SECRET}</Value></String></Entry></Group></KeePassFile>`, "broken.xml"),
    () => importFromText(`foo,bar\n${SECRET},2\n`, "x.csv"),
    () => importFromText(`${SECRET},x,y`, "keeper.csv"),
    () => importFromText(`{"records": [], "x": "${SECRET}"}`, "keeper.json"),
  ];
  for (const run of cases) {
    try { run(); assert.fail("expected an error"); } catch (error) { assert.ok(!String(error.message).includes(SECRET), error.message); }
  }
  try { await importFromFile(named(new TextEncoder().encode(SECRET), "x.1pux")); } catch (error) { assert.ok(!error.message.includes(SECRET)); }
  const ok = importFromText(keepassXml, "db.xml");
  assert.ok(ok.warnings.every((warning) => !warning.includes(SECRET)));
});
