import assert from "node:assert/strict";
import { register } from "node:module";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const hash = await import("../../apps/web/lib/security/url-hash.ts");
const guard = await import("../../apps/web/lib/security/web-guard.ts");
const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

const canon = (url) => {
  const value = hash.canonicalExpression(url);
  return value ? `${value.host}${value.path}${value.query}` : null;
};

test("canonicalization follows the Safe Browsing examples", () => {
  assert.equal(canon("http://host/%25%32%35"), "host/%25");
  assert.equal(canon("http://host/%25%32%35%25%32%35"), "host/%25%25");
  assert.equal(canon("http://host/%2525252525252525"), "host/%25");
  assert.equal(canon("http://www.google.com/blah/.."), "www.google.com/");
  assert.equal(canon("http://www.google.com/foo\tbar\rbaz\n2"), "www.google.com/foobarbaz2");
  assert.equal(canon("http://3279880203/blah"), "195.127.0.11/blah");
  assert.equal(canon("http://www.GOOgle.com/"), "www.google.com/");
  assert.equal(canon("http://www.google.com.../"), "www.google.com/");
  assert.equal(canon("http://www.google.com/q?r?"), "www.google.com/q?r?");
  assert.equal(canon("http://www.google.com/q?r?s"), "www.google.com/q?r?s");
  assert.equal(canon("http://evil.com/foo#bar#baz"), "evil.com/foo");
  assert.equal(canon("http://host.com/ab%23cd"), "host.com/ab%23cd");
  assert.equal(canon("http://host.com//twoslashes?more//slashes"), "host.com/twoslashes?more//slashes");
  assert.equal(canon("http://www.google.com/blah/./"), "www.google.com/blah/");
  assert.equal(canon("www.google.com"), "www.google.com/");
  assert.equal(canon("https://user:pw@Example.COM:8443/a b"), "example.com/a%20b");
  assert.equal(canon("javascript:alert(1)"), null);
});

test("lookup expressions match the Safe Browsing example", () => {
  assert.deepEqual(hash.urlExpressions("http://a.b.c/1/2.html?param=1").sort(), [
    "a.b.c/", "a.b.c/1/", "a.b.c/1/2.html", "a.b.c/1/2.html?param=1",
    "b.c/", "b.c/1/", "b.c/1/2.html", "b.c/1/2.html?param=1",
  ].sort());
  const deep = hash.urlExpressions("http://a.b.c.d.e.f.g/1.html");
  assert.ok(deep.includes("a.b.c.d.e.f.g/1.html") && deep.includes("c.d.e.f.g/") && deep.includes("f.g/1.html"));
  assert.ok(!deep.some((expression) => expression.startsWith("b.c.d.e.f.g/")) && !deep.some((expression) => expression.startsWith("g/")));
  assert.deepEqual(hash.urlExpressions("http://1.2.3.4/1/"), ["1.2.3.4/1/", "1.2.3.4/"]);
  assert.ok(hash.urlExpressions("https://x.example.com/a/b/c/d/e/f/g.html").length <= 30);
  assert.equal(hash.domainExpression("*.Evil.example"), "evil.example/");
});

test("prefix sets round-trip and reject malformed data", async () => {
  const prefixes = [];
  for (const expression of ["evil.example/", "phish.test/login"]) prefixes.push(hash.prefixOf(await hash.sha256Bytes(expression)));
  const set = hash.PrefixSet.decode(hash.encodePrefixSet([...prefixes, prefixes[0], 0xffffffff, 0], 7));
  assert.equal(set.version, 7);
  assert.equal(set.size, 4);
  for (const prefix of prefixes) assert.ok(set.has(prefix));
  assert.ok(set.has(0xffffffff) && set.has(0) && !set.has(12345));
  assert.throws(() => hash.PrefixSet.decode(new Uint8Array(8)));
  const unsorted = hash.encodePrefixSet([1, 2], 1);
  unsorted.set([0, 0, 0, 1], 16); // duplicate value: not strictly increasing
  assert.throws(() => hash.PrefixSet.decode(unsorted));
});

test("threat lookups send only matching prefixes and compare full hashes on the device", async () => {
  const target = "http://phish.test/login?id=1";
  const full = await hash.sha256Bytes("phish.test/login");
  const set = hash.PrefixSet.decode(hash.encodePrefixSet([hash.prefixOf(full)], 1));
  let sent = null;
  const match = await guard.lookupThreats(target, [set], async (prefixes) => {
    sent = prefixes;
    return [{ hash: hash.toBase64(full), threat: "phishing", source: "Google Web Risk" },
      { hash: hash.toBase64(new Uint8Array(32)), threat: "malware", source: "other" }];
  });
  assert.deepEqual(sent, [hash.toBase64(full.slice(0, 4))]);
  assert.equal(match.threat, "phishing");
  let asked = false;
  assert.equal(await guard.lookupThreats("https://safe.example/", [set], async () => { asked = true; return []; }), null);
  assert.equal(asked, false, "no network call without a local prefix match");
  const verdict = guard.withThreat(guard.assessPageLocally(target), match);
  assert.equal(verdict.level, "dangerous");
  assert.equal(guard.verdictKind(verdict), "phishing_site");
  assert.equal(guard.guardAction(verdict, guard.DEFAULT_GUARD_POLICY), "warn");
  assert.equal(guard.guardAction(verdict, { ...guard.DEFAULT_GUARD_POLICY, webMode: "block" }), "block");
  assert.equal(guard.guardAction(verdict, { ...guard.DEFAULT_GUARD_POLICY, webMode: "off" }), "none");
});

test("look-alikes of vault sites, brands and the organization are caught; real sites are not", () => {
  const vault = ["https://github.com/login", "https://acme-payroll.com"];
  const homoglyph = guard.assessPageLocally("https://g1thub.com/login", guard.DEFAULT_GUARD_POLICY, { savedUrls: vault });
  assert.equal(homoglyph.level, "dangerous");
  assert.equal(homoglyph.reasons[0].of, "vault");
  assert.equal(guard.assessPageLocally("https://github.com/settings", guard.DEFAULT_GUARD_POLICY, { savedUrls: vault }).level, "safe");
  // Brand embedded in another site's address.
  const embedded = guard.assessPageLocally("https://paypal.com.account-check.top/signin");
  assert.equal(embedded.level, "dangerous");
  assert.match(guard.verdictTitle(embedded), /pretending to be paypal\.com/u);
  // Punycode copy of a brand.
  assert.equal(guard.assessPageLocally("https://xn--pypal-4ve.com/").level, "dangerous");
  // Weak hints only where a password is asked for, and never for known legitimate sites.
  assert.equal(guard.assessPageLocally("https://paypal-help.net/").level, "safe");
  assert.equal(guard.assessPageLocally("https://paypal-help.net/", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).level, "suspicious");
  assert.equal(guard.assessPageLocally("https://paypay.ne.jp/", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).level, "safe");
  assert.equal(guard.assessPageLocally("https://google-analytics.com/", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true, isKnownLegitimate: (d) => d === "google-analytics.com" }).level, "safe");
  assert.equal(guard.assessPageLocally("https://www.paypal.com/signin", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).level, "safe");
  // The organization's own domain.
  const policy = { ...guard.DEFAULT_GUARD_POLICY, protectedDomains: ["acmecorp.com"] };
  const org = guard.assessPageLocally("https://acmec0rp.com/sso", policy);
  assert.equal(org.level, "dangerous");
  assert.equal(org.reasons[0].of, "organization");
});

test("organization lists, risky login pages and password reuse", () => {
  const policy = { ...guard.DEFAULT_GUARD_POLICY, blockDomains: ["casino.example"], allowDomains: ["intranet.acme.local", "partner.top"] };
  assert.equal(guard.assessPageLocally("https://www.casino.example/", policy).level, "dangerous");
  assert.equal(guard.verdictKind(guard.assessPageLocally("https://casino.example/", policy)), "blocked_site");
  assert.equal(guard.assessPageLocally("https://partner.top/login", policy, { hasPasswordField: true }).level, "safe");
  assert.equal(guard.assessPageLocally("http://shop.example/login", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).reasons[0].code, "insecure_login");
  assert.equal(guard.assessPageLocally("http://shop.example/", guard.DEFAULT_GUARD_POLICY).level, "safe");
  assert.equal(guard.assessPageLocally("https://203.0.113.9/login", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).level, "suspicious");
  assert.equal(guard.assessPageLocally("https://secure-bank.zip/", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).reasons[0].code, "unusual_ending");
  assert.equal(guard.assessPageLocally("data:text/html,<form>", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).level, "dangerous");
  assert.equal(guard.assessPageLocally("http://localhost:3000/login", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true }).level, "safe");
  const suspicious = guard.assessPageLocally("http://shop.example/login", guard.DEFAULT_GUARD_POLICY, { hasPasswordField: true });
  assert.equal(guard.guardAction(suspicious, guard.DEFAULT_GUARD_POLICY), "notice");
  assert.equal(guard.guardAction(suspicious, { ...guard.DEFAULT_GUARD_POLICY, blockSuspicious: true }), "warn");

  const saved = [{ url: "https://bank.example", secret: "correct horse battery" }, { url: "https://mail.example", secret: "other secret 1" }];
  assert.equal(guard.passwordReuseSite("https://bank-example.top/login", "correct horse battery", saved), "bank.example");
  assert.equal(guard.passwordReuseSite("https://online.bank.example/login", "correct horse battery", saved), null);
  assert.equal(guard.passwordReuseSite("https://elsewhere.example/", "short", saved), null);
  assert.equal(guard.passwordReuseSite("https://elsewhere.example/", "not saved anywhere", saved), null);
});

test("the edge functions hash exactly like the devices", async () => {
  assert.equal(await read("supabase/functions/_shared/url-hash.ts"), await read("apps/web/lib/security/url-hash.ts"));
});
