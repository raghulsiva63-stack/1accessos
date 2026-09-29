// Hostname helpers shared by phishing checks and the 2FA / passkey site directory. Pure.

// Public suffixes with two labels that matter for common sites. Not the full Public Suffix List,
// but enough to avoid treating "co.uk" or "github.io" as one site.
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in",
  "co.nz", "org.nz", "govt.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn", "org.cn", "gov.cn",
  "com.sg", "edu.sg", "gov.sg", "com.my", "co.za", "org.za", "gov.za", "com.mx", "org.mx", "gob.mx",
  "com.tr", "gov.tr", "co.kr", "or.kr", "go.kr", "com.hk", "org.hk", "com.tw", "org.tw", "co.id", "or.id", "go.id",
  "com.ar", "com.sa", "com.pk", "com.ng", "com.eg", "co.il", "org.il", "com.ph", "com.vn", "co.th", "in.th",
  "com.ua", "com.pl", "co.ke", "com.co", "com.pe", "com.bd", "com.np", "com.lk",
  // Shared hosting: every subdomain is a different owner.
  "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev",
  "azurewebsites.net", "cloudfront.net", "blogspot.com", "web.app", "firebaseapp.com", "appspot.com",
  "onrender.com", "fly.dev", "glitch.me", "repl.co", "wixsite.com", "squarespace.com", "myshopify.com",
]);

/** Lower-case hostname without a leading "www.", or null for anything that is not a web address. */
export function hostnameOf(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try { url = new URL(candidate); } catch { return null; }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  const host = url.hostname.toLowerCase().replace(/\.$/u, "").replace(/^www\./u, "");
  if (!host || host.startsWith("[") || /^\d+\.\d+\.\d+\.\d+$/u.test(host)) return host || null;
  return host;
}

/** "accounts.google.co.uk" → { domain: "google.co.uk", label: "google", suffix: "co.uk" }. */
export function splitDomain(host: string): { domain: string; label: string; suffix: string } {
  const parts = host.split(".").filter(Boolean);
  if (parts.length < 2) return { domain: host, label: host, suffix: "" };
  const lastTwo = parts.slice(-2).join(".");
  const suffixLength = parts.length >= 3 && MULTI_LABEL_SUFFIXES.has(lastTwo) ? 2 : 1;
  const label = parts[parts.length - suffixLength - 1] ?? parts[0];
  const suffix = parts.slice(-suffixLength).join(".");
  return { domain: `${label}.${suffix}`, label, suffix };
}

export function registrableDomain(host: string): string {
  return splitDomain(host).domain;
}
