// Full-page warning shown instead of a dangerous site. Everything shown comes from the URL
// fragment written by the service worker; it is inserted as text only.

type Payload = { url: string; title: string; reasons: string[]; level: string; mode: "warn" | "block"; organization: string | null };

const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function payload(): Payload | null {
  try {
    const value = JSON.parse(decodeURIComponent(location.hash.slice(1))) as Partial<Payload>;
    if (typeof value.url !== "string" || typeof value.title !== "string") return null;
    return {
      url: value.url.slice(0, 4096), title: value.title.slice(0, 160), level: value.level === "suspicious" ? "suspicious" : "dangerous",
      reasons: Array.isArray(value.reasons) ? value.reasons.filter((reason): reason is string => typeof reason === "string").slice(0, 6).map((reason) => reason.slice(0, 300)) : [],
      mode: value.mode === "block" ? "block" : "warn",
      organization: typeof value.organization === "string" ? value.organization.slice(0, 80) : null,
    };
  } catch { return null; }
}

const data = payload();
const status = get<HTMLParagraphElement>("status");

if (data) {
  let site = data.url;
  try { const parsed = new URL(data.url); site = parsed.protocol === "data:" ? "A page created in the address bar (data: URL)" : parsed.host + (parsed.pathname === "/" ? "" : parsed.pathname); } catch { /* keep raw */ }
  document.title = `${data.title} · Passkey-X`;
  document.body.classList.toggle("suspicious", data.level === "suspicious");
  get("title").textContent = data.title;
  get("site").textContent = site.slice(0, 300);
  if (data.level === "suspicious") get("summary").textContent = "Passkey-X paused this page. Check it carefully before you continue.";
  const list = get<HTMLUListElement>("reasons");
  for (const reason of data.reasons) { const item = document.createElement("li"); item.textContent = reason; list.append(item); }
  if (data.organization) {
    const organization = get<HTMLParagraphElement>("organization");
    organization.hidden = false;
    organization.textContent = data.mode === "block"
      ? `${data.organization} does not allow opening this site. Contact your IT team if you need it.`
      : `${data.organization} has been notified that this site was blocked on your device.`;
  }
  get<HTMLDetailsElement>("more").hidden = data.mode === "block";
}

get<HTMLButtonElement>("leave").addEventListener("click", () => {
  void chrome.runtime.sendMessage({ type: "PX_GUARD_LEAVE" }).catch(() => undefined);
});
get<HTMLButtonElement>("proceed").addEventListener("click", async () => {
  if (!data || data.mode === "block") return;
  if (!window.confirm("Continue to a site Passkey-X marked as dangerous? Your organization will see that you continued.")) return;
  const answer = await chrome.runtime.sendMessage({ type: "PX_GUARD_PROCEED", url: data.url }).catch(() => null) as { ok?: boolean } | null;
  if (!answer?.ok) status.textContent = "This site can't be opened.";
});
get<HTMLButtonElement>("report-safe").addEventListener("click", async () => {
  if (!data) return;
  const answer = await chrome.runtime.sendMessage({ type: "PX_GUARD_DISPUTE", url: data.url }).catch(() => null) as { ok?: boolean } | null;
  status.textContent = answer?.ok ? "Thanks. Your IT team will review this site." : "Couldn't send the request. Contact your IT team.";
});
