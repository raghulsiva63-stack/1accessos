// Mirrors the service worker: never capture or fill on plain-HTTP pages except local development.
function safeOrigin(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol === "https:") return url.origin;
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ? url.origin : "";
  }
  catch { return ""; }
}

function visible(input: HTMLInputElement) {
  const style = getComputedStyle(input); const rect = input.getBoundingClientRect();
  return !input.disabled && !input.readOnly && !input.closest('[hidden], [inert]') && style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0" && rect.width > 0 && rect.height > 0;
}

function fields(root: ParentNode = document, filling = false) {
  const passwords = [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(visible);
  const fresh = passwords.filter(input => input.autocomplete === "new-password");
  const password = filling ? passwords.find(input => input.autocomplete !== "new-password") : fresh[0] ?? passwords[0];
  if (!password) return null;
  if (!filling && fresh.length > 1 && fresh.some(input => input.value !== password.value)) return null;
  const form = password.form ?? root;
  if (password.form && safeOrigin(password.form.action) !== location.origin) return null;
  const usernames = [...form.querySelectorAll<HTMLInputElement>('input[type="email"],input[autocomplete="username"],input[type="text"]')].filter(visible);
  const username = usernames.find(input => input.autocomplete === "username") ?? usernames.find(input => input.type === "email") ?? usernames[0];
  return { username, password };
}

function setValue(input: HTMLInputElement, value: string) {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  descriptor?.set?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function capture(event: Event, root: ParentNode) {
  if (!event.isTrusted || window.top !== window || !safeOrigin(location.href) || ["passkey-x.com", "www.passkey-x.com"].includes(location.hostname)) return;
  const found = fields(root);
  if (!found?.password.value) return;
  void chrome.runtime.sendMessage({ type: "PX_CANDIDATE", origin: location.origin, url: location.origin + location.pathname, username: found.username?.value ?? "", secret: found.password.value }).catch(() => { /* Extension was reloaded or is unavailable. */ });
}

document.addEventListener("submit", event => capture(event, event.target instanceof HTMLFormElement ? event.target : document), true);
// Many modern sign-in screens use a button and fetch(), without submitting a form.
document.addEventListener("click", event => {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest<HTMLButtonElement | HTMLInputElement>('button,input[type="submit"],input[type="image"],[role="button"]');
  if (!button || button.disabled) return;
  const label = (button.getAttribute("aria-label") || button.textContent || button.value || "").trim();
  if (button.type !== "submit" && !/^(sign[\s-]?in|log[\s-]?in|continue|sign[\s-]?up|create\s+(account|password)|register|change\s+password|save\s+password|reset\s+password)\b/iu.test(label)) return;
  capture(event, button.form ?? button.closest('form,[role="form"]') ?? document);
}, true);
document.addEventListener("keydown", event => {
  if (event.key !== "Enter" || !(event.target instanceof HTMLInputElement) || !["password", "email", "text"].includes(event.target.type)) return;
  capture(event, event.target.form ?? document);
}, true);

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const request = message as Record<string, unknown>;
  if (request?.type === "PX_GUARD_BANNER") { guardMessage(request, sender); return false; }
  if (window.top !== window || sender.id !== chrome.runtime.id || request?.type !== "PX_FILL" || !safeOrigin(location.href) || request.origin !== location.origin || typeof request.username !== "string" || typeof request.secret !== "string") return false;
  const found = fields(document, true); if (!found) { sendResponse({ ok: false }); return false; }
  if (found.username) setValue(found.username, request.username);
  setValue(found.password, request.secret);
  sendResponse({ ok: true });
  return false;
});

// ---------------------------------------------------------------------------
// Web Guard: tell the service worker whether this page asks for a password, and show its
// warnings in the page. The banner lives in a closed shadow root and shows text only.
// ---------------------------------------------------------------------------

let guardBanner: HTMLElement | null = null;

function showGuardBanner(level: "suspicious" | "dangerous", title: string, text: string) {
  if (window.top !== window) return;
  guardBanner?.remove();
  const host = document.createElement("passkey-x-guard");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `:host{all:initial}div{position:fixed;z-index:2147483647;top:12px;left:50%;transform:translateX(-50%);width:min(640px,calc(100vw - 24px));
    display:flex;gap:12px;align-items:flex-start;padding:14px 16px;border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.35);
    font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;color:#fff;background:${level === "dangerous" ? "#a11b1b" : "#9a5208"}}
    strong{display:block;font-size:15px;margin-bottom:2px}span{flex:1}button{all:unset;cursor:pointer;padding:2px 8px;border-radius:6px;font-weight:700;background:rgba(255,255,255,.2)}
    button:focus-visible{outline:2px solid #fff}`;
  const box = document.createElement("div");
  box.setAttribute("role", "alert");
  const body = document.createElement("span");
  const heading = document.createElement("strong");
  heading.textContent = `Passkey-X: ${title}`;
  body.append(heading, document.createTextNode(text));
  const close = document.createElement("button");
  close.textContent = "Dismiss";
  close.addEventListener("click", () => host.remove());
  box.append(body, close);
  shadow.append(style, box);
  (document.body ?? document.documentElement).append(host);
  guardBanner = host;
}

let contextSent = false;
function reportPageContext() {
  if (contextSent || window.top !== window || !/^https?:$/u.test(location.protocol)) return;
  const hasPasswordField = [...document.querySelectorAll<HTMLInputElement>('input[type="password"]')].some(visible);
  if (!hasPasswordField) return;
  contextSent = true;
  void chrome.runtime.sendMessage({ type: "PX_PAGE_CONTEXT", origin: location.origin, hasPasswordField })
    .then((answer: { notice?: { level?: string; title?: string; text?: string } } | undefined) => {
      const notice = answer?.notice;
      if (notice && typeof notice.title === "string" && typeof notice.text === "string") {
        showGuardBanner(notice.level === "dangerous" ? "dangerous" : "suspicious", notice.title.slice(0, 160), notice.text.slice(0, 400));
      }
    })
    .catch(() => { /* Extension was reloaded or is unavailable. */ });
}

reportPageContext();
// Sign-in forms often appear after the page loads.
if (!contextSent && window.top === window && typeof MutationObserver === "function") {
  const observer = new MutationObserver(() => { reportPageContext(); if (contextSent) observer.disconnect(); });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => observer.disconnect(), 30_000);
}

function guardMessage(request: Record<string, unknown>, sender: chrome.runtime.MessageSender) {
  if (window.top !== window || sender.id !== chrome.runtime.id) return;
  if (typeof request.title === "string" && typeof request.text === "string") {
    showGuardBanner(request.level === "dangerous" ? "dangerous" : "suspicious", request.title.slice(0, 160), request.text.slice(0, 400));
  }
}
