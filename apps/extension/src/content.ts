function safeOrigin(value: string) {
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.origin : ""; }
  catch { return ""; }
}

function visible(input: HTMLInputElement) {
  const style = getComputedStyle(input); const rect = input.getBoundingClientRect();
  return !input.disabled && !input.readOnly && !input.closest('[hidden], [inert]') && style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0" && rect.width > 0 && rect.height > 0;
}

function fields(root: ParentNode = document, filling = false) {
  const password = [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].find(input => visible(input) && (!filling || input.autocomplete !== "new-password"));
  if (!password) return null;
  const form = password.form ?? root;
  if (filling && password.form && safeOrigin(password.form.action) !== location.origin) return null;
  const username = [...form.querySelectorAll<HTMLInputElement>('input[type="email"],input[autocomplete="username"],input[type="text"]')].find(visible);
  return { username, password };
}

function setValue(input: HTMLInputElement, value: string) {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  descriptor?.set?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

document.addEventListener("submit", (event) => {
  if (window.top !== window || !safeOrigin(location.href) || ["passkey-x.com", "www.passkey-x.com"].includes(location.hostname)) return;
  const found = fields(event.target instanceof HTMLFormElement ? event.target : document);
  if (!found?.password.value) return;
  void chrome.runtime.sendMessage({ type: "PX_CANDIDATE", origin: location.origin, url: location.origin + location.pathname, username: found.username?.value ?? "", secret: found.password.value }).catch(() => { /* Extension was reloaded or is unavailable. */ });
}, true);

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const request = message as Record<string, unknown>;
  if (window.top !== window || sender.id !== chrome.runtime.id || request?.type !== "PX_FILL" || request.origin !== location.origin || typeof request.username !== "string" || typeof request.secret !== "string") return false;
  const found = fields(document, true); if (!found) { sendResponse({ ok: false }); return false; }
  if (found.username) setValue(found.username, request.username);
  setValue(found.password, request.secret);
  sendResponse({ ok: true });
  return false;
});
