function safeOrigin(value: string) {
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.origin : ""; }
  catch { return ""; }
}

function visible(input: HTMLInputElement) {
  const style = getComputedStyle(input); const rect = input.getBoundingClientRect();
  return !input.disabled && !input.readOnly && style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
}

function fields(root: ParentNode = document) {
  const password = [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].find(visible);
  if (!password) return null;
  const form = password.form ?? root;
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
  if (window.top !== window || !safeOrigin(location.href)) return;
  const found = fields(event.target instanceof HTMLFormElement ? event.target : document);
  if (!found?.password.value) return;
  void chrome.runtime.sendMessage({ type: "PX_CANDIDATE", origin: location.origin, url: location.href, username: found.username?.value ?? "", secret: found.password.value });
}, true);

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const request = message as Record<string, unknown>;
  if (sender.id !== chrome.runtime.id || request?.type !== "PX_FILL" || request.origin !== location.origin || typeof request.username !== "string" || typeof request.secret !== "string") return false;
  const found = fields(); if (!found) { sendResponse({ ok: false }); return false; }
  if (found.username) setValue(found.username, request.username);
  setValue(found.password, request.secret);
  sendResponse({ ok: true });
  return false;
});
