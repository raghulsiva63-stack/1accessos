type Status = { ok: boolean; unlocked?: boolean; matches?: { id: string; title: string; username: string }[]; candidate?: boolean; error?: string };
const get = <T extends Element>(selector: string) => document.querySelector<T>(selector)!;
const signedOut = get<HTMLElement>("#signed-out"); const unlocked = get<HTMLElement>("#unlocked"); const loginForm = get<HTMLFormElement>("#login-form"); const lockButton = get<HTMLButtonElement>("#lock"); const matches = get<HTMLElement>("#matches"); const empty = get<HTMLElement>("#empty"); const candidate = get<HTMLElement>("#candidate"); const message = get<HTMLElement>("#message"); const originLabel = get<HTMLElement>("#origin");
let tabId = 0; let origin = "";

async function request(payload: Record<string, unknown>): Promise<Status> { return chrome.runtime.sendMessage({ ...payload, tabId, origin }) as Promise<Status>; }
function showMessage(value = "") { message.textContent = value; }
function render(status: Status) {
  if (!status.ok) { showMessage(status.error ?? "Unable to open Passkey-X."); return; }
  signedOut.hidden = Boolean(status.unlocked); unlocked.hidden = !status.unlocked; lockButton.hidden = !status.unlocked;
  if (!status.unlocked) return;
  matches.replaceChildren();
  for (const credential of status.matches ?? []) {
    const button = document.createElement("button"); const text = document.createElement("span"); const title = document.createElement("strong"); const username = document.createElement("span"); const action = document.createElement("em");
    title.textContent = credential.title; username.textContent = credential.username || "No username"; action.textContent = "Fill"; text.append(title, username); button.append(text, action);
    button.addEventListener("click", async () => { showMessage(""); render(await request({ type: "PX_FILL", id: credential.id })); window.close(); }); matches.append(button);
  }
  candidate.hidden = !status.candidate; empty.hidden = Boolean((status.matches ?? []).length || status.candidate); empty.style.display = empty.hidden ? "none" : "grid";
}

async function refresh() { render(await request({ type: "PX_STATUS" })); }

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault(); showMessage("Unlocking…");
  const email = get<HTMLInputElement>("#email"); const loginPassword = get<HTMLInputElement>("#login-password"); const vaultPassword = get<HTMLInputElement>("#vault-password");
  const status = await request({ type: "PX_UNLOCK", email: email.value, loginPassword: loginPassword.value, vaultPassword: vaultPassword.value });
  loginPassword.value = ""; vaultPassword.value = ""; showMessage(""); render(status);
});
lockButton.addEventListener("click", async () => { render(await request({ type: "PX_LOCK" })); });
get<HTMLButtonElement>("#save").addEventListener("click", async () => { showMessage("Encrypting and saving…"); const status = await request({ type: "PX_SAVE" }); showMessage(status.ok ? "Login saved." : status.error); render(status); });
get<HTMLButtonElement>("#never").addEventListener("click", async () => { const status = await request({ type: "PX_NEVER" }); showMessage(status.ok ? "Passkey-X will ignore this site." : status.error); render(status); });

void chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  tabId = tab?.id ?? 0;
  try { const parsed = new URL(tab?.url ?? ""); origin = ["http:", "https:"].includes(parsed.protocol) ? parsed.origin : ""; } catch { origin = ""; }
  originLabel.textContent = origin ? new URL(origin).hostname : "Unsupported page";
  void refresh();
});
