type Status = { ok: boolean; connected?: boolean; email?: string; unlocked?: boolean; matches?: { id: string; title: string; username: string }[]; workspaces?: { id: string; name: string }[]; ignored?: boolean; candidate?: boolean; error?: string };
const get = <T extends Element>(selector: string) => document.querySelector<T>(selector)!;
const disconnected = get<HTMLElement>("#disconnected");
const locked = get<HTMLElement>("#locked");
const unlocked = get<HTMLElement>("#unlocked");
const form = get<HTMLFormElement>("#unlock-form");
const lockButton = get<HTMLButtonElement>("#lock");
const matches = get<HTMLElement>("#matches");
const empty = get<HTMLElement>("#empty");
const candidate = get<HTMLElement>("#candidate");
const message = get<HTMLElement>("#message");
let tabId = 0, origin = "";
const show = (value = "") => { message.textContent = value; };
async function request(payload: Record<string, unknown>): Promise<Status> {
  try { return await chrome.runtime.sendMessage({ ...payload, tabId, origin }) as Status; }
  catch { return { ok: false, error: "Passkey-X could not respond. Reload the extension and try again." }; }
}
function render(status: Status) {
  if (!status.ok) { show(status.error ?? "Unable to open Passkey-X."); return; }
  disconnected.hidden = Boolean(status.connected);
  locked.hidden = !status.connected || Boolean(status.unlocked);
  unlocked.hidden = !status.unlocked;
  lockButton.hidden = !status.unlocked;
  get<HTMLElement>("#account").textContent = status.email ?? "Account connected";
  matches.replaceChildren();
  if (!status.unlocked) return;
  const selector = get<HTMLSelectElement>("#save-workspace");
  const selected = selector.value;
  selector.replaceChildren();
  for (const workspace of status.workspaces ?? []) {
    const option = document.createElement("option");
    option.value = workspace.id; option.textContent = workspace.name; selector.append(option);
  }
  if ([...selector.options].some(option => option.value === selected)) selector.value = selected;
  get<HTMLButtonElement>("#save").disabled = !selector.options.length;
  get<HTMLButtonElement>("#allow").hidden = !status.ignored;
  for (const credential of status.matches ?? []) {
    const button = document.createElement("button"), text = document.createElement("span"), title = document.createElement("strong"), username = document.createElement("span"), action = document.createElement("em");
    title.textContent = credential.title; username.textContent = credential.username || "No username"; action.textContent = "Fill";
    text.append(title, username); button.append(text, action);
    button.addEventListener("click", () => void perform({ type: "PX_FILL", id: credential.id }, "Filling…", "Login filled.", true));
    matches.append(button);
  }
  candidate.hidden = !status.candidate;
  empty.hidden = Boolean((status.matches ?? []).length || status.candidate);
}
async function perform(payload: Record<string, unknown>, progress = "", success = "", close = false) {
  show(progress);
  const buttons = [...document.querySelectorAll<HTMLButtonElement>("button")].filter(button => button !== lockButton);
  buttons.forEach(button => { button.disabled = true; });
  try {
    const status = await request(payload);
    show(status.ok ? success : status.error);
    render(status);
    if (status.ok && close) window.close();
  } finally {
    buttons.forEach(button => { button.disabled = false; });
    get<HTMLButtonElement>("#save").disabled = !get<HTMLSelectElement>("#save-workspace").options.length;
  }
}
get<HTMLButtonElement>("#connect").addEventListener("click", () => void perform({ type: "PX_CONNECT" }, "Opening secure connection…", "", true));
form.addEventListener("submit", event => {
  event.preventDefault();
  const password = get<HTMLInputElement>("#vault-password");
  const vaultPassword = password.value; password.value = "";
  void perform({ type: "PX_UNLOCK", vaultPassword }, "Unlocking…");
});
lockButton.addEventListener("click", () => void perform({ type: "PX_LOCK" }));
get<HTMLButtonElement>("#disconnect").addEventListener("click", () => void perform({ type: "PX_DISCONNECT" }, "Disconnecting…"));
get<HTMLButtonElement>("#save").addEventListener("click", () => void perform({ type: "PX_SAVE", workspaceId: get<HTMLSelectElement>("#save-workspace").value }, "Encrypting and saving…", "Login saved."));
get<HTMLButtonElement>("#never").addEventListener("click", () => void perform({ type: "PX_NEVER" }, "", "Passkey-X will ignore this site."));
get<HTMLButtonElement>("#allow").addEventListener("click", () => void perform({ type: "PX_ALLOW" }, "", "Passkey-X can offer saves for this site again."));
void chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
  tabId = tab?.id ?? 0;
  try { const parsed = new URL(tab?.url ?? ""); origin = ["http:", "https:"].includes(parsed.protocol) ? parsed.origin : ""; } catch { origin = ""; }
  get<HTMLElement>("#origin").textContent = origin ? new URL(origin).hostname : "Unsupported page";
  render(await request({ type: "PX_STATUS" }));
}).catch(() => show("Unable to read this tab. Reopen Passkey-X on a website."));
export {};
