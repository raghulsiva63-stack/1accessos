type PendingLogin = { id: string; username: string; origin: string; modes: Record<string, "save" | "update" | "same"> };
type Desktop = { available: boolean; paired: boolean; pendingCode: string | null };
type Status = { ok: boolean; desktop?: Desktop; desktopCode?: string; connected?: boolean; email?: string; unlocked?: boolean; matches?: { id: string; title: string; username: string }[]; workspaces?: { id: string; name: string }[]; ignored?: boolean; candidate?: PendingLogin | null; lookalike?: { resembles: string; reason: string } | null; error?: string };
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
let pending: PendingLogin | null = null;
let triedDesktop = false;
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
  const desktop = status.desktop;
  const code = status.desktopCode ?? desktop?.pendingCode ?? null;
  get<HTMLElement>("#desktop-unlock-row").hidden = !desktop?.paired;
  get<HTMLButtonElement>("#desktop-pair").hidden = Boolean(desktop?.paired);
  get<HTMLButtonElement>("#desktop-unpair").hidden = !desktop?.paired;
  const codeView = get<HTMLElement>("#desktop-code");
  codeView.hidden = !code;
  codeView.textContent = code ? `Check that Passkey-X desktop shows ${code.slice(0, 3)} ${code.slice(3)}, then approve it there.` : "";
  // Paired: try the desktop app first, once per popup.
  if (status.connected && !status.unlocked && desktop?.paired && desktop.available && !triedDesktop) {
    triedDesktop = true;
    setTimeout(() => void perform({ type: "PX_DESKTOP_UNLOCK" }, "Unlocking with Passkey-X desktop…"), 0);
  }
  pending = status.candidate ?? null;
  get<HTMLElement>("#pending-unlock").hidden = !pending;
  get<HTMLElement>("#pending-locked-actions").hidden = !pending;
  get<HTMLElement>("#pending-unlock").textContent = pending ? `A login for ${new URL(pending.origin).hostname} is waiting. Unlock to review and save it.` : "";
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
  get<HTMLElement>("#candidate-username").textContent = pending?.username || "No username detected";
  updateSaveAction();
  get<HTMLButtonElement>("#allow").hidden = !status.ignored;
  const warning = get<HTMLElement>("#lookalike");
  warning.hidden = !status.lookalike;
  get<HTMLElement>("#lookalike-text").textContent = status.lookalike
    ? `You have a login saved for ${status.lookalike.resembles}, but this is ${origin ? new URL(origin).hostname : "a different site"}. Passkey-X won't fill here. Don't type your password unless you're sure this is the real site.`
    : "";
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
function updateSaveAction() {
  const mode = pending?.modes[get<HTMLSelectElement>("#save-workspace").value] ?? "save";
  get<HTMLElement>("#candidate-title").textContent = mode === "update" ? "Update this password?" : mode === "same" ? "This login is already saved" : "Save this login?";
  get<HTMLButtonElement>("#save").textContent = mode === "update" ? "Update password" : mode === "same" ? "Keep saved login" : "Save login";
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
get<HTMLButtonElement>("#desktop-unlock").addEventListener("click", () => void perform({ type: "PX_DESKTOP_UNLOCK" }, "Unlocking with Passkey-X desktop…"));
get<HTMLButtonElement>("#desktop-unpair").addEventListener("click", () => void perform({ type: "PX_DESKTOP_UNPAIR" }, "", "This browser is no longer paired."));
get<HTMLButtonElement>("#desktop-pair").addEventListener("click", async () => {
  // Talking to a desktop app needs the browser's "native messaging" permission (asked once).
  let allowed = false;
  try { allowed = await chrome.permissions.request({ permissions: ["nativeMessaging"] }); } catch { allowed = false; }
  if (!allowed) { show("Passkey-X needs permission to talk to the desktop app."); return; }
  const browser = navigator.userAgent.includes("Edg/") ? "Microsoft Edge" : navigator.userAgent.includes("Brave") ? "Brave" : "Chrome";
  await perform({ type: "PX_DESKTOP_PAIR", browser }, "Contacting Passkey-X desktop…", "Approve the request in Passkey-X desktop.");
});
get<HTMLButtonElement>("#disconnect").addEventListener("click", () => void perform({ type: "PX_DISCONNECT" }, "Disconnecting…"));
get<HTMLSelectElement>("#save-workspace").addEventListener("change", updateSaveAction);
get<HTMLButtonElement>("#save").addEventListener("click", () => void perform({ type: "PX_SAVE", candidateId: pending?.id, workspaceId: get<HTMLSelectElement>("#save-workspace").value }, "Encrypting and saving…", "Login saved. It will sync to your web and desktop vaults."));
get<HTMLButtonElement>("#dismiss").addEventListener("click", () => void perform({ type: "PX_DISMISS", candidateId: pending?.id }, "", "Login discarded."));
get<HTMLButtonElement>("#dismiss-locked").addEventListener("click", () => void perform({ type: "PX_DISMISS", candidateId: pending?.id }, "", "Login discarded."));
get<HTMLButtonElement>("#never").addEventListener("click", () => void perform({ type: "PX_NEVER" }, "", "Passkey-X will ignore this site."));
get<HTMLButtonElement>("#never-locked").addEventListener("click", () => void perform({ type: "PX_NEVER" }, "", "Passkey-X will ignore this site."));
get<HTMLButtonElement>("#allow").addEventListener("click", () => void perform({ type: "PX_ALLOW" }, "", "Passkey-X can offer saves for this site again."));
async function showGuard() {
  const answer = await request({ type: "PX_GUARD_STATUS" }) as Status & { guard?: { mode: string; organization: string | null; level: string; title: string } };
  const guard = answer.guard;
  if (!answer.ok || !guard) return;
  const box = get<HTMLElement>("#guard");
  box.hidden = false;
  box.className = `guard ${guard.level === "safe" ? "" : guard.level}`;
  get<HTMLElement>("#guard-state").textContent = guard.mode === "off"
    ? "Web protection is turned off by your organization."
    : guard.level === "safe" ? `Web protection is on${guard.organization ? ` · ${guard.organization}` : ""}. No threats found on this page.` : guard.title;
  get<HTMLButtonElement>("#report-phishing").hidden = !origin;
}
get<HTMLButtonElement>("#report-phishing").addEventListener("click", async () => {
  if (!window.confirm("Report this page as phishing? Your organization's IT team will review it.")) return;
  const answer = await request({ type: "PX_REPORT_PHISHING" });
  show(answer.ok ? "Thanks. The page was reported to your IT team." : answer.error ?? "The page could not be reported.");
});
void chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
  tabId = tab?.id ?? 0;
  try { const parsed = new URL(tab?.url ?? ""); origin = ["http:", "https:"].includes(parsed.protocol) ? parsed.origin : ""; } catch { origin = ""; }
  get<HTMLElement>("#origin").textContent = origin ? new URL(origin).hostname : "Unsupported page";
  render(await request({ type: "PX_STATUS" }));
  void showGuard();
}).catch(() => show("Unable to read this tab. Reopen Passkey-X on a website."));
export {};
