// SSH keys in the vault (desktop app). An "ssh-key" item holds the OpenSSH private key as its
// secret and the public key in fields.publicKey. While the vault is unlocked, the Ed25519 keys of
// the open workspace are handed to the Passkey-X SSH agent; every signature is approved in the app.

import type { VaultItem, VaultPayload } from "@/lib/vault/items";

const OPENSSH = "-----BEGIN OPENSSH PRIVATE KEY-----";

export function agentKeyItems(items: VaultItem[]): VaultItem[] {
  return items.filter((item) => item.contentType === "ssh-key" && !item.deletedAt && !item.payload.archived && (item.payload.secret ?? "").trimStart().startsWith(OPENSSH)).slice(0, 100);
}

export function agentKeyInputs(items: VaultItem[]) {
  return agentKeyItems(items).map((item) => ({ id: item.id, name: item.payload.title.slice(0, 200), privateKey: item.payload.secret ?? "" }));
}

/** Payload for a new or imported key. */
export function sshKeyPayload(title: string, privateKey: string, publicKey: string, fingerprint: string, now = new Date()): VaultPayload {
  return {
    version: 1, title: title.trim() || "SSH key", secret: privateKey, notes: "", tags: ["ssh"],
    fields: { publicKey, fingerprint }, updatedAt: now.toISOString(), passwordChangedAt: now.toISOString(),
  };
}

/** 32 random bytes, base64 (the seed of a new Ed25519 key). */
export function randomSeed(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const text = btoa(String.fromCharCode(...bytes));
  bytes.fill(0);
  return text;
}

export function setupSnippets(endpoint: string, os: "macos" | "windows" | "linux") {
  if (os === "windows") {
    return {
      shell: `setx SSH_AUTH_SOCK "${endpoint}"`,
      config: `Host *\n  IdentityAgent "${endpoint}"`,
      note: "Works with the OpenSSH client built into Windows 10 and 11, and with Git for Windows when it uses that client (git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe).",
    };
  }
  return {
    shell: `export SSH_AUTH_SOCK="${endpoint}"`,
    config: `Host *\n  IdentityAgent "${endpoint}"`,
    note: os === "macos" ? "Add the Host block to ~/.ssh/config so Terminal, Git and other tools use Passkey-X." : "Add the export line to ~/.bashrc or ~/.zshrc, or the Host block to ~/.ssh/config.",
  };
}

export function sshErrorMessage(code: string) {
  switch (code.split(":")[0]) {
    case "encrypted": return "This key is protected with a passphrase. Remove it first (ssh-keygen -p -f <file>) — the vault encrypts it instead.";
    case "unsupported": return "Only Ed25519 keys can be used by the Passkey-X SSH agent. You can still store other keys in the vault.";
    case "not_openssh": return "This doesn't look like an OpenSSH private key.";
    case "disabled": return "Turn on the SSH agent in Settings › This computer first.";
    default: return "This key could not be read.";
  }
}
