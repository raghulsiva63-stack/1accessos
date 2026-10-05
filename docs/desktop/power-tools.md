# Passkey-X desktop 1.2: tools only the desktop app has

Desktop 1.2 adds five features under **This computer** in the sidebar. Turn them on or off in **Settings › This computer**; organizations can enforce them with the `autoType`, `sshAgent`, `commandLine` and `downloadProtection` policies (see [managed-deployment.md](managed-deployment.md)).

| Feature | Default | What it does |
|---|---|---|
| Auto-type | on | Types a login into any program with **Ctrl+Alt+A** (⌘⌥A on macOS). |
| SSH agent | off | Serves Ed25519 keys stored in the vault to ssh, git and IDEs; every use is approved. |
| Command-line tool (`pkx`) | off | Gives secrets to scripts and dev tools; every request is approved. |
| Download protection | on | Checks new files in Downloads (name tricks, source site, known-malware hashes). |
| Presentation mode | automatic | Blocks revealing passwords while Zoom sharing, OBS or another recorder runs; also from the tray. |
| Secrets on this computer | on demand | Finds plaintext passwords and keys in files and moves them into the vault. |

## Auto-type

1. Click into the sign-in box of any program (VPN client, Remote Desktop, a database tool…).
2. Press the shortcut. Passkey-X remembers that window.
3. If an item has a matching **Auto-type window** rule, or you chose "always use this login in this window" before, it is typed at once. Otherwise a picker opens on top with suggestions (items whose name or website appears in the window title).

Safety rules:

* Typing stops if another window comes to the front (checked before every step).
* In browsers the picker always opens with a warning: a page title can't prove which site is open. Use the browser extension there.
* The window token is single-use and expires after two minutes; locking the vault clears it.
* Only Tab and Enter can be "pressed"; text never contains control characters.

Item fields (optional): `Auto-type window` — title patterns with `*` and `?`, separated by `;` or new lines. `Auto-type sequence` — e.g. `{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}`; also `{URL}`, `{DELAY 500}`, `{S:Field name}`.

Requirements: macOS — allow Passkey-X in **System Settings › Privacy & Security › Accessibility**. Linux — X11 session with `xdotool` installed (Wayland can't type into other apps). Windows — programs running as administrator can't receive keys from a normal app.

## SSH agent

Keys are `SSH key` items: the OpenSSH private key is the secret, `publicKey` and `fingerprint` are fields. Create one in **This computer › SSH & command line** (Ed25519, generated on this computer) or paste an existing unencrypted OpenSSH key.

Point your tools at the agent once:

```sh
# macOS / Linux
export SSH_AUTH_SOCK="$HOME/.passkey-x/ssh-agent.sock"
# or in ~/.ssh/config
Host *
  IdentityAgent "~/.passkey-x/ssh-agent.sock"
```

On Windows the agent is the named pipe `\\.\pipe\passkey-x-ssh-agent-<username>` (only local connections, current user). Use `setx SSH_AUTH_SOCK "\\.\pipe\passkey-x-ssh-agent-<username>"` or `IdentityAgent` in `%USERPROFILE%\.ssh\config` with the built-in OpenSSH client.

Every signature asks: **Allow once**, **Allow for 10 minutes** or **Deny** (no answer in 90 seconds = deny). Locking forgets private keys and approvals; public keys stay listed so `ssh-add -L` still works. Signing out removes everything. The socket folder is `0700` and the socket `0600`.

## pkx

```sh
pkx run --env DATABASE_URL=px://Work/Production DB/password -- npm start
pkx run --env-file .env.passkey -- docker compose up   # values like px://… are filled in
pkx read "px://GitHub/token"
```

References: `px://<item>/<field>` or `px://<vault>/<item>/<field>`; fields `password`, `username`, `url`, `notes`, `totp`, or a custom field name. Items match by name (case-insensitive) or id; a name found in two vaults needs the vault part.

Each request shows the command, folder and items, and must be approved in the app (120 seconds). Values go only into the child process environment and are never written to disk. On Windows `pkx` only talks to the Passkey-X app installed in the same folder; the pipe rejects remote clients. **Settings › This computer** offers "Add pkx to PATH" on Windows; on macOS link `/Applications/Passkey-X.app/Contents/MacOS/pkx` into `/usr/local/bin`.

## Download protection

Every minute, files that finished downloading since the last check are judged by:

* name tricks — `invoice.pdf.exe`, right-to-left override characters, padded extensions;
* the site they came from (Windows Mark of the Web, macOS "Where from", Linux `user.xdg.origin.url`) against Guard's page rules and threat lists;
* for programs, installers, disk images and macro documents: the SHA-256 against abuse.ch MalwareBazaar, through the `file-check` function (needs `URLHAUS_AUTH_KEY`; without it this check is skipped).

Dangerous files raise the emergency alert and are reported to the organization as Guard findings (`web` / `dangerous_download` or `risky_download`, file name and source site only). **Block** renames a file to `<name>.blocked`. Files are never uploaded.

## Secrets on this computer

A scan of Desktop, Documents, Downloads, code folders (`~/code`, `~/src`, `~/projects`, …) and tool settings (`~/.ssh`, `~/.aws`, `~/.docker`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`) finds exported password lists, unprotected private keys, cloud/API tokens and connection-string passwords (depth 8, up to 60,000 files, 90 seconds). Results show masked previews only. From each finding: **Save in vault**, **Import to vault** (password exports), **Show in folder**, **Move to trash** (home folder only). The organization sees one finding with counts (`device` / `plaintext_secrets`), never paths or values.

## Owner checklist

* Deploy the `file-check` edge function (`verify_jwt = true`) and set `URLHAUS_AUTH_KEY` (already used by threat-sync).
* Update the ADMX/ADML templates in Group Policy / Intune (new 1.2 policies).
* macOS notarization: no new entitlements are needed; people grant Accessibility on first auto-type.
