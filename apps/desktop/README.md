# Passkey-X desktop 1.1

A self-contained desktop app for Windows, macOS and Linux (Tauri 2).

## How it works

- **Bundled vault.** `scripts/build-frontend.mjs` builds the Passkey-X web app (`apps/web`) as a static export into `dist/`. The app loads it from its own local origin: `http://tauri.localhost` on Windows, `tauri://localhost` elsewhere.
  - The window never loads passkey-x.com or any other website. Other links open in the default browser.
  - Public client settings (Supabase URL, publishable key) live in `desktop.config.json`.
- **Browser sign-in (PKCE + loopback, RFC 7636 / RFC 8252).** The app never shows a password form.
  1. It creates a PKCE verifier and starts a one-shot listener on `127.0.0.1:<random port>`.
  2. It opens `https://passkey-x.com/desktop-link/` in the default browser. There the person signs in (security check, passkeys, SSO, two-step verification) and chooses **Allow**.
  3. The browser returns a one-time code to the listener.
  4. The app redeems code + verifier once through the `desktop-session` Edge Function.
  - Codes expire after 2 minutes, and a wrong verifier burns the code (`supabase/migrations/20261003090000_desktop_sign_in.sql`).
  - Accounts with two-step verification must still complete it in the app before vault data is readable (the RLS aal2 policies).
- **Session storage.** Supabase tokens are kept in an AES-256-GCM encrypted file. Its key is in the system credential store: Keychain, Credential Manager or Secret Service. Without a credential store, the session is memory-only.

## Security features

| Feature | Windows | macOS | Linux |
|---|---|---|---|
| Fingerprint/face unlock | Windows Hello. The key is derived from a Hello signature, so it is cryptographically bound to Hello. | Touch ID gate, plus a key in the login Keychain (see note) | — (vault password) |
| Clipboard | Hidden from history and cloud clipboard, wiped after 30 s | Hidden from history, wiped | Password-manager hint, wiped |
| Screenshot / screen-share blocking | ✓ | ✓ | — |
| Lock on sleep | ✓ | ✓ | ✓ |
| Lock on screen lock | ✓ | ✓ | idle timeout only |
| Lock on quit / close / idle; optional on app switch or hide | ✓ | ✓ | ✓ |
| Quick access over any app | Ctrl+Shift+Space | ⌘⇧Space | Ctrl+Shift+Space |

- **Command allow-list.** Only the bundled pages in the `main` window can call native commands. The commands are declared in `build.rs`, and the allow-list is `capabilities/desktop.json`.
- **Content Security Policy.** `tauri.conf.json` sets a strict CSP. Inline scripts are allowed only by build-time hashes.
- **Biometric unlock is bound to the vault password envelope.** After a vault password change it stops working and is deleted. It is also removed on sign-out.
- **macOS Touch ID note.** Touch ID is currently a gate in front of a normal Keychain item, and only Passkey-X can read that item without a system prompt. Binding the item to biometry (SecAccessControl) needs a Developer ID-signed build; see Owner actions.

## For organizations (1.1)

- **Managed settings.** IT can enforce settings through Group Policy / Intune (`policy/windows/PasskeyX.admx`), an MDM profile (`policy/macos/…mobileconfig`) or `/etc/passkey-x/policy.json`. The settings include allowed email domains, lock rules, clipboard time, idle limit, Windows Hello / Touch ID, updates, auto-start, offline access and browser pairing. See `docs/desktop/managed-deployment.md`. The policy is read in `src-tauri/src/managed.rs`, only from locations standard users cannot write.
- **MSI.** Windows builds produce a per-machine `.msi` next to the per-user NSIS `.exe` (set `PASSKEY_X_SKIP_MSI=1` to skip it).
- **Start at sign-in.** Optional, and can be enforced by policy. The app starts hidden in the tray (`--hidden`) with the vault locked (`src-tauri/src/autostart.rs`).
- **Browser extension pairing.**
  - The app registers a native messaging host (`com.vlightsoft.passkeyx`) for Chrome, Edge, Brave and Chromium. The browser starts this same binary as the host, which only relays messages to the running app over an authenticated loopback connection (`src-tauri/src/browser_link.rs`).
  - Pairing is an ECDH key agreement approved in the app with a matching 6-digit code (`apps/web/lib/desktop/browser-link.ts`, `apps/extension/src/desktop-link.ts`).
  - A paired extension unlocks while the app is unlocked and locks when it locks.
  - Store extension IDs are added at build time with `PASSKEY_X_EXTENSION_IDS=<id>,<id>`; the preview (UAT) ID is built in.
- **Offline access.** Every sync keeps an encrypted copy (`apps/web/lib/desktop/offline-cache.ts`). Without internet, the vault unlocks read-only with the vault password.

## Build

```bash
npm ci
npm run build   # builds dist/ (web app) then the installer
```

- Signed automatic updates are included only when `updater.pub` is committed and `TAURI_SIGNING_PRIVATE_KEY` is set (`scripts/tauri-build.mjs`).
- Linux uses `.deb` packages, which the Tauri updater cannot update. Linux users download new versions.

## Owner actions

1. **Updater signing key.**
   - Run `npx tauri signer generate -w ~/.tauri/passkey-x.key` on your own computer.
   - Commit the public key as `apps/desktop/updater.pub`.
   - Add the private key and its password as GitHub secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
   - Update the workflow from `docs/desktop/desktop-release.yml`.
2. **Code signing.**
   - Windows: an OV/EV code-signing certificate, or Azure Trusted Signing.
   - macOS: an Apple Developer ID certificate plus notarization.
   - Until then, Windows SmartScreen and macOS Gatekeeper warn on install.
3. **Publish a release.**
   - Download the three installers from the workflow run.
   - Add them under `releases/desktop/1.0.0/` (see `scripts/prepare-desktop-downloads.mjs`).
   - Set `"desktop": "1.0.0"` in `apps/web/lib/client-releases.json`.
   - With the updater on, also publish `latest.json`.
