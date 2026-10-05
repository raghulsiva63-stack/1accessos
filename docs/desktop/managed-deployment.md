# Deploying Passkey-X desktop in an organization

This guide is for IT teams. It covers silent installation, settings you can enforce, browser extension pairing, and offline access.

## Install

| Platform | Package | Silent install |
|---|---|---|
| Windows | `passkey-x-desktop-<version>-windows-x64.msi` (per machine) | `msiexec /i passkey-x-desktop-1.1.0-windows-x64.msi /qn` (Intune: *Line-of-business app*; SCCM/GPO software installation) |
| Windows | `…-windows-x64.exe` (per user, NSIS) | `passkey-x-desktop-1.1.0-windows-x64.exe /S` |
| macOS | `…-macos-universal.dmg` | Copy `Passkey-X.app` to `/Applications` (Jamf, Kandji, Intune). Needs the Developer ID-signed and notarized build. |
| Linux | `…-linux-x64.deb` | `sudo apt install ./passkey-x-desktop-1.1.0-linux-x64.deb` |

The app never stores vault data in plaintext. People sign in through their browser (SSO works), then unlock with their vault password, Windows Hello or Touch ID.

## Enforced settings

Policies only restrict or preconfigure the app. They never give anyone, including IT, access to vault contents.

| Name | Type | Effect |
|---|---|---|
| `organizationName` | text | Shown on the sign-in screen and in settings. |
| `supportUrl` | text (https) | "Get help" link in settings. |
| `allowedEmailDomains` | text, comma-separated | Only accounts on these domains can sign in on the computer, e.g. `acme.com, acme.co.uk`. |
| `lockOnBlur` | on/off | Lock when switching to another app. |
| `lockOnHide` | on/off | Lock when the window is hidden. |
| `hotkeyEnabled` | on/off | Global quick access shortcut. |
| `maxClipboardSeconds` | 10–120 | Longest time a copied password stays on the clipboard. |
| `idleLockMinutes` | 1–480 | Maximum idle time before the vault locks. The shorter of this and the organization's account policy applies. |
| `disableBiometric` | on/off | Turn off Windows Hello and Touch ID unlock. |
| `disableUpdates` | on/off | The app does not check for or install updates; deploy new versions yourself. |
| `autoStart` | on/off | Start hidden in the tray when people sign in. |
| `offlineAccess` | on/off | Keep an encrypted copy of the vault for use without internet. Off also deletes existing copies. |
| `browserIntegration` | on/off | Allow pairing the Passkey-X browser extension. |
| `extensionIds` | text, comma-separated | Extra Chromium extension IDs allowed to pair (internal builds). The store versions are always allowed. |
| `autoType` | on/off | Auto-type a login into another app (Ctrl+Alt+A / ⌘⌥A). Desktop 1.2+. |
| `sshAgent` | on/off | SSH agent for Ed25519 keys stored in the vault; each signature is approved in the app. Desktop 1.2+. |
| `commandLine` | on/off | `pkx` command-line tool for scripts and developer tools; each request is approved in the app. Desktop 1.2+. |
| `downloadProtection` | on/off | Check new downloads against Guard rules and threat lists. Desktop 1.2+. |

On/off settings that you do not configure stay under the person's control. Settings you configure appear as "Set by <organization>" in the app.

### Windows: Group Policy or Intune

- Copy `apps/desktop/policy/windows/PasskeyX.admx` and `en-US/PasskeyX.adml` to `C:\Windows\PolicyDefinitions` (or your central store). The policies then appear under *Computer Configuration › Administrative Templates › Passkey-X*.
- With Intune, import the ADMX (*Devices › Configuration › Import ADMX*), or use a custom OMA-URI policy.
- The values live in `HKLM\SOFTWARE\Policies\Vlightsoft\Passkey-X`. On/off and numbers are `REG_DWORD`; text is `REG_SZ`. Standard users cannot change this key.

### macOS: configuration profile

- Edit `apps/desktop/policy/macos/com.vlightsoft.passkeyx.mobileconfig`, give both `PayloadUUID`s new values (`uuidgen`), and deploy it with your MDM. The preference domain is `com.vlightsoft.passkeyx`.
- Without an MDM, an administrator can run `sudo defaults write /Library/Preferences/com.vlightsoft.passkeyx allowedEmailDomains acme.com`.
- The app only reads managed (forced) values and the system-wide domain. It ignores values a person writes to their own preferences.

### Linux

- Put the policy in `/etc/passkey-x/policy.json`, owned by root and not writable by others. An example is in `apps/desktop/policy/linux/policy.json`.

## Browser extension pairing

When `browserIntegration` is on, the desktop app registers itself as a native messaging host (`com.vlightsoft.passkeyx`) for Chrome, Edge, Brave and Chromium for the current user.

- In the extension, people choose **Pair with Passkey-X desktop**, compare the 6-digit code, and approve it in the app.
- After that, the extension unlocks on its own while the desktop app is unlocked (same account only) and locks when the app locks.
- Pairings appear in *Settings › This computer* and can be removed there. Turning the setting off removes all pairings.
- The relay only accepts connections that carry a random token from the person's own app data folder, and only from allowed extension IDs.

## Offline access

With `offlineAccess` on (the default), each sync keeps a copy in the app's data folder:

- the account's key-derivation profile;
- the workspace key envelopes;
- the item ciphertext.

Everything except the profile is encrypted again with keys derived from the account and workspace keys. Without internet, people unlock with their vault password and can read and copy, but not edit. Signing out deletes the copy.

## Updates

- Signed automatic updates check `https://passkey-x.com/releases/desktop/latest.json` and only install packages signed with Vlightsoft's update key.
- With `disableUpdates`, deploy new MSI/PKG/deb versions through your management tool instead.
