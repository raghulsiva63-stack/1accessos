# Passkey-X combined testing

Use a disposable account and synthetic website credentials. Never send real
passwords or recovery files to a tester. Installers and the extension are previews.

1. From https://passkey-x.com/download, install the desktop app for your platform
   and extension 0.3.0 in Chrome or Edge 127+. Check each SHA-256 sidecar.
2. Sign in to the same account in the web and desktop vault. Connect the extension
   using its Connect securely button. Keep account login and vault unlock separate.
3. On a compatible test website, submit a synthetic login. Check that Save this
   login appears, or that the SAVE badge lets you open it. Approve one writable
   workspace. Refresh web and desktop; verify the new item appears in both.
4. Change that website password, submit it again, and approve Update password.
   Verify one revised item, with its existing title, notes and tags preserved.
5. Sign in again with the saved details while unlocked. Check that no repeated
   save is requested. Not now must discard a candidate; Never must suppress that
   site's future candidates until Allow saves on this site again is selected.
6. Lock the extension, submit a new test login, then unlock to review it. Also try
   Not now while locked. Wait over two minutes or close the tab; the pending login
   must disappear. Switching to another origin must clear it immediately.
7. On the exact saved website, use Fill or Alt+Shift+X. Check that the visible login
   fields are filled without submitting. Another origin or a hidden/cross-origin
   form must not receive the secret.
8. In the desktop app, check Ctrl/Cmd+L, Ctrl/Cmd+R, focus-loss lock, five-minute
   idle lock, copy/paste, sharing, and recovery/export downloads. Confirm external
   web links open in the browser. Reopen the desktop app and unlock again.
9. Test recovery, signup/CAPTCHA, account passkeys and MFA on real supported
   devices. If the OS webview cannot complete a security check, use the native
   Open in browser menu. Do not count compiled builds as a passed passkey test.
10. Install the web app on Android Chrome and iOS Safari. Check navigation,
    background/resume lock and the offline screen. Reconnect before unlocking.

Record OS, browser, version, result and any error for each step. Browser-store
review, signed/notarized desktop releases and autofill inside other native apps
remain outstanding. Existing plan entitlements and workspace permissions apply
equally in the desktop and web vaults.
