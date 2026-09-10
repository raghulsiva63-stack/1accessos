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
10. Open `/login`, `/app/mobile`, `/app/desktop` and the legacy `/#access` link.
    Each must open account login directly without the public marketing sections.
    The public root page must still show the website when opened in a browser.
11. Install the web app on Android Chrome and iOS Safari. Its launcher opens the
    mobile experience. Check Favorites, Recent, Logins, Recovery, search, generator,
    full-vault navigation, background/resume lock and offline reconnect behavior.
12. In desktop quick access, verify local search and Ctrl/Cmd+K, Ctrl/Cmd+Shift+N
    and Ctrl/Cmd+L while focused. In native desktop 0.3, also test system tray,
    compact/full window, lock-and-hide, closing/reopening from tray and Quit.
    Read the download page version: older 0.2 installers do not have tray controls.
13. When the native Android preview is available, install the APK on Android 9+,
    open it and enable Passkey-X in App menu > Autofill settings. In a compatible
    native app's login form, choose Passkey-X, unlock, select a login and confirm
    the displayed receiving app/package. Only those login fields should fill;
    no form should submit automatically. Decline the native dialog and verify
    that no credentials are filled.
14. Type a synthetic login in a compatible native Android app and submit it.
    Android should ask to save; approve, unlock Passkey-X and confirm a writable
    workspace. Refresh the web/desktop/extension vault and verify the encrypted
    item is synchronized. Change its password and verify a unique matching
    package/username updates with notes and tags preserved. Repeated unchanged
    credentials should show Already saved at review.
15. On Android, test Not now, back/close, background, process death and expiry
    after two minutes. A stale request must never fill or save. A read-only
    workspace cannot accept a save. Screenshots/recent-app previews are blocked.
    Test Android file import and export, cancellation and the browser fallback.
16. Native Android browser pages, embedded web forms and ambiguous/unsupported
    fields are intentionally excluded. Native iOS autofill and filling into other
    desktop applications are not supported; record these as outside this release.

Record OS, browser, version, result and any error for each step. Browser-store
review, signed/notarized desktop releases, stable Android signing, native iOS
autofill and autofill into other desktop apps remain outstanding. Compiled builds
and the synthetic Android emulator test do not certify real-account save/sync,
CAPTCHA, passkey or MFA behavior on every device. Existing plan entitlements and workspace permissions apply
equally in the desktop and web vaults.
