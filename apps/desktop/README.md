# Passkey-X desktop 0.3.0

Desktop opens `https://passkey-x.com/app/desktop` directly to account login or vault unlock. The focused home screen provides local search, favorites, recently updated logins, recovery items and quick actions. The full encrypted vault, workspaces, sharing and account tools remain available.

Native 0.3 controls: system-tray quick access, 480-pixel compact window, full workspace, lock and hide, add-login shortcut, reload and browser fallback. Ctrl/Cmd+K opens quick access, Ctrl/Cmd+Shift+N adds a login, and Ctrl/Cmd+L locks while the application is focused. Closing locks and hides when a tray is available; Quit exits. On desktops without a tray host the close button closes normally.

The native shell grants no remote command permissions. It permits only the exact production HTTPS origin and a bundled connection screen. External HTTP(S) links open in the browser. Focus loss locks the vault; recovery and export downloads go to Downloads with unique filenames. Vault keys remain in webview memory and are wiped on lock. Internet access is required.

The Chrome/Edge extension provides website save prompts and filling. Desktop does not inspect other native applications or provide systemwide autofill. Passkey/CAPTCHA compatibility depends on the OS webview; Open in browser is the fallback. Native biometric vault unlock and signed automatic binary updates are not included.

`desktop-release.yml` builds Windows x64 NSIS, macOS universal DMG and Ubuntu 24.04-compatible x64 DEB. Each artifact includes source, workflow, Cargo.lock and SHA-256 provenance. Windows/Linux are unsigned; macOS is ad-hoc signed and not notarized. The public download version is independently selected in `apps/web/lib/client-releases.json`; bump it only after verified static release assets are available.

For a local build, install the official Tauri prerequisites, run `npm ci` here and `npm run build`. No backend keys or account credentials are required to build the shell.
