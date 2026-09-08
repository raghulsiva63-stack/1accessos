# Passkey-X desktop 0.2.0

The Tauri desktop app opens the live HTTPS vault in a dedicated system webview. It uses the same deployed web application, account, encrypted data, workspace permissions, sharing, organization tools, billing and account settings. Web updates arrive when the app reloads. An internet connection is required; account sessions are separate from the browser and vault keys are not persisted by the native shell.

Native controls include Lock vault (Ctrl/Cmd+L), Reload vault (Ctrl/Cmd+R), standard editing commands, Open in browser, Get browser extension, and Connection help. Losing focus or closing the window locks the vault and cancels pending unlocks. Recovery-key and export downloads go to the user's Downloads folder with unique filenames. The native runtime permits only the exact production domain and a bundled connection screen; external web links open in the system browser, and the web content receives no native command permissions.

Install the Chrome/Edge extension to receive automatic save/update prompts and explicit fill on websites. The desktop app does not inspect other native applications or provide systemwide autofill. Passkey and CAPTCHA compatibility depends on the OS webview; use Open in browser if a platform cannot complete those flows. Native biometric vault unlock and signed automatic binary updates are not part of this preview.

The `desktop-release.yml` workflow builds Windows x64 NSIS, macOS universal DMG, and Ubuntu 24.04-compatible x64 DEB packages. Each artifact includes SHA-256, source commit, workflow run and Cargo.lock provenance. Windows/Linux previews are unsigned; macOS is ad-hoc signed and not notarized. Real device acceptance testing and production signing remain release gates.

For local builds, install Rust and the platform's Tauri prerequisites, run `npm ci` here, then `npm run build`. No backend keys or user credentials are required to build the desktop shell. See https://v2.tauri.app/start/prerequisites/.
