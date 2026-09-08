# Passkey-X native desktop source

The Tauri 2 shell packages the static web client. Build paths and CSP use the current production backend. Browser passkey sign-in is disabled in native builds because its HTTPS relying-party origin does not match a local webview.

This is source preparation, not a tested or signed native release. Mobile and desktop users can use the installed web app described at `/download`.

To continue native release work, install the platform's Rust/Tauri prerequisites, run `npm ci` in this directory and `npm ci` in `../web`, configure the public frontend environment, then run `npm run build`. Resolve native-origin API CORS, CAPTCHA, email/deep links, clipboard/download behavior, and passkey/biometric integration on each target before release. Signing/notarization credentials belong in the release environment and are not committed.
