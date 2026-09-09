# Passkey-X client implementation — 8 September 2026

This continuation starts from verified GitHub main `85ac304240702a7c127bd0ee2c72c44f62e63472` and restores the unpublished extension work from the previous chat.

## Delivered source

| Client | Implemented | Release status |
|---|---|---|
| Chrome / Edge extension 0.3.0 | Dedicated account pairing, MFA verification, local vault unlock, exact-origin fill, automatic save/update prompts with explicit workspace approval, ignored-site controls, shared-capsule use checks, lock/disconnect | Unpacked preview ZIP; store submission and browser UAT remain |
| Android | Installable web app, existing web vault screens, mobile navigation, background/idle lock, safe offline screen, update handling | Install from Chrome after web deployment |
| iPhone / iPad | Same installable web app and vault protections | Safari Add to Home Screen after deployment; device UAT remains |
| Windows / macOS / Linux | Installable web app in its own window | Browser installation after deployment |
| Native desktop 0.2.0 | Live canonical HTTPS vault, restricted native shell, native lock/reload/edit menus and safe export downloads | Windows x64 EXE, universal macOS DMG and Linux x64 DEB preview builds; publisher signing and real-device UAT remain |

Native Android/iOS binaries, OS autofill providers, native biometric vault unlock, native passkey-provider integration, signed desktop installers and app-store releases are **not complete**. The installed web app does not register as an operating-system password provider.

## Security behavior

- The web app locks when hidden, closed/frozen, explicitly locked, or idle for five minutes. It clears root/workspace key buffers and rejects pending unlocks after background transitions.
- Extension pairing checks nonce, exact origin/route, tab, frame, expiry, verified account and MFA assurance. Disconnect removes local session state even when server sign-out fails.
- Session storage survives extension-worker restart but not browser restart. Decrypted vault keys/logins remain in memory only.
- Save/update requires a selected writable workspace; server RLS and expected revisions remain authoritative. Read-only or rotation-blocked workspaces are not save targets.
- Fill rejects hidden/disabled/read-only/new-password inputs and cross-origin form actions. It never submits a form. Capturing on Passkey-X itself is blocked in the content script and message boundary.
- The service worker caches only `/offline.html` and two public icons. No vault data, authenticated responses, APIs, tokens or application HTML are cached. Offline vault unlock and queued writes are not included.
- JavaScript cannot guarantee erasure of immutable strings or garbage-collected copies.

## Build and verify

Use Node.js 24 and the committed lockfiles:

```sh
npm --prefix apps/web ci
npm --prefix apps/extension ci
npm run check
npm run test:clients
npm --prefix apps/web run lint
npm run build:clients
node --test --test-concurrency=1 apps/web/tests/*.test.mjs
```

Configure `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` for the web build, and `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` for extension builds. Production project URL: `https://wkkmyacbhqloubtwvjom.supabase.co`. Use the enabled publishable key, never a secret/service-role key. Local untracked `.env.local` files are supported.

The build generates and verifies the extension ZIP/checksum, copies them into public downloads, and exports the web app. Netlify runs `scripts/build-hosted-clients.mjs` to include the matching extension. Tests use a separate synthetic `dist-test` build; packaging rejects that test key.

## Deployment and acceptance

1. Deploy the tested source to existing Netlify site `passkey-x` (`312da651-a4aa-400b-a9f6-4636e9404fa7`). Preserve production environment and billing settings.
2. Check `/download`, `/extension/connect`, `/sw.js`, `/manifest.webmanifest`, the extension ZIP/checksum, and `/api-docs` on the production domain.
3. Load the ZIP in Chrome and Edge; confirm ID `egkaneajfcaomheahcmopioiemmplebg`. Complete `docs/extension/test-cases.md` with a disposable account. Physical passkey ceremonies need a supported device.
4. Install on Android Chrome and iOS Safari; verify background/resume, screen locking, recovery-file downloads, mobile navigation and updates after locking.
5. Submit to extension stores using publisher accounts after UAT; synchronize the manifest and web allowlist if a store assigns a different ID.

Automated checks pass locally. The cloud browser could not reach the local preview (`ERR_BLOCKED_BY_CLIENT`), so visual/device acceptance is not represented as passed.

## Recovered release consistency

The preceding chat's branded API guides and narrow Netlify rewrites are included. Customer documentation uses `https://passkey-x.com/api`. Profile API-key issuance remains a separate unfinished feature described in `docs/operations/branded-api-and-profile-keys.md`.

The missing account-lifecycle source is restored from deployed Supabase function version 3. This client release changes no database migration or existing provider secret. Restoring the source does not redeploy the function.
