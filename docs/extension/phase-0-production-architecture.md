# Passkey-X Chrome/Edge extension 0.2.0

## Implemented architecture

Chrome and Edge share the Manifest V3 package. Production identity is
`egkaneajfcaomheahcmopioiemmplebg`, derived from the public manifest key. Store
publication may assign another identity; update both the manifest and web
allowlist together before releasing a store build. No private signing key is
part of the source or UAT ZIP.

The extension uses the same client-encrypted account/workspace envelope format
and production RLS policies as the web app. It includes no service-role key.
The publishable Supabase key is public client configuration, not a user API key.
The documented customer REST boundary remains `https://passkey-x.com/api`.
Internal extension synchronization uses the existing Supabase client and RLS.

## Account connection

1. Clicking Connect in the popup creates a random 256-bit nonce and opens the
   production `/extension/connect` page. Only the public extension ID is in the
   query. The nonce travels in the fragment, which is removed after hydration.
2. The extension retains the nonce, originating tab ID and five-minute expiry
   in `chrome.storage.session`. A new request replaces the previous request.
3. The page creates a dedicated, memory-only Supabase login. It supports the
   configured login password or account passkey, Turnstile, and enrolled phone
   or TOTP verification. It does not reuse the web vault's session.
4. The user approves the named account. Chrome external messaging transfers the
   session directly to the fixed extension identity, never through a URL or log.
5. The worker checks exact HTTPS origin, exact route, top frame, tab identity,
   extension identity, nonce, expiry and payload size. It consumes the pending
   request before verifying the user with Supabase and accepting the session.
6. Supabase owns token rotation through a custom `chrome.storage.session`
   adapter. The web handoff client has automatic refresh disabled and releases
   its references after success. It does not sign out the transferred session.
7. Lock clears decrypted vault material, leaving the account connected.
   Disconnect signs out only this session and removes local session storage.
   Browser-session storage is cleared by browser restart. A service-worker
   restart preserves the account session but always starts with a locked vault.

This is a Chrome-origin-authenticated handoff, not a custom signed-token service.
It does not create a profile API key or a device-scoped backend token. Existing
RLS enforces the signed-in account's permissions. Refresh revocation and JWT
expiry follow Supabase semantics; instant access-token revocation is not claimed.

## Vault and browser boundary

- Vault password is entered only in the popup and used locally with Argon2id.
- AES-GCM account/workspace keys and decrypted logins exist only in worker memory.
- Lock, five-minute inactivity, disconnect and worker shutdown clear references
  and zero mutable key buffers. JavaScript cannot guarantee erasure of immutable
  strings or garbage-collected copies.
- Generation checks prevent an in-flight unlock or synchronization from
  repopulating state after Lock. Concurrent vault operations are rejected.
- Save captures only submitted top-frame forms while unlocked, with 60-second
  expiry. Passkey-X's own pages are excluded from capture so a vault password
  cannot be offered for saving. Query strings/fragments are stripped from URLs.
- Fill requires explicit popup action or Alt+Shift+X and exact origin. Memberships
  and RLS-filtered items are reloaded before releasing a cached secret. A changed
  tab or a page without a visible login form produces a failure.
- Fill-only Access Capsules consume a server-authorized use before delivery;
  failed delivery can therefore still consume a use. This is intentional to
  avoid granting an uncounted use after a navigation or receiver failure.
- Save targets are explicitly selected from authorized writable workspaces.
  Matching origin + username updates only within that workspace; another
  workspace receives a separate encrypted record.
- HTTP origins are supported independently from HTTPS; neither can match the
  other. The visited page can read a credential deliberately filled into it.
- "Never for this site" stores only ignored origins in `storage.local`; the
  popup can allow saves on the current site again.

## Permissions and packaging

- `activeTab` for explicit fill/current-page context; `storage` for session state
  and ignored-origin preferences.
- HTTP/HTTPS top-frame content scripts; production web and one Supabase host.
- Extension CSP permits bundled WebAssembly for Argon2; no remote JavaScript.
- No cookies, clipboard, history, downloads, debugger or native messaging access.
- The UAT ZIP is a load-unpacked package, not a signed store release.

## Acceptance boundary

Automated tests cover message authority, nonce/tab/origin/expiry validation,
replay, mocked Auth session lifecycle, offline local disconnect, encryption
source invariants and production packaging. These do not substitute for live
Chrome/Edge tests with a disposable account or an independent security review.
See `test-cases.md` and `UAT-README.md` for the remaining browser/device gates.
