# Passkey-X extension 0.2.0 — UAT installation

## Prerequisites

- Current Chrome or Edge, version 120 or later.
- An existing Passkey-X test account with a completed encrypted vault and saved
  recovery file. Use synthetic logins for testing.
- The production `/extension/connect` page must be deployed from this release.

## Install the UAT package

1. Extract `passkey-x-extension-0.2.0-uat.zip` into a dedicated folder.
2. Open `chrome://extensions` or `edge://extensions`.
3. Turn on Developer mode. Choose **Load unpacked**, then select the extracted
   folder containing `manifest.json`.
4. Verify the displayed extension ID is
   `egkaneajfcaomheahcmopioiemmplebg`. Pin Passkey-X to the toolbar.
5. Open the popup and select **Connect securely**. Complete the web account
   sign-in and security checks, review the account, and approve the connection.
6. Close the connection tab. Open the popup and enter the separate vault password.
7. Use the test cases in `test-cases.md`, recording Chrome and Edge separately.

## Everyday operations

- **Fill:** visit the exact saved origin, open the popup and select a login, or
  press Alt+Shift+X to fill the first match. The extension never submits the form.
- **Save/update:** unlock first, submit a website login, then reopen the popup
  within 60 seconds and select **Encrypt and save**. Matching origin + username
  updates the existing item in the selected writable workspace; otherwise it
  creates one there. Select the destination before saving.
- **Never:** select **Never for this site** to stop offering saves for that origin.
  Use **Allow saves on this site again** to reverse that preference.
- **Lock:** use the popup Lock button. Five minutes of inactivity and a worker
  restart also lock the vault.
- **Disconnect:** lock, then select **Disconnect account**. Restarting the browser
  clears the browser-only session and requires a new connection.

## Troubleshooting

- Expired connection: start again from the extension; old tabs/links cannot pair.
- Connection unavailable: verify the exact extension ID, production web release,
  and enabled extension. Preview domains cannot pair with the production package.
- Incorrect vault password: use the web recovery flow and your saved recovery
  file. Login password resets do not decrypt the vault.
- No visible form: open the site's login form in its top-level page. Cross-origin
  iframes and hidden/disabled/read-only inputs are not filled.
- Worker restarted: account remains connected, but unlock again. This is expected.
- Offline: authorization and save/fill cannot be verified. Reconnect and retry.
- Removing the extension clears local preferences. Encrypted server data remains.

## Build from source

Use the pinned dependencies in `apps/extension/package-lock.json` with `npm ci`.
Set `VITE_SUPABASE_URL` to the production project URL and
`VITE_SUPABASE_PUBLISHABLE_KEY` to its public publishable key through the build
shell or a local untracked environment file. Never use a service-role key.
Run `npm test`, then `npm run package:uat` in `apps/extension`.
The package command writes the UAT ZIP and SHA-256 under `artifacts/`.

## Public release gates

UAT packaging does not publish to Chrome Web Store or Edge Add-ons. Publisher
accounts, final store IDs, store review/disclosures and independent security
review must be completed before claiming a public store release. Physical
passkey ceremonies require a supported user device. Mobile/desktop clients are
separate releases and are not implemented by this extension change.
