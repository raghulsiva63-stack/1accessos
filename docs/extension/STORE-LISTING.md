# Passkey-X extension — Chrome Web Store and Edge Add-ons submission kit

Use this to submit version 0.4.0. Build the upload file with:

```bash
cd apps/extension
npm ci
npm run package:store      # writes artifacts/passkey-x-extension-0.4.0-store.zip (+ .sha256)
```

The store build has **no manifest `key`**, runs only on HTTPS pages (plus `localhost` for development), and refuses to package without the production Supabase URL.

## After the stores assign IDs (one time)

1. Copy the extension ID from each dashboard (Chrome Web Store and Edge Add-ons each give a different 32-letter ID).
2. In Netlify → passkey-x → Site configuration → Environment variables, set
   `NEXT_PUBLIC_EXTENSION_IDS` = `<chrome-id>,<edge-id>` for the Production context.
3. Trigger a redeploy. The pairing page (`/extension/connect`) then accepts both store builds as well as the UAT build.

## Listing text

**Name:** Passkey-X — Password Manager

**Short description (≤132 characters):**
Save and fill passwords from your end-to-end encrypted Passkey-X vault. Your vault password never leaves your device.

**Detailed description:**

Passkey-X keeps your passwords, passkeys and secrets in an end-to-end encrypted vault. This extension connects your browser to your Passkey-X account so you can:

- Save new logins when you sign in to a website — Passkey-X asks first, and nothing is saved without your click.
- Fill a saved login on the matching website with one click in the toolbar or with Alt+Shift+X.
- Use logins shared with you by your family or team, including fill-only shares that never reveal the password.
- Say "Never for this site" to stop prompts on a website.

Security by design:
- Your vault is decrypted only inside this extension, in memory, and is locked automatically after inactivity.
- Logins are only offered on the exact website they belong to (www and non-www count as the same site). Plain-HTTP pages are never filled.
- The extension never reads pages to send data anywhere; it talks only to Passkey-X.

A free Passkey-X account is required: https://passkey-x.com

**Category:** Productivity (Chrome) / Productivity (Edge)
**Language:** English
**Support URL:** https://passkey-x.com/help — **Support email:** support@vlightsoft.com
**Privacy policy URL:** https://passkey-x.com/privacy
**Website:** https://passkey-x.com

## Single purpose (Chrome requirement)

Save and fill website logins from the user's own end-to-end encrypted Passkey-X vault.

## Permission justifications

| Permission | Why it is needed |
|---|---|
| `activeTab` | Fill the selected login into the page the user is looking at when they click the toolbar button or press the shortcut. |
| `tabs` | Read the current tab's URL to show only logins saved for that website, and to cancel a save or fill if the page changes. |
| `storage` | Keep the sign-in session for this browser session (`storage.session`) and the user's "Never for this site" list (`storage.local`). Vault contents are never stored. |
| Content script on `https://*/*` | Detect a submitted login form so the user can choose to save it, and place a login into the form when the user asks to fill it. |
| Host `https://passkey-x.com/*` | Pair the extension with the user's Passkey-X account. |
| Host `https://wkkmyacbhqloubtwvjom.supabase.co/*` | Passkey-X's own API: sign-in session and encrypted vault items. |

**Remote code:** No. All code is bundled in the package; the content security policy is `script-src 'self' 'wasm-unsafe-eval'` (WebAssembly is used for Argon2 key derivation).

## Data usage disclosures (Chrome "Privacy practices" tab)

Collected, only to provide the feature, never sold or used for ads or credit decisions:

- **Authentication information** — the user's Passkey-X sign-in session, and website usernames and passwords the user chooses to save. Passwords are encrypted on the device before upload.
- **Website content** — only the values of the login form the user submits or asks to fill.
- **Web history** — the current tab's website address, to match saved logins. Not stored or sent to Passkey-X except as part of a login the user saves.

Certify: data is not sold, not used for unrelated purposes, and not used for creditworthiness or lending.

## Reviewer test account

Create a dedicated account on https://passkey-x.com, set a vault password, add one login for `https://example.com`, and give the reviewers the email, login password and vault password in the "Test instructions" field. Delete the account after approval.
